'use server'

import path from 'path'
import { spawn, spawnSync, ChildProcessWithoutNullStreams } from 'child_process'
import fs from 'fs'

import { invalidateScanCache } from '@/lib/scan-data'

type StageId = 'network' | 'linux' | 'windows'
type LogLevel = 'info' | 'success' | 'error'

interface StageMeta {
  id: StageId
  label: string
  weight: number
  etaSeconds: number
  command: string
  args: string[]
  cwd: string
}

interface LogEntry {
  timestamp: number
  level: LogLevel
  message: string
  stage?: StageId
}

interface LastRunSummary {
  startedAt: number
  finishedAt: number
  durationMs: number
  status: 'completed' | 'error' | 'stopped'
  error?: string
}

interface InternalJobState {
  status: 'idle' | 'running' | 'completed' | 'error' | 'stopped'
  stage: StageId | null
  startedAt?: number
  stageStartedAt?: number
  error?: string
  logs: LogEntry[]
  lastRun?: LastRunSummary
}

export interface AuditStatus {
  status: InternalJobState['status']
  stage: StageId | null
  stageLabel?: string
  progress: number
  etaSeconds: number | null
  logs: LogEntry[]
  startedAt?: number
  error?: string
  lastRun?: LastRunSummary
}

const repoRoot = path.resolve(process.cwd(), '..')
const privilegedClientPath = path.join(repoRoot, 'Siteuhweb', 'scripts', 'privileged-scan-client.js')
const networkCommand = buildStageCommand('python3', ['Network/Scanner.py', '--config', 'Network/config.xml'])
const windowsCommand = buildStageCommand('python3', ['pingcastle_remote.py', 'pingcastle_config.yaml'])

const stageMeta: StageMeta[] = [
  {
    id: 'network',
    label: 'Scan réseau',
    weight: 0.5,
    etaSeconds: 15 * 60,
    command: networkCommand.command,
    args: networkCommand.args,
    cwd: repoRoot,
  },
  {
    id: 'linux',
    label: 'Audit Linux (Lynis)',
    weight: 0.25,
    etaSeconds: 8 * 60,
    command: 'python3',
    args: ['audit_ssh_lynis.py'],
    cwd: path.join(repoRoot, 'Linux'),
  },
  {
    id: 'windows',
    label: 'Audit Windows (PingCastle)',
    weight: 0.25,
    etaSeconds: 10 * 60,
    command: windowsCommand.command,
    args: windowsCommand.args,
    cwd: path.join(repoRoot, 'pingcastle'),
  },
]
const stageOrder: StageId[] = stageMeta.map((stage) => stage.id)

function buildStageCommand(baseCommand: string, baseArgs: string[]): { command: string; args: string[] } {
  if (fs.existsSync(privilegedClientPath)) {
    return {
      command: process.execPath,
      args: [privilegedClientPath, '--', baseCommand, ...baseArgs],
    }
  }
  return { command: baseCommand, args: baseArgs }
}

const MAX_LOG_ENTRIES = 200

type RunnerSingleton = {
  jobState: InternalJobState
  stopRequested: boolean
  activeProcess: ChildProcessWithoutNullStreams | null
  pipelinePromise: Promise<void> | null
}

const globalRunner = globalThis as typeof globalThis & { __auditRunnerState__?: RunnerSingleton }

if (!globalRunner.__auditRunnerState__) {
  globalRunner.__auditRunnerState__ = {
    jobState: {
      status: 'idle',
      stage: null,
      logs: [],
    },
    stopRequested: false,
    activeProcess: null,
    pipelinePromise: null,
  }
}

const runnerState = () => globalRunner.__auditRunnerState__!

export async function getAuditStatus(): Promise<AuditStatus> {
  const { jobState } = runnerState()
  return {
    status: jobState.status,
    stage: jobState.stage,
    stageLabel: jobState.stage ? stageMeta.find((stage) => stage.id === jobState.stage)?.label : undefined,
    progress: Math.round(computeProgress(jobState) * 100),
    etaSeconds: computeEta(jobState),
    logs: jobState.logs,
    startedAt: jobState.startedAt,
    error: jobState.error,
    lastRun: jobState.lastRun,
  }
}

export async function startAudit(): Promise<AuditStatus> {
  const state = runnerState()
  if (state.jobState.status === 'running') {
    return await getAuditStatus()
  }

  state.stopRequested = false
  state.jobState = {
    status: 'running',
    stage: null,
    logs: [],
    startedAt: Date.now(),
    stageStartedAt: undefined,
    error: undefined,
    lastRun: state.jobState.lastRun,
  }

  state.pipelinePromise = runAuditPipeline(state).catch((error) => {
    console.error('Audit pipeline failed:', error)
  })

  return await getAuditStatus()
}

export async function stopAudit(): Promise<AuditStatus> {
  const state = runnerState()
  if (state.jobState.status !== 'running') {
    return await getAuditStatus()
  }

  state.stopRequested = true
  if (state.activeProcess) {
    state.activeProcess.kill('SIGTERM')
  }
  appendLog('error', 'Audit interrompu par l’utilisateur')

  state.jobState.status = 'stopped'
  state.jobState.stage = null
  state.jobState.stageStartedAt = undefined
  state.jobState.error = undefined
  const now = Date.now()
  if (state.jobState.startedAt) {
    state.jobState.lastRun = {
      startedAt: state.jobState.startedAt,
      finishedAt: now,
      durationMs: now - state.jobState.startedAt,
      status: 'stopped',
    }
  }
  return await getAuditStatus()
}

async function runAuditPipeline(state: RunnerSingleton) {
  try {
    for (const stage of stageMeta) {
      if (state.stopRequested) {
        throw new Error('AUDIT_STOPPED')
      }
      await prepareStage(stage)
      await runStage(stage, state)
    }

    state.jobState.status = 'completed'
    state.jobState.stage = null
    state.jobState.stageStartedAt = undefined
    state.jobState.error = undefined
    if (state.jobState.startedAt) {
      const finishedAt = Date.now()
      state.jobState.lastRun = {
        startedAt: state.jobState.startedAt,
        finishedAt,
        durationMs: finishedAt - state.jobState.startedAt,
        status: 'completed',
      }
    }
    appendLog('success', 'Tous les scans sont terminés')
    invalidateScanCache()
  } catch (error) {
    if ((error as Error).message === 'AUDIT_STOPPED') {
      state.jobState.status = 'stopped'
    } else {
      state.jobState.status = 'error'
      state.jobState.error = (error as Error).message
      appendLog('error', `Erreur lors de l’audit : ${(error as Error).message}`)
    }
    state.jobState.stage = null
    state.jobState.stageStartedAt = undefined
    if (state.jobState.startedAt) {
      const finishedAt = Date.now()
      state.jobState.lastRun = {
        startedAt: state.jobState.startedAt,
        finishedAt,
        durationMs: finishedAt - state.jobState.startedAt,
        status: state.jobState.status === 'error' ? 'error' : 'stopped',
        error: state.jobState.error,
      }
    }
  } finally {
    state.activeProcess = null
    state.stopRequested = false
    state.pipelinePromise = null
  }
}

async function runStage(meta: StageMeta, state: RunnerSingleton) {
  state.jobState.stage = meta.id
  state.jobState.stageStartedAt = Date.now()
  appendLog('info', `Démarrage : ${meta.label}`, meta.id)

  await executeCommand(meta, state)

  appendLog('success', `Terminé : ${meta.label}`, meta.id)
}

function executeCommand(meta: StageMeta, state: RunnerSingleton): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(meta.command, meta.args, {
      cwd: meta.cwd,
      env: process.env,
      shell: false,
    })

    state.activeProcess = child

    child.stdout.on('data', (chunk: Buffer) => {
      bufferAndAppend(chunk.toString(), 'info', meta.id)
    })

    child.stderr.on('data', (chunk: Buffer) => {
      bufferAndAppend(chunk.toString(), 'error', meta.id)
    })

    child.on('close', (code) => {
      state.activeProcess = null
      if (state.stopRequested) {
        reject(new Error('AUDIT_STOPPED'))
        return
      }
      if (code === 0) {
        if (meta.id === 'network') {
          const latestDir = findLatestScanDirectory()
          if (latestDir) {
            appendLog('info', `Résultats réseau : ${latestDir}`, meta.id)
          }
        }
        resolve()
      } else {
        reject(new Error(`Échec de l’étape "${meta.label}" (code ${code})`))
      }
    })

    child.on('error', (error) => {
      state.activeProcess = null
      reject(error)
    })
  })
}

function bufferAndAppend(output: string, level: LogLevel, stage?: StageId) {
  const lines = output.split(/\r?\n/)
  for (const line of lines) {
    if (line.trim().length === 0) continue
    appendLog(level, line.trim(), stage)
  }
}

function appendLog(level: LogLevel, message: string, stage?: StageId) {
  const state = runnerState()
  state.jobState.logs = [
    ...state.jobState.logs,
    {
      timestamp: Date.now(),
      level,
      message,
      stage,
    },
  ].slice(-MAX_LOG_ENTRIES)
}

function computeProgress(state: InternalJobState) {
  if (state.status === 'idle') return 0
  if (state.status === 'completed') return 1
  if (!state.stage) return state.status === 'error' || state.status === 'stopped' ? 0 : 0

  let progress = 0
  for (const stage of stageMeta) {
    if (stage.id === state.stage) {
      const elapsed = state.stageStartedAt ? (Date.now() - state.stageStartedAt) / 1000 : 0
      const ratio = Math.min(elapsed / stage.etaSeconds, 1)
      progress += ratio * stage.weight
      break
    } else {
      progress += stage.weight
    }
  }
  return Math.min(progress, 0.99)
}

function computeEta(state: InternalJobState): number | null {
  if (state.status !== 'running' || !state.stage) return null

  const stage = stageMeta.find((meta) => meta.id === state.stage)
  if (!stage) return null

  const elapsed = state.stageStartedAt ? (Date.now() - state.stageStartedAt) / 1000 : 0
  let remaining = Math.max(stage.etaSeconds - elapsed, 0)

  const currentIndex = stageOrder.indexOf(state.stage)
  for (let i = currentIndex + 1; i < stageMeta.length; i++) {
    remaining += stageMeta[i].etaSeconds
  }

  return Math.ceil(remaining)
}

function findLatestScanDirectory() {
  try {
    const entries = fs
      .readdirSync(repoRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name.startsWith('scan_results_'))
      .map((entry) => entry.name)
    if (!entries.length) return null
    const latest = entries.sort().reverse()[0]
    return path.join(repoRoot, latest)
  } catch {
    return null
  }
}

async function prepareStage(meta: StageMeta) {
  if (meta.id === 'linux') {
    await ensureLynisAssets(meta.cwd)
    ensureLinuxCredentials(meta.cwd)
  }
}

async function ensureLynisAssets(baseDir: string) {
  const lynisBinary = path.join(baseDir, 'lynis', 'lynis')
  if (fs.existsSync(lynisBinary)) {
    return
  }

  const zipPath = path.join(baseDir, 'lynis.zip')
  if (!fs.existsSync(zipPath)) {
    throw new Error("Archive 'lynis.zip' introuvable dans le dossier Linux")
  }

  appendLog('info', 'Extraction de Lynis depuis lynis.zip...', 'linux')
  const result = spawnSync('unzip', ['-o', 'lynis.zip'], {
    cwd: baseDir,
    stdio: 'pipe',
    encoding: 'utf-8',
  })

  if (result.status !== 0) {
    throw new Error(`Impossible d'extraire lynis.zip (${result.stderr || 'erreur inconnue'})`)
  }

  if (!fs.existsSync(lynisBinary)) {
    throw new Error("Extraction de Lynis terminée mais binaire 'lynis/lynis' introuvable")
  }

  try {
    fs.chmodSync(lynisBinary, 0o755)
  } catch {
    // ignore chmod issues on non-unix systems
  }
}

function ensureLinuxCredentials(baseDir: string) {
  const credentialsPath = path.join(baseDir, 'ssh_credentials.txt')
  if (fs.existsSync(credentialsPath)) {
    return
  }

  const template = [
    '# Identifiants SSH utilisés par audit_ssh_lynis.py',
    '# Format par ligne : adresse_ip;utilisateur;motdepasse',
    '# Exemple : 10.0.10.10;admin;MotDePasseTresSecret',
    '# Ajoutez une ligne par machine Linux à auditer.',
    '',
  ].join('\n')

  fs.writeFileSync(credentialsPath, template, { encoding: 'utf-8', mode: 0o600 })
  appendLog(
    'error',
    `Fichier ssh_credentials.txt introuvable. Un modèle vide a été créé dans ${credentialsPath}. ` +
      'Renseignez les machines Linux ciblées avant de relancer un audit.',
    'linux'
  )
}
