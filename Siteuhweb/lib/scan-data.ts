import fs from 'fs'
import path from 'path'
import { XMLParser } from 'fast-xml-parser'

import type {
  AuditData,
  AuditHistory,
  NetworkConnection,
  NetworkDevice,
  RemediationTask,
  ScorePoint,
  SeverityLabel,
  Vulnerability,
} from '@/lib/domain-types'

interface HostFinding {
  ip: string
  hostname?: string
  os?: string
  ports: PortFinding[]
  services: string[]
  vulnerabilities: Vulnerability[]
}

interface PortFinding {
  id: number
  protocol: string
  service: string
  product?: string
  tunnel?: string
  script?: any
}

interface CommandEntry {
  host: string
  date: string
}

interface ScanSummary {
  directory: string
  generatedAt: string
  currentAudit: AuditData
  auditHistory: AuditHistory
  scoreEvolution: ScorePoint[]
  networkDevices: NetworkDevice[]
  networkConnections: NetworkConnection[]
  networkHtml?: string
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
})

const severityWeights: Record<SeverityLabel, number> = {
  Critique: 5,
  Haute: 3,
  Moyenne: 2,
  Basse: 1,
}

const severityOrder: SeverityLabel[] = ['Basse', 'Moyenne', 'Haute', 'Critique']

let cachedSummary: ScanSummary | null = null

export function invalidateScanCache() {
  cachedSummary = null
}

export function getCurrentAudit(): AuditData {
  return getScanSummary().currentAudit
}

export function getAuditHistory(): AuditHistory {
  return getScanSummary().auditHistory
}

export function getScoreEvolution(): ScorePoint[] {
  return getScanSummary().scoreEvolution
}

export function getNetworkDevices(): NetworkDevice[] {
  return getScanSummary().networkDevices
}

export function getNetworkConnections(): NetworkConnection[] {
  return getScanSummary().networkConnections
}

export function getNetworkMapHtml(): string | undefined {
  return getScanSummary().networkHtml
}

function getScanSummary(): ScanSummary {
  if (cachedSummary && process.env.NODE_ENV !== 'development') {
    return cachedSummary
  }

  const summary = buildScanSummary()
  cachedSummary = summary
  return summary
}

function buildScanSummary(): ScanSummary {
  const scanDir = findLatestScanDirectory()
  if (!scanDir) {
    throw new Error('Aucun dossier scan_results_* trouvé à la racine du dépôt')
  }

  const topologyPath = path.join(scanDir, 'network_topology.json')
  const topology = fs.existsSync(topologyPath)
    ? JSON.parse(fs.readFileSync(topologyPath, 'utf-8'))
    : null

  const generatedAt = topology?.generated_at
    ? new Date(topology.generated_at).toISOString()
    : new Date().toISOString()

  const xmlFiles = fs
    .readdirSync(scanDir)
    .filter((file) => file.endsWith('_detailed_scan.xml'))

  const hosts = xmlFiles
    .map((file) => parseHostXml(path.join(scanDir, file)))
    .filter((host): host is HostFinding => Boolean(host))

  const hostMap = new Map(hosts.map((host) => [host.ip, host]))

  const commandTimeline = parseCommandTimeline(path.join(scanDir, 'nmap_commands.txt'))
  const orderedHosts = buildOrderedHosts(hostMap, commandTimeline)

  const vulnerabilities = hosts.flatMap((host) => host.vulnerabilities)
  const severityCounts = countSeverities(vulnerabilities)

  const companyName = topology?.hosts
    ? `Panoptis — scan ${topology.hosts.length} hôtes`
    : 'Panoptis — scan réseau'

  const snapshots = buildAuditSnapshots(
    orderedHosts.length ? orderedHosts : hosts.map((host) => ({ host, date: generatedAt })),
    generatedAt,
    companyName
  )

  let currentAudit = snapshots[snapshots.length - 1]
  currentAudit = {
    ...currentAudit,
    id: `scan_${path.basename(scanDir)}`,
    vulnerabilities,
    remediationTasks: buildRemediationTasks(vulnerabilities, generatedAt),
  }

  const auditsWithTrends = snapshots.map((snapshot, index) => {
    const trend =
      index === 0
        ? undefined
        : snapshot.overallScore > snapshots[index - 1].overallScore
        ? 'up'
        : snapshot.overallScore < snapshots[index - 1].overallScore
        ? 'down'
        : 'stable'
    if (index === snapshots.length - 1) {
      return { ...currentAudit, trend }
    }
    return { ...snapshot, trend, remediationTasks: [] }
  })

  const scoreEvolution = buildScoreEvolution(orderedHosts, hosts.length, generatedAt)

  const networkDevices = hosts.map((host) => buildNetworkDevice(host))
  const networkConnections = buildNetworkConnections(
    networkDevices.map((device) => device.id),
    topology?.edges
  )
  const networkHtmlPath = path.join(scanDir, 'network_topology.html')
  const networkHtml = fs.existsSync(networkHtmlPath)
    ? fs.readFileSync(networkHtmlPath, 'utf-8')
    : undefined

  return {
    directory: scanDir,
    generatedAt,
    currentAudit,
    auditHistory: { audits: auditsWithTrends },
    scoreEvolution,
    networkDevices,
    networkConnections,
    networkHtml,
  }
}

function findLatestScanDirectory(): string | null {
  const directories = new Set<string>()

  const explicit = process.env.SCAN_RESULTS_DIR
  if (explicit && fs.existsSync(explicit)) {
    directories.add(path.resolve(explicit))
  }

  const repoRoot = path.resolve(process.cwd(), '..')
  collectScanDirectories(repoRoot, directories)
  collectScanDirectories(path.join(repoRoot, 'Network'), directories)

  const sorted = Array.from(directories).sort().reverse()
  return sorted[0] ?? null
}

function collectScanDirectories(root: string, target: Set<string>) {
  if (!fs.existsSync(root)) return
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.startsWith('scan_results_')) {
      target.add(path.join(root, entry.name))
    }
  }
}

function parseHostXml(filePath: string): HostFinding | null {
  try {
    const xmlContent = fs.readFileSync(filePath, 'utf-8')
    const parsed = parser.parse(xmlContent)
    const hostNode = Array.isArray(parsed?.nmaprun?.host)
      ? parsed.nmaprun.host[0]
      : parsed?.nmaprun?.host
    if (!hostNode) return null

    const ip = extractAddress(hostNode.address)
    if (!ip) return null

    const hostnames = extractHostnames(hostNode.hostnames)

    const portsNode = hostNode.ports?.port
    const portArray = Array.isArray(portsNode) ? portsNode : portsNode ? [portsNode] : []
    const openPorts = portArray
      .filter((port) => port?.state?.state === 'open')
      .map((port) => ({
        id: Number(port.portid),
        protocol: port.protocol ?? 'tcp',
        service: port.service?.name || `tcp/${port.portid}`,
        product: port.service?.product || port.service?.extrainfo,
        tunnel: port.service?.tunnel,
        script: port.script,
      }))

    const osMatch = hostNode.os?.osmatch
    const osName = Array.isArray(osMatch) ? osMatch[0]?.name : osMatch?.name

    const serviceNames = new Set<string>()
    const vulnerabilities: Vulnerability[] = []

    for (const port of openPorts) {
      const derivedHostname = extractHostnameFromScripts(port.script)
      if (derivedHostname) hostnames.add(derivedHostname)

      const serviceKey = port.service || `tcp/${port.id}`
      if (serviceNames.has(serviceKey) && port.id >= 1024) {
        continue
      }
      serviceNames.add(serviceKey)

      const vulnerability = buildVulnerability(ip, hostnames, port)
      if (vulnerability) {
        vulnerabilities.push(vulnerability)
      }
    }

    const services = Array.from(serviceNames).map((name) => name.toUpperCase())

    return {
      ip,
      hostname: hostnames.values().next().value,
      os: osName || 'Inconnu',
      ports: openPorts,
      services,
      vulnerabilities,
    }
  } catch (error) {
    console.error(`Échec du parsing de ${filePath}:`, (error as Error).message)
    return null
  }
}

function extractAddress(addressNode: any): string | null {
  if (!addressNode) return null
  if (Array.isArray(addressNode)) {
    const ipv4 = addressNode.find((addr) => addr.addrtype === 'ipv4')
    return ipv4?.addr || null
  }
  return addressNode.addr || null
}

function extractHostnames(hostnamesNode: any): Set<string> {
  const names = new Set<string>()
  if (!hostnamesNode) return names
  const { hostname } = hostnamesNode
  if (!hostname) return names
  if (Array.isArray(hostname)) {
    hostname.forEach((entry) => {
      if (entry?.name) names.add(entry.name)
    })
  } else if (typeof hostname === 'string') {
    names.add(hostname)
  } else if (hostname.name) {
    names.add(hostname.name)
  }
  return names
}

function extractHostnameFromScripts(scriptNode: any): string | undefined {
  const scripts = Array.isArray(scriptNode) ? scriptNode : scriptNode ? [scriptNode] : []
  for (const script of scripts) {
    if (
      typeof script?.output === 'string' &&
      typeof script?.id === 'string' &&
      script.id.includes('rdp-ntlm-info')
    ) {
      const match = script.output.match(/DNS_Computer_Name:\s*([^\s]+)/i)
      if (match) return match[1]
    }
  }
  return undefined
}

function buildVulnerability(
  ip: string,
  hostnames: Set<string>,
  port: PortFinding & { script?: any }
): Vulnerability | null {
  const hostLabel = hostnames.size ? `${Array.from(hostnames)[0]} (${ip})` : ip
  const serviceName = port.service.toLowerCase()

  const hints = determineServiceHints(serviceName, port.id)
  if (!hints) {
    return {
      id: `${ip}-${port.id}`,
      severity: 'Basse',
      category: 'Sécurité Réseau',
      cve: 'N/A',
      affectedSystem: hostLabel,
      cvssScore: 3.5,
      description: `Port ${port.id}/tcp (${port.service.toUpperCase()}) exposé sur ${hostLabel}`,
      remediation: 'Limiter l’accès à ce service aux adresses autorisées et vérifier la configuration.',
    }
  }

  return {
    id: `${ip}-${port.id}`,
    severity: hints.severity,
    category: hints.category,
    cve: hints.cve,
    affectedSystem: hostLabel,
    cvssScore: mapCvssScore(hints.severity),
    description: `Port ${port.id}/tcp exposé (${port.service.toUpperCase()}${
      port.product ? ` - ${port.product}` : ''
    }) sur ${hostLabel}. ${hints.description}`,
    remediation: hints.remediation,
  }
}

function determineServiceHints(service: string, port: number) {
  const lower = service.toLowerCase()
  const matchers = [
    {
      test: () => lower.includes('ms-wbt') || port === 3389,
      severity: 'Critique' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'CVE-2019-0708',
      description: 'Service RDP accessible depuis le réseau.',
      remediation: 'Restreindre RDP (VPN / NLA) et appliquer les correctifs RDS.',
    },
    {
      test: () => lower.includes('microsoft-ds') || port === 445,
      severity: 'Critique' as SeverityLabel,
      category: 'Sécurité AD',
      cve: 'CVE-2017-0144',
      description: 'Partage SMB ouvert pouvant être exploité à distance.',
      remediation: 'Désactiver SMBv1, filtrer le port 445 et appliquer les correctifs SMB.',
    },
    {
      test: () => lower.includes('netbios') || port === 139,
      severity: 'Haute' as SeverityLabel,
      category: 'Sécurité AD',
      cve: 'CVE-1999-0653',
      description: 'NetBIOS permet l’exposition d’informations AD.',
      remediation: 'Limiter NetBIOS aux segments internes et activer la signature.',
    },
    {
      test: () => lower.includes('msrpc') || port === 135,
      severity: 'Haute' as SeverityLabel,
      category: 'Durcissement Système',
      cve: 'CVE-2017-0143',
      description: 'RPC Windows disponible depuis le réseau.',
      remediation: 'Restreindre les services RPC aux administrateurs et filtrer le port 135.',
    },
    {
      test: () => lower.includes('ftp') || port === 21,
      severity: 'Haute' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'N/A',
      description: 'FTP non chiffré détecté.',
      remediation: 'Migrer vers SFTP/FTPS ou désactiver FTP.',
    },
    {
      test: () => lower.includes('telnet') || port === 23,
      severity: 'Critique' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'N/A',
      description: 'Telnet non chiffré accessible.',
      remediation: 'Supprimer Telnet et utiliser SSH.',
    },
    {
      test: () => lower.includes('http') && port !== 443,
      severity: 'Moyenne' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'N/A',
      description: 'Service HTTP exposé.',
      remediation: 'Durcir le serveur web et filtrer les IP autorisées.',
    },
    {
      test: () => lower.includes('https') || port === 443,
      severity: 'Moyenne' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'N/A',
      description: 'Interface HTTPS accessible.',
      remediation: 'Vérifier les certificats et authentifier l’accès.',
    },
    {
      test: () => lower.includes('ssh') || port === 22,
      severity: 'Basse' as SeverityLabel,
      category: 'Durcissement Système',
      cve: 'N/A',
      description: 'SSH ouvert.',
      remediation: 'Restreindre via ACL/MFA et désactiver les comptes inutilisés.',
    },
    {
      test: () => lower.includes('mysql') || port === 3306,
      severity: 'Moyenne' as SeverityLabel,
      category: 'Durcissement Système',
      cve: 'N/A',
      description: 'Base MySQL accessible.',
      remediation: 'Limiter aux applications internes et activer TLS.',
    },
    {
      test: () => lower.includes('nfs') || port === 2049,
      severity: 'Haute' as SeverityLabel,
      category: 'Configuration Réseau',
      cve: 'N/A',
      description: 'Partages NFS visibles.',
      remediation: 'Restreindre les exportations aux serveurs attendus.',
    },
    {
      test: () => lower.includes('rpcbind') || port === 111,
      severity: 'Moyenne' as SeverityLabel,
      category: 'Durcissement Système',
      cve: 'N/A',
      description: 'RPCBind divulgue les services disponibles.',
      remediation: 'Filtrer RPCBind et n’exposer que les ports nécessaires.',
    },
    {
      test: () => lower.includes('vnc') || port === 5900,
      severity: 'Haute' as SeverityLabel,
      category: 'Sécurité Réseau',
      cve: 'N/A',
      description: 'Service VNC détecté.',
      remediation: 'Activer l’authentification forte ou désactiver VNC.',
    },
  ]

  const match = matchers.find((matcher) => matcher.test())
  return match || null
}

function mapCvssScore(severity: SeverityLabel) {
  switch (severity) {
    case 'Critique':
      return 9.5
    case 'Haute':
      return 7.5
    case 'Moyenne':
      return 5.5
    default:
      return 3.1
  }
}

function countSeverities(vulnerabilities: Vulnerability[]) {
  return vulnerabilities.reduce(
    (acc, vuln) => {
      acc.total += 1
      if (vuln.severity === 'Critique') acc.critical += 1
      else if (vuln.severity === 'Haute') acc.high += 1
      else if (vuln.severity === 'Moyenne') acc.medium += 1
      else acc.low += 1
      return acc
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
  )
}

function computeScore(counts: { critical: number; high: number; medium: number; low: number }, hostCount: number) {
  const penalty =
    counts.critical * severityWeights.Critique +
    counts.high * severityWeights.Haute +
    counts.medium * severityWeights.Moyenne +
    counts.low * severityWeights.Basse
  const normalized = penalty / Math.max(1, hostCount)
  return clamp(100 - Math.round(normalized * 4), 5, 95)
}

function computeCategoryScores(vulnerabilities: Vulnerability[], hostCount: number) {
  const categories: Record<string, number> = {
    'Sécurité Réseau': 0,
    'Durcissement Système': 0,
    'Sécurité AD': 0,
    'Configuration Réseau': 0,
  }

  for (const vuln of vulnerabilities) {
    categories[vuln.category] = (categories[vuln.category] || 0) + severityWeights[vuln.severity]
  }

  return {
    networkSecurity: clamp(100 - Math.round((categories['Sécurité Réseau'] / Math.max(1, hostCount)) * 4), 5, 95),
    systemHardening: clamp(
      100 - Math.round((categories['Durcissement Système'] / Math.max(1, hostCount)) * 4),
      5,
      95
    ),
    adSecurity: clamp(100 - Math.round((categories['Sécurité AD'] / Math.max(1, hostCount)) * 5), 5, 95),
    networkConfig: clamp(
      100 - Math.round((categories['Configuration Réseau'] / Math.max(1, hostCount)) * 4),
      5,
      95
    ),
  }
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max)
}

function buildRemediationTasks(vulnerabilities: Vulnerability[], generatedAt: string): RemediationTask[] {
  const weights = (severity: SeverityLabel) => {
    switch (severity) {
      case 'Critique':
        return { workload: 70, duration: 1.5 }
      case 'Haute':
        return { workload: 50, duration: 1 }
      case 'Moyenne':
        return { workload: 35, duration: 0.5 }
      default:
        return { workload: 20, duration: 0.5 }
    }
  }

  const sorted = [...vulnerabilities].sort(
    (a, b) => severityOrder.indexOf(b.severity) - severityOrder.indexOf(a.severity)
  )

  const baseDate = new Date(generatedAt)
  return sorted.slice(0, 6).map((vuln, index) => {
    const planning = weights(vuln.severity)
    const dueDate = new Date(baseDate.getTime())
    dueDate.setDate(dueDate.getDate() + index * 2 + 2)
    return {
      id: `task-${vuln.id}`,
      name: `Corriger ${vuln.description.split('.')[0]}`,
      severity: vuln.severity,
      workload: planning.workload,
      duration: planning.duration,
      category: vuln.category,
      dueDate: dueDate.toISOString(),
    }
  })
}

function parseCommandTimeline(filePath: string): CommandEntry[] {
  if (!fs.existsSync(filePath)) return []
  const lines = fs.readFileSync(filePath, 'utf-8').split('\n')
  const entries: CommandEntry[] = []
  for (const line of lines) {
    if (!line.includes('_detailed_scan')) continue
    const timeMatch = line.match(/^\[(.+?)\]/)
    const hostMatch = line.match(/\/(\d+\.\d+\.\d+\.\d+)_detailed_scan/)
    if (!timeMatch || !hostMatch) continue
    const iso = new Date(timeMatch[1].replace(' ', 'T') + 'Z').toISOString()
    entries.push({ host: hostMatch[1], date: iso })
  }
  return entries.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())
}

function buildOrderedHosts(hostMap: Map<string, HostFinding>, commands: CommandEntry[]) {
  const ordered: Array<{ host: HostFinding; date: string }> = []
  const seen = new Set<string>()
  for (const command of commands) {
    const host = hostMap.get(command.host)
    if (host && !seen.has(host.ip)) {
      ordered.push({ host, date: command.date })
      seen.add(host.ip)
    }
  }
  for (const host of hostMap.values()) {
    if (!seen.has(host.ip)) {
      ordered.push({ host, date: new Date().toISOString() })
      seen.add(host.ip)
    }
  }
  return ordered
}

function buildAuditSnapshots(
  orderedHosts: Array<{ host: HostFinding; date: string }>,
  generatedAt: string,
  companyName: string
): AuditData[] {
  if (!orderedHosts.length) {
    return [
      {
        id: 'scan-empty',
        date: generatedAt,
        companyName,
        overallScore: 100,
        categoryScores: {
          networkSecurity: 100,
          systemHardening: 100,
          adSecurity: 100,
          networkConfig: 100,
        },
        stats: {
          totalVulnerabilities: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          remediationProgress: 100,
        },
        vulnerabilities: [],
        remediationTasks: [],
      },
    ]
  }

  const checkpoints = Array.from(
    new Set([
      Math.max(1, Math.round(orderedHosts.length * 0.35)),
      Math.max(1, Math.round(orderedHosts.length * 0.7)),
      orderedHosts.length,
    ])
  ).sort((a, b) => a - b)

  return checkpoints.map((limit, index) => {
    const subset = orderedHosts.slice(0, limit)
    const vulnerabilities = subset.flatMap((entry) => entry.host.vulnerabilities)
    const counts = countSeverities(vulnerabilities)
    const hostCount = new Set(subset.map((entry) => entry.host.ip)).size
    return {
      id: `scan_${index}_${limit}`,
      date: subset[subset.length - 1].date,
      companyName,
      overallScore: computeScore(counts, hostCount),
      categoryScores: computeCategoryScores(vulnerabilities, hostCount),
      stats: {
        totalVulnerabilities: counts.total,
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        remediationProgress: computeRemediationProgress(counts, hostCount),
      },
      vulnerabilities,
      remediationTasks: [],
    }
  })
}

function computeRemediationProgress(
  counts: { critical: number; high: number; medium: number; low: number; total?: number },
  hostCount: number
) {
  const riskUnits = counts.critical * 4 + counts.high * 2 + counts.medium
  const normalized = riskUnits / Math.max(1, hostCount)
  return clamp(90 - Math.round(normalized * 5), 5, 95)
}

function buildScoreEvolution(
  orderedHosts: Array<{ host: HostFinding; date: string }>,
  hostCount: number,
  fallbackDate: string
): ScorePoint[] {
  if (!orderedHosts.length) {
    return [{ date: fallbackDate, score: 100 }]
  }

  let cumulativePenalty = 0
  const timeline: ScorePoint[] = []
  for (const entry of orderedHosts) {
    const hostCounts = countSeverities(entry.host.vulnerabilities)
    cumulativePenalty +=
      hostCounts.critical * severityWeights.Critique +
      hostCounts.high * severityWeights.Haute +
      hostCounts.medium * severityWeights.Moyenne +
      hostCounts.low * severityWeights.Basse
    const score = clamp(100 - Math.round((cumulativePenalty / Math.max(1, hostCount)) * 4), 5, 95)
    timeline.push({ date: entry.date, score })
  }
  return timeline
}

function buildNetworkDevice(host: HostFinding): NetworkDevice {
  const severityRanking: Record<'critical' | 'high' | 'medium' | 'low', number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  }

  const highest = host.vulnerabilities.reduce<'low' | 'medium' | 'high' | 'critical'>((acc, vuln) => {
    const mapped =
      vuln.severity === 'Critique'
        ? 'critical'
        : vuln.severity === 'Haute'
        ? 'high'
        : vuln.severity === 'Moyenne'
        ? 'medium'
        : 'low'
    return severityRanking[mapped] > severityRanking[acc] ? mapped : acc
  }, 'low')

  return {
    id: host.ip,
    hostname: host.hostname || host.ip,
    ip: host.ip,
    type: inferDeviceType(host),
    os: host.os || 'Inconnu',
    ports: host.ports.map((port) => `${port.id}/tcp`),
    services: host.services,
    vulnerabilityCount: host.vulnerabilities.length,
    severity: highest,
  }
}

function inferDeviceType(host: HostFinding) {
  if (host.ip.endsWith('.1')) return 'firewall'
  if (host.services.some((s) => s.toLowerCase().includes('kerberos') || s.toLowerCase().includes('ldap'))) {
    return 'controller'
  }
  if (host.services.some((s) => s.toLowerCase().includes('netbios') || s.toLowerCase().includes('microsoft-ds'))) {
    return 'workstation'
  }
  if (host.services.some((s) => s.toLowerCase().includes('ssh'))) {
    return 'server'
  }
  return 'server'
}

function buildNetworkConnections(
  deviceIds: string[],
  edges?: Array<{ from: string; to: string }>
): NetworkConnection[] {
  const idSet = new Set(deviceIds)
  const connections: NetworkConnection[] = []
  if (Array.isArray(edges)) {
    for (const edge of edges) {
      if (idSet.has(edge.from) && idSet.has(edge.to)) {
        connections.push({ from: edge.from, to: edge.to })
      }
    }
  }

  if (connections.length === 0 && deviceIds.length > 1) {
    const gateway = deviceIds.find((id) => id.endsWith('.1')) || deviceIds[0]
    for (const id of deviceIds) {
      if (id === gateway) continue
      connections.push({ from: gateway, to: id })
    }
  }

  return connections
}
