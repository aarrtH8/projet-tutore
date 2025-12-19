'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Play, Square, ChevronDown, ChevronUp, CheckCircle2, Loader2, XCircle } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'

type StageId = 'network' | 'linux' | 'windows'
type ApiStatus = {
  status: 'idle' | 'running' | 'completed' | 'error' | 'stopped'
  stage: StageId | null
  stageLabel?: string
  progress: number
  etaSeconds: number | null
  logs: Array<{ timestamp: number; level: 'info' | 'success' | 'error'; message: string; stage?: StageId }>
  startedAt?: number
  error?: string
  lastRun?: {
    startedAt: number
    finishedAt: number
    durationMs: number
    status: 'completed' | 'error' | 'stopped'
    error?: string
  }
}

const stageLabels: Record<StageId, string> = {
  network: 'Scan réseau',
  linux: 'Audit Linux',
  windows: 'Audit Windows',
}

const logIcons: Record<'info' | 'success' | 'error', JSX.Element> = {
  info: <Loader2 className="h-4 w-4 text-accent flex-shrink-0 mt-0.5" />,
  success: <CheckCircle2 className="h-4 w-4 text-low flex-shrink-0 mt-0.5" />,
  error: <XCircle className="h-4 w-4 text-critical flex-shrink-0 mt-0.5" />,
}

const initialStatus: ApiStatus = {
  status: 'idle',
  stage: null,
  progress: 0,
  etaSeconds: null,
  logs: [],
}

function formatEta(seconds: number | null) {
  if (!seconds || seconds <= 0) {
    return 'Calcul en cours'
  }
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  if (mins === 0) {
    return `${secs}s restantes`
  }
  return `${mins} min ${secs.toString().padStart(2, '0')} restantes`
}

function formatDuration(ms: number) {
  const totalSeconds = Math.max(1, Math.floor(ms / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes === 0) {
    return `${seconds}s`
  }
  return `${minutes} min ${seconds.toString().padStart(2, '0')}s`
}

function formatTimestamp(timestamp?: number) {
  if (!timestamp) {
    return '—'
  }
  return new Date(timestamp).toLocaleString('fr-FR', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function AuditControls() {
  const { toast } = useToast()
  const [status, setStatus] = useState<ApiStatus>(initialStatus)
  const [showLogs, setShowLogs] = useState(false)
  const [isStarting, setIsStarting] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [isMounted, setIsMounted] = useState(false)

  useEffect(() => {
    setIsMounted(true)
  }, [])

  const fetchStatus = useCallback(async () => {
    try {
      const response = await fetch('/api/audit/status', { cache: 'no-store' })
      if (!response.ok) {
        throw new Error('Impossible de récupérer le statut')
      }
      const payload = (await response.json()) as ApiStatus
      setStatus(payload)
    } catch (error) {
      console.error(error)
    }
  }, [])

  useEffect(() => {
    if (!isMounted) return
    fetchStatus()
    const interval = setInterval(fetchStatus, status.status === 'running' ? 3000 : 8000)
    return () => clearInterval(interval)
  }, [fetchStatus, status.status, isMounted])

  const handleStart = async () => {
    setIsStarting(true)
    try {
      const response = await fetch('/api/audit/start', { method: 'POST' })
      if (!response.ok) {
        throw new Error('Le serveur a refusé le démarrage de l’audit')
      }
      const payload = (await response.json()) as ApiStatus
      setStatus(payload)
      toast({
        title: 'Audit démarré',
        description: 'Les scripts réseau, Linux et Windows sont en cours d’exécution.',
      })
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Impossible de démarrer l’audit',
        description: (error as Error).message,
      })
    } finally {
      setIsStarting(false)
      fetchStatus()
    }
  }

  const handleStop = async () => {
    setIsStopping(true)
    try {
      const response = await fetch('/api/audit/stop', { method: 'POST' })
      if (!response.ok) {
        throw new Error('Le serveur n’a pas pu arrêter l’audit')
      }
      const payload = (await response.json()) as ApiStatus
      setStatus(payload)
      toast({
        variant: 'destructive',
        title: 'Audit arrêté',
        description: 'Le pipeline a été interrompu.',
      })
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Erreur lors de l’arrêt',
        description: (error as Error).message,
      })
    } finally {
      setIsStopping(false)
      fetchStatus()
    }
  }

  const isRunning = status.status === 'running'
  const progress = useMemo(() => Math.min(Math.max(status.progress ?? 0, 0), 100), [status.progress])

  const statusBadge = (() => {
    switch (status.status) {
      case 'idle':
        return <Badge variant="secondary">Inactif</Badge>
      case 'running':
        return (
          <Badge className="bg-accent text-accent-foreground">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            En cours
          </Badge>
        )
      case 'completed':
        return (
          <Badge className="bg-low text-white">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Terminé
          </Badge>
        )
      case 'error':
        return (
          <Badge className="bg-critical text-white">
            <XCircle className="h-3 w-3 mr-1" />
            Erreur
          </Badge>
        )
      case 'stopped':
        return (
          <Badge variant="outline">
            <Square className="h-3 w-3 mr-1" />
            Arrêté
          </Badge>
        )
    }
  })()

  const lastRunText = status.lastRun
    ? `${formatTimestamp(status.lastRun.finishedAt)} • Durée: ${formatDuration(status.lastRun.durationMs)}`
    : 'Aucun audit exécuté récemment'

  if (!isMounted) {
    return (
      <Card className="border-2">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle>Contrôle des Audits</CardTitle>
              <CardDescription>Chargement de l’état en cours…</CardDescription>
            </div>
            <Badge variant="secondary">Inactif</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <Progress value={0} className="h-2" />
          <div className="w-full h-20 rounded-lg bg-muted/40 animate-pulse" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="border-2">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>Contrôle des Audits</CardTitle>
            <CardDescription>Démarrer, arrêter et surveiller les scans de sécurité</CardDescription>
          </div>
          {statusBadge}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {isRunning && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                {status.stageLabel
                  ? `Étape actuelle : ${status.stageLabel}`
                  : 'Étape actuelle : initialisation'}
              </span>
              <span className="font-medium">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
            <p className="text-xs text-muted-foreground">{formatEta(status.etaSeconds)}</p>
          </div>
        )}

        <div className="flex flex-wrap gap-3">
          {isRunning ? (
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="destructive" disabled={isStopping}>
                  <Square className="h-4 w-4 mr-2" />
                  Arrêter le Scan Actuel
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirmer l’arrêt de l’audit</DialogTitle>
                  <DialogDescription>
                    Êtes-vous sûr de vouloir arrêter l’audit en cours ? Les données collectées
                    pourraient être incomplètes.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button variant="outline">Annuler</Button>
                  </DialogClose>
                  <DialogClose asChild>
                    <Button variant="destructive" onClick={handleStop} disabled={isStopping}>
                      Arrêter
                    </Button>
                  </DialogClose>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          ) : (
            <Dialog>
              <DialogTrigger asChild>
                <Button className="bg-low hover:bg-low/90" disabled={isStarting}>
                  <Play className="h-4 w-4 mr-2" />
                  Démarrer un Audit Manuel
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Lancer un audit complet</DialogTitle>
                  <DialogDescription>
                    Le scan réseau sera exécuté puis enchaîné avec les audits Linux (Lynis) et
                    Windows (PingCastle). L’opération peut durer plusieurs minutes.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button variant="outline">Annuler</Button>
                  </DialogClose>
                  <DialogClose asChild>
                    <Button
                      onClick={handleStart}
                      className="bg-low hover:bg-low/90"
                      disabled={isStarting}
                    >
                      Démarrer
                    </Button>
                  </DialogClose>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>

        <div className="pt-4 border-t space-y-2">
          <h4 className="text-sm font-medium text-foreground">Dernière exécution</h4>
          <p className="text-sm text-muted-foreground">{lastRunText}</p>
          {status.lastRun?.status === 'error' && status.lastRun.error && (
            <p className="text-xs text-critical">Erreur : {status.lastRun.error}</p>
          )}
        </div>

        <div className="pt-4 border-t">
          <Button
            variant="ghost"
            className="w-full justify-between"
            onClick={() => setShowLogs((prev) => !prev)}
          >
            <span className="font-medium">Logs d’exécution</span>
            {showLogs ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>

          {showLogs && (
            <div className="mt-4 space-y-2 max-h-64 overflow-y-auto p-4 bg-muted/50 rounded-lg font-mono text-xs">
              {status.logs.length === 0 && (
                <p className="text-muted-foreground text-center py-4">Aucun log disponible</p>
              )}
              {status.logs.map((log, index) => (
                <div key={`${log.timestamp}-${index}`} className="flex items-start gap-2">
                  {logIcons[log.level]}
                  <div>
                    <div className="flex gap-2 flex-wrap">
                      <span className="text-muted-foreground">
                        {new Date(log.timestamp).toLocaleTimeString('fr-FR')}
                      </span>
                      {log.stage && (
                        <Badge variant="outline" className="text-[0.6rem] uppercase tracking-wide">
                          {stageLabels[log.stage]}
                        </Badge>
                      )}
                    </div>
                    <p className={log.level === 'error' ? 'text-critical' : ''}>{log.message}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
