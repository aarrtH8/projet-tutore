'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Play, Square, ChevronDown, ChevronUp, CheckCircle2, Loader2, XCircle } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'

export function AuditControls() {
  const [status, setStatus] = useState<'inactive' | 'running' | 'processing' | 'completed'>('inactive')
  const [progress, setProgress] = useState(0)
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<Array<{ type: 'success' | 'error' | 'info'; message: string }>>([])
  const { toast } = useToast()

  const startAudit = () => {
    setStatus('running')
    setProgress(0)
    setLogs([{ type: 'info', message: 'Démarrage de l\'audit...' }])

    // Simulate audit progress
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval)
          setStatus('completed')
          setLogs((logs) => [
            ...logs,
            { type: 'success', message: 'Scan réseau terminé - 45 hôtes détectés' },
            { type: 'success', message: 'Analyse des vulnérabilités terminée' },
            { type: 'success', message: 'Rapport généré avec succès' },
          ])
          toast({
            title: 'Audit terminé',
            description: 'L\'audit a été complété avec succès',
          })
          return 100
        }
        
        // Add log messages at different stages
        if (prev === 30) {
          setLogs((logs) => [
            ...logs,
            { type: 'success', message: 'Scan réseau terminé - 45 hôtes détectés' },
          ])
        }
        if (prev === 60) {
          setLogs((logs) => [
            ...logs,
            { type: 'info', message: 'Analyse des vulnérabilités en cours...' },
          ])
        }
        if (prev === 80) {
          setLogs((logs) => [
            ...logs,
            { type: 'error', message: 'Impossible de se connecter à 192.168.1.50 (timeout)' },
          ])
        }
        
        return prev + 5
      })
    }, 500)

    toast({
      title: 'Audit démarré',
      description: 'L\'audit de sécurité est en cours...',
    })
  }

  const stopAudit = () => {
    setStatus('inactive')
    setProgress(0)
    setLogs((logs) => [...logs, { type: 'error', message: 'Audit arrêté par l\'utilisateur' }])
    toast({
      variant: 'destructive',
      title: 'Audit arrêté',
      description: 'L\'audit a été interrompu',
    })
  }

  const getStatusBadge = () => {
    switch (status) {
      case 'inactive':
        return <Badge variant="secondary">Inactif</Badge>
      case 'running':
        return (
          <Badge className="bg-accent text-accent-foreground">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            En cours
          </Badge>
        )
      case 'processing':
        return (
          <Badge className="bg-accent text-accent-foreground">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            Traitement
          </Badge>
        )
      case 'completed':
        return (
          <Badge className="bg-low text-white">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Terminé
          </Badge>
        )
    }
  }

  return (
    <Card className="border-2">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>Contrôle des Audits</CardTitle>
            <CardDescription>Démarrer, arrêter et surveiller les scans de sécurité</CardDescription>
          </div>
          {getStatusBadge()}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Progress */}
        {(status === 'running' || status === 'processing') && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Progression</span>
              <span className="font-medium">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
            <p className="text-xs text-muted-foreground">
              Temps restant estimé: {Math.ceil((100 - progress) / 5)} minutes
            </p>
          </div>
        )}

        {/* Control Buttons */}
        <div className="flex flex-wrap gap-3">
          {status === 'inactive' || status === 'completed' ? (
            <Dialog>
              <DialogTrigger asChild>
                <Button className="bg-low hover:bg-low/90">
                  <Play className="h-4 w-4 mr-2" />
                  Démarrer un Audit Manuel
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirmer le démarrage de l'audit</DialogTitle>
                  <DialogDescription>
                    Un audit complet va être lancé sur toute l'infrastructure. Cette opération peut
                    prendre plusieurs minutes selon la taille du réseau.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <Button variant="outline">Annuler</Button>
                  <Button onClick={startAudit} className="bg-low hover:bg-low/90">
                    Démarrer
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          ) : (
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="destructive">
                  <Square className="h-4 w-4 mr-2" />
                  Arrêter le Scan Actuel
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirmer l'arrêt de l'audit</DialogTitle>
                  <DialogDescription>
                    Êtes-vous sûr de vouloir arrêter l'audit en cours ? Les données collectées
                    jusqu'à présent seront perdues.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <Button variant="outline">Annuler</Button>
                  <Button variant="destructive" onClick={stopAudit}>
                    Arrêter
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>

        {/* Last Execution */}
        <div className="pt-4 border-t">
          <h4 className="text-sm font-medium mb-2 text-foreground">Dernière exécution</h4>
          <p className="text-sm text-muted-foreground">
            14 novembre 2025 à 09:30 • Durée: 12 minutes
          </p>
        </div>

        {/* Logs */}
        <div className="pt-4 border-t">
          <Button
            variant="ghost"
            className="w-full justify-between"
            onClick={() => setShowLogs(!showLogs)}
          >
            <span className="font-medium">Logs d'exécution</span>
            {showLogs ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
          
          {showLogs && (
            <div className="mt-4 space-y-2 max-h-64 overflow-y-auto p-4 bg-muted/50 rounded-lg font-mono text-xs">
              {logs.map((log, index) => (
                <div key={index} className="flex items-start gap-2">
                  {log.type === 'success' && <CheckCircle2 className="h-4 w-4 text-low flex-shrink-0 mt-0.5" />}
                  {log.type === 'error' && <XCircle className="h-4 w-4 text-critical flex-shrink-0 mt-0.5" />}
                  {log.type === 'info' && <Loader2 className="h-4 w-4 text-accent flex-shrink-0 mt-0.5" />}
                  <span className={log.type === 'error' ? 'text-critical' : ''}>{log.message}</span>
                </div>
              ))}
              {logs.length === 0 && (
                <p className="text-muted-foreground text-center py-4">Aucun log disponible</p>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
