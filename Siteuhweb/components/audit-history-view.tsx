'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ScoreGauge } from '@/components/score-gauge'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { ScoreChart } from '@/components/score-chart'
import type { AuditHistory, AuditData, ScorePoint } from '@/lib/domain-types'

interface AuditHistoryViewProps {
  history: AuditHistory
  timeline: ScorePoint[]
}

export function AuditHistoryView({ history, timeline }: AuditHistoryViewProps) {
  const [selectedAudits, setSelectedAudits] = useState<string[]>([])

  const toggleAuditSelection = (id: string) => {
    setSelectedAudits((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id].slice(-2)
    )
  }

  const getTrendIcon = (trend?: 'up' | 'down' | 'stable') => {
    if (trend === 'up') return <TrendingUp className="h-4 w-4 text-low" />
    if (trend === 'down') return <TrendingDown className="h-4 w-4 text-critical" />
    return <Minus className="h-4 w-4 text-muted-foreground" />
  }

  const getTrendBadge = (trend?: 'up' | 'down' | 'stable') => {
    if (trend === 'up')
      return (
        <Badge className="bg-low text-white hover:bg-low/90">
          <TrendingUp className="h-3 w-3 mr-1" />
          Amélioré
        </Badge>
      )
    if (trend === 'down')
      return (
        <Badge className="bg-critical text-white hover:bg-critical/90">
          <TrendingDown className="h-3 w-3 mr-1" />
          Dégradé
        </Badge>
      )
    return (
      <Badge variant="secondary">
        <Minus className="h-3 w-3 mr-1" />
        Stable
      </Badge>
    )
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    })
  }

  const selectedAuditData = history.audits.filter((a) => selectedAudits.includes(a.id))

  return (
    <div className="space-y-6">
      {/* Global Trend Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Tendance Globale</CardTitle>
          <CardDescription>Évolution du score de sécurité sur tous les audits</CardDescription>
        </CardHeader>
        <CardContent>
          <ScoreChart data={timeline} />
        </CardContent>
      </Card>

      {/* Comparison Tool */}
      {selectedAudits.length === 2 && (
        <Card className="border-primary">
          <CardHeader>
            <CardTitle>Comparaison des Audits</CardTitle>
            <CardDescription>Différences entre les deux audits sélectionnés</CardDescription>
          </CardHeader>
          <CardContent>
            <ComparisonView audits={selectedAuditData} />
          </CardContent>
        </Card>
      )}

      {/* Audit List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Liste des Audits</CardTitle>
              <CardDescription>
                Sélectionnez 2 audits pour les comparer
              </CardDescription>
            </div>
            {selectedAudits.length > 0 && (
              <Button variant="outline" size="sm" onClick={() => setSelectedAudits([])}>
                Réinitialiser la sélection
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {history.audits.map((audit) => (
              <div
                key={audit.id}
                className="flex items-center gap-4 p-4 rounded-lg border border-border hover:bg-accent/50 transition-colors"
              >
                <Checkbox
                  checked={selectedAudits.includes(audit.id)}
                  onCheckedChange={() => toggleAuditSelection(audit.id)}
                  disabled={selectedAudits.length === 2 && !selectedAudits.includes(audit.id)}
                />
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-semibold text-foreground">{formatDate(audit.date)}</h3>
                    {getTrendBadge(audit.trend)}
                  </div>
                  <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
                    <span>Total vulnérabilités: {audit.stats.totalVulnerabilities}</span>
                    <span className="text-critical">Critiques: {audit.stats.critical}</span>
                    <span className="text-high">Hautes: {audit.stats.high}</span>
                  </div>
                </div>
                <div className="text-center">
                  <ScoreGauge score={audit.overallScore} size="sm" showLabel={false} />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function ComparisonView({ audits }: { audits: AuditData[] }) {
  if (audits.length !== 2) return null

  const [older, newer] = audits.sort(
    (a, b) => new Date(a.date).getTime() - new Date(b.date).getTime()
  )

  const scoreDelta = newer.overallScore - older.overallScore
  const vulnDelta = newer.stats.totalVulnerabilities - older.stats.totalVulnerabilities

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <div>
        <h3 className="font-semibold mb-4 text-foreground">
          {new Date(older.date).toLocaleDateString('fr-FR')}
        </h3>
        <div className="space-y-4">
          <div className="flex justify-center">
            <ScoreGauge score={older.overallScore} size="md" />
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Sécurité Réseau:</span>
              <span className="font-medium">{older.categoryScores.networkSecurity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Durcissement Système:</span>
              <span className="font-medium">{older.categoryScores.systemHardening}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Sécurité AD:</span>
              <span className="font-medium">{older.categoryScores.adSecurity}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Configuration Réseau:</span>
              <span className="font-medium">{older.categoryScores.networkConfig}</span>
            </div>
          </div>
        </div>
      </div>

      <div>
        <h3 className="font-semibold mb-4 text-foreground">
          {new Date(newer.date).toLocaleDateString('fr-FR')}
        </h3>
        <div className="space-y-4">
          <div className="flex justify-center">
            <ScoreGauge score={newer.overallScore} size="md" />
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Sécurité Réseau:</span>
              <span className="font-medium flex items-center gap-2">
                {newer.categoryScores.networkSecurity}
                <DeltaBadge
                  delta={newer.categoryScores.networkSecurity - older.categoryScores.networkSecurity}
                />
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Durcissement Système:</span>
              <span className="font-medium flex items-center gap-2">
                {newer.categoryScores.systemHardening}
                <DeltaBadge
                  delta={newer.categoryScores.systemHardening - older.categoryScores.systemHardening}
                />
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Sécurité AD:</span>
              <span className="font-medium flex items-center gap-2">
                {newer.categoryScores.adSecurity}
                <DeltaBadge delta={newer.categoryScores.adSecurity - older.categoryScores.adSecurity} />
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Configuration Réseau:</span>
              <span className="font-medium flex items-center gap-2">
                {newer.categoryScores.networkConfig}
                <DeltaBadge
                  delta={newer.categoryScores.networkConfig - older.categoryScores.networkConfig}
                />
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="md:col-span-2 pt-4 border-t">
        <h4 className="font-semibold mb-3 text-foreground">Résumé des Changements</h4>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
            <span className="text-sm text-muted-foreground">Score global:</span>
            <span className="font-semibold flex items-center gap-2">
              {scoreDelta > 0 ? '+' : ''}
              {scoreDelta}
              <DeltaBadge delta={scoreDelta} />
            </span>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
            <span className="text-sm text-muted-foreground">Vulnérabilités totales:</span>
            <span className="font-semibold flex items-center gap-2">
              {vulnDelta > 0 ? '+' : ''}
              {vulnDelta}
              <DeltaBadge delta={-vulnDelta} />
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function DeltaBadge({ delta }: { delta: number }) {
  if (delta > 0) {
    return (
      <Badge className="bg-low text-white hover:bg-low/90">
        <TrendingUp className="h-3 w-3" />
      </Badge>
    )
  }
  if (delta < 0) {
    return (
      <Badge className="bg-critical text-white hover:bg-critical/90">
        <TrendingDown className="h-3 w-3" />
      </Badge>
    )
  }
  return null
}
