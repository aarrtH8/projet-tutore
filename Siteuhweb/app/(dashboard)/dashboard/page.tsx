import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ScoreGauge } from '@/components/score-gauge'
import { CategoryScoreCard } from '@/components/category-score-card'
import { SeverityBadge } from '@/components/severity-badge'
import { ScoreChart } from '@/components/score-chart'
import { Shield, Server, Lock, Network, AlertCircle, TrendingUp, Calendar } from 'lucide-react'
import { getCurrentAudit, getScoreEvolution } from '@/lib/scan-data'

export default function DashboardPage() {
  const currentAudit = getCurrentAudit()
  const scoreEvolution = getScoreEvolution()
  const { overallScore, categoryScores, stats, date } = currentAudit

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="p-4 lg:p-8 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Tableau de bord</h1>
        <p className="text-muted-foreground mt-1">
          Vue d'ensemble de la sécurité de votre infrastructure
        </p>
      </div>

      {/* Overall Score */}
      <Card className="border-2">
        <CardHeader>
          <CardTitle>Score Global de Sécurité</CardTitle>
          <CardDescription>
            Dernier audit: {formatDate(date)}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center py-6">
          <ScoreGauge score={overallScore} size="lg" showLabel={false} />
        </CardContent>
      </Card>

      {/* Category Scores */}
      <div>
        <h2 className="text-xl font-semibold mb-4 text-foreground">Scores par Catégorie</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <CategoryScoreCard
            title="Sécurité Réseau"
            score={categoryScores.networkSecurity}
            weight={30}
            icon={<Network className="h-5 w-5" />}
          />
          <CategoryScoreCard
            title="Durcissement Système"
            score={categoryScores.systemHardening}
            weight={25}
            icon={<Server className="h-5 w-5" />}
          />
          <CategoryScoreCard
            title="Sécurité AD"
            score={categoryScores.adSecurity}
            weight={25}
            icon={<Lock className="h-5 w-5" />}
          />
          <CategoryScoreCard
            title="Configuration Réseau"
            score={categoryScores.networkConfig}
            weight={20}
            icon={<Shield className="h-5 w-5" />}
          />
        </div>
      </div>

      {/* Statistics */}
      <div>
        <h2 className="text-xl font-semibold mb-4 text-foreground">Statistiques</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Total Vulnérabilités</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-muted-foreground" />
                <span className="text-3xl font-bold">{stats.totalVulnerabilities}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Alertes Critiques</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <div className="h-5 w-5 rounded-full bg-critical" />
                <span className="text-3xl font-bold text-critical">{stats.critical}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Haute Priorité</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <div className="h-5 w-5 rounded-full bg-high" />
                <span className="text-3xl font-bold text-high">{stats.high}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Progrès Remédiation</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-low" />
                <span className="text-3xl font-bold text-low">{stats.remediationProgress}%</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Score Evolution Chart */}
      <div>
        <h2 className="text-xl font-semibold mb-4 text-foreground">Évolution du Score</h2>
        <Card>
          <CardHeader>
            <CardTitle>Tendance sur 3 mois</CardTitle>
            <CardDescription>Évolution du score global de sécurité</CardDescription>
          </CardHeader>
          <CardContent>
            <ScoreChart data={scoreEvolution} />
          </CardContent>
        </Card>
      </div>

      {/* Recent Vulnerabilities Summary */}
      <div>
        <h2 className="text-xl font-semibold mb-4 text-foreground">Vulnérabilités Récentes</h2>
        <Card>
          <CardHeader>
            <CardTitle>Top 5 Vulnérabilités Critiques et Hautes</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {currentAudit.vulnerabilities.slice(0, 5).map((vuln) => (
                <div
                  key={vuln.id}
                  className="flex items-start gap-4 p-4 rounded-lg border border-border hover:bg-accent/50 transition-colors"
                >
                  <SeverityBadge severity={vuln.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm text-foreground">{vuln.description}</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      <span className="font-mono">{vuln.cve}</span> • {vuln.affectedSystem}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium">CVSS {vuln.cvssScore}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
