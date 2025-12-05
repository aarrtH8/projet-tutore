import { Progress } from '@/components/ui/progress'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface CategoryScoreCardProps {
  title: string
  score: number
  weight: number
  icon?: React.ReactNode
}

export function CategoryScoreCard({ title, score, weight, icon }: CategoryScoreCardProps) {
  const getColor = (score: number) => {
    if (score < 40) return 'bg-critical'
    if (score < 70) return 'bg-high'
    return 'bg-low'
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <CardTitle className="text-base font-medium">{title}</CardTitle>
          {icon && <div className="text-muted-foreground">{icon}</div>}
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold">{score}</span>
            <span className="text-sm text-muted-foreground pb-1">/100</span>
          </div>
          <div className="space-y-1">
            <Progress value={score} className="h-2" indicatorClassName={getColor(score)} />
            <p className="text-xs text-muted-foreground">Pondération: {weight}%</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
