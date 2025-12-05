import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface SeverityBadgeProps {
  severity: 'Critique' | 'Haute' | 'Moyenne' | 'Basse'
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const variants = {
    Critique: 'bg-critical text-white hover:bg-critical/90',
    Haute: 'bg-high text-white hover:bg-high/90',
    Moyenne: 'bg-medium text-foreground hover:bg-medium/90',
    Basse: 'bg-low text-white hover:bg-low/90',
  }

  return (
    <Badge className={cn(variants[severity], className)}>
      {severity}
    </Badge>
  )
}
