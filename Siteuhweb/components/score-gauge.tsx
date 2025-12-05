'use client'

import { cn } from '@/lib/utils'

interface ScoreGaugeProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  label?: string
}

export function ScoreGauge({ score, size = 'md', showLabel = true, label }: ScoreGaugeProps) {
  const getColor = (score: number) => {
    if (score < 40) return 'text-critical'
    if (score < 70) return 'text-high'
    return 'text-low'
  }

  const getStrokeColor = (score: number) => {
    if (score < 40) return '#DC2626'
    if (score < 70) return '#F59E0B'
    return '#10B981'
  }

  const sizes = {
    sm: { width: 80, strokeWidth: 6, fontSize: 'text-lg' },
    md: { width: 120, strokeWidth: 8, fontSize: 'text-2xl' },
    lg: { width: 160, strokeWidth: 10, fontSize: 'text-4xl' },
  }

  const { width, strokeWidth, fontSize } = sizes[size]
  const radius = (width - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width, height: width }}>
        <svg width={width} height={width} className="transform -rotate-90">
          {/* Background circle */}
          <circle
            cx={width / 2}
            cy={width / 2}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-muted/20"
          />
          {/* Progress circle */}
          <circle
            cx={width / 2}
            cy={width / 2}
            r={radius}
            fill="none"
            stroke={getStrokeColor(score)}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={cn('font-bold', fontSize, getColor(score))}>
            {score}
          </span>
        </div>
      </div>
      {showLabel && label && (
        <p className="text-sm font-medium text-center text-muted-foreground">{label}</p>
      )}
    </div>
  )
}
