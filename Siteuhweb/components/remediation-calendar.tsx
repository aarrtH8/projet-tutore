'use client'

import { useState, useMemo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from '@/components/severity-badge'
import { RemediationTask } from '@/lib/mock-data'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { CalendarDays, Clock } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface RemediationCalendarProps {
  tasks: RemediationTask[]
}

export function RemediationCalendar({ tasks }: RemediationCalendarProps) {
  const [view, setView] = useState<'week' | 'month'>('week')
  const [sortBy, setSortBy] = useState<'criticality' | 'urgency' | 'feasibility'>('criticality')

  // Calculate totals
  const totalWorkload = useMemo(() => {
    return tasks.reduce((sum, task) => sum + task.workload, 0)
  }, [tasks])

  const totalDuration = useMemo(() => {
    return tasks.reduce((sum, task) => sum + task.duration, 0)
  }, [tasks])

  // Sort tasks
  const sortedTasks = useMemo(() => {
    return [...tasks].sort((a, b) => {
      if (sortBy === 'criticality') {
        const severityOrder = { Critique: 0, Haute: 1, Moyenne: 2, Basse: 3 }
        return severityOrder[a.severity] - severityOrder[b.severity]
      }
      if (sortBy === 'urgency') {
        if (!a.dueDate || !b.dueDate) return 0
        return new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime()
      }
      // feasibility - shorter tasks first
      return a.duration - b.duration
    })
  }, [tasks, sortBy])

  const formatDuration = (duration: number) => {
    if (duration === 0.5) return '3h30 (demi-journée)'
    if (duration === 1) return '7h (1 journée)'
    if (duration === 1.5) return '10h30 (1,5 journées)'
    return `${duration * 7}h (${duration} journées)`
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Nombre de tâches</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{tasks.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Charge totale estimée</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalWorkload}%</div>
            <p className="text-xs text-muted-foreground mt-1">
              d'une semaine de 35h
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Durée totale</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalDuration}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {totalDuration === 1 ? 'journée' : 'journées'} de travail
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Controls */}
      <Card>
        <CardHeader>
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <CardTitle>Tâches de Remédiation</CardTitle>
              <CardDescription>
                Planification organisée par ordre de priorité
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Tabs value={sortBy} onValueChange={(v) => setSortBy(v as any)}>
                <TabsList>
                  <TabsTrigger value="criticality">Criticité</TabsTrigger>
                  <TabsTrigger value="urgency">Urgence</TabsTrigger>
                  <TabsTrigger value="feasibility">Faisabilité</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {sortedTasks.map((task, index) => (
              <div
                key={task.id}
                className="relative p-4 rounded-lg border border-border bg-card hover:bg-accent/50 transition-colors"
              >
                <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                  <div className="flex-1 space-y-2">
                    <div className="flex items-start gap-3">
                      <span className="text-sm font-medium text-muted-foreground mt-1">
                        #{index + 1}
                      </span>
                      <div className="flex-1">
                        <h3 className="font-semibold text-foreground">{task.name}</h3>
                        <p className="text-sm text-muted-foreground mt-1">{task.category}</p>
                      </div>
                      <SeverityBadge severity={task.severity} />
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <div className="flex items-center gap-2 text-sm">
                      <Clock className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{formatDuration(task.duration)}</span>
                    </div>
                    <Badge variant="secondary">
                      Charge: {task.workload}%
                    </Badge>
                    {task.dueDate && (
                      <div className="flex items-center gap-2 text-sm">
                        <CalendarDays className="h-4 w-4 text-muted-foreground" />
                        <span>
                          {new Date(task.dueDate).toLocaleDateString('fr-FR', {
                            day: 'numeric',
                            month: 'short',
                          })}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
                {/* Progress bar */}
                <div className="mt-3">
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary transition-all"
                      style={{ width: `${task.workload}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
