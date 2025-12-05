import { RemediationCalendar } from '@/components/remediation-calendar'
import { currentAudit } from '@/lib/mock-data'

export default function CalendrierPage() {
  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">
          Calendrier de Remédiation
        </h1>
        <p className="text-muted-foreground mt-1">
          Planification des tâches de correction des vulnérabilités
        </p>
      </div>

      <RemediationCalendar tasks={currentAudit.remediationTasks} />
    </div>
  )
}
