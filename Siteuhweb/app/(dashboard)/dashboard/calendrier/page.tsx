import { RemediationCalendar } from '@/components/remediation-calendar'
import { getCurrentAudit } from '@/lib/scan-data'

export default function CalendrierPage() {
  const audit = getCurrentAudit()

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

      <RemediationCalendar tasks={audit.remediationTasks} />
    </div>
  )
}
