import { AuditHistoryView } from '@/components/audit-history-view'
import { auditHistory } from '@/lib/mock-data'

export default function HistoriquePage() {
  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">
          Historique des Audits
        </h1>
        <p className="text-muted-foreground mt-1">
          Suivi de l'évolution de la sécurité dans le temps
        </p>
      </div>

      <AuditHistoryView history={auditHistory} />
    </div>
  )
}
