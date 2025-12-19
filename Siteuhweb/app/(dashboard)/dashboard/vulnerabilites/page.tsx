import { VulnerabilitiesTable } from '@/components/vulnerabilities-table'
import { getCurrentAudit } from '@/lib/scan-data'

export default function VulnerabilitiesPage() {
  const audit = getCurrentAudit()

  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Vulnérabilités</h1>
        <p className="text-muted-foreground mt-1">
          Liste complète des vulnérabilités détectées lors du dernier audit
        </p>
      </div>

      <VulnerabilitiesTable vulnerabilities={audit.vulnerabilities} />
    </div>
  )
}
