import { redirect } from 'next/navigation'
import { getSession } from '@/lib/auth'
import { ConfigurationForm } from '@/components/configuration-form'
import { AuditControls } from '@/components/audit-controls'

export default async function ConfigurationPage() {
  const session = await getSession()

  if (!session || session.role !== 'admin') {
    redirect('/dashboard')
  }

  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Configuration</h1>
        <p className="text-muted-foreground mt-1">
          Paramètres système et contrôles d'audit (Admin uniquement)
        </p>
      </div>

      <AuditControls />
      <ConfigurationForm />
    </div>
  )
}
