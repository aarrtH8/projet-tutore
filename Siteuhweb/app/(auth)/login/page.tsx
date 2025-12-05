import { redirect } from 'next/navigation'
import { getSession } from '@/lib/auth'
import { LoginForm } from '@/components/login-form'

export default async function LoginPage() {
  const session = await getSession()
  
  if (session) {
    redirect('/dashboard')
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="flex justify-center mb-8">
          <PanoptisLogo className="h-12 w-auto text-primary" />
        </div>
        <div className="bg-card rounded-lg shadow-lg p-8 border border-border">
          <h1 className="text-2xl font-bold text-center mb-2 text-foreground">
            Connexion
          </h1>
          <p className="text-center text-muted-foreground mb-6">
            Accédez à la plateforme Panoptis
          </p>
          <LoginForm />
        </div>
        <p className="text-center text-sm text-muted-foreground mt-6">
          Audit de sécurité automatisé • Raspberry Pi
        </p>
      </div>
    </div>
  )
}

function PanoptisLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 180 50" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
      <path d="M25 5L10 12V22C10 30 17 37 25 40C33 37 40 30 40 22V12L25 5Z" fill="currentColor" opacity="0.2"/>
      <path d="M25 5L10 12V22C10 30 17 37 25 40C33 37 40 30 40 22V12L25 5Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
      <ellipse cx="25" cy="23" rx="8" ry="5" stroke="currentColor" strokeWidth="1.5"/>
      <circle cx="25" cy="23" r="3" fill="currentColor"/>
      <text x="52" y="32" fontFamily="Inter, sans-serif" fontSize="20" fontWeight="700" fill="currentColor">Panoptis</text>
    </svg>
  )
}
