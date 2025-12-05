'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { Loader2 } from 'lucide-react'

export function LoginForm() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()
  const { toast } = useToast()

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setIsLoading(true)

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        toast({
          title: 'Connexion réussie',
          description: `Bienvenue ${username}`,
        })
        router.push('/dashboard')
        router.refresh()
      } else {
        toast({
          variant: 'destructive',
          title: 'Erreur de connexion',
          description: data.error || 'Identifiants incorrects',
        })
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Erreur',
        description: 'Une erreur est survenue. Veuillez réessayer.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="rounded-lg border border-border bg-muted/50 p-4 space-y-2">
        <p className="text-sm font-medium text-foreground">Identifiants de test :</p>
        <div className="space-y-1 text-sm text-muted-foreground font-mono">
          <p><span className="text-foreground">Admin :</span> admin / admin123</p>
          <p><span className="text-foreground">Client :</span> client / client123</p>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="username">Nom d'utilisateur</Label>
        <Input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          disabled={isLoading}
          autoComplete="username"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Mot de passe</Label>
        <Input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          disabled={isLoading}
          autoComplete="current-password"
        />
      </div>
      <Button type="submit" className="w-full" disabled={isLoading}>
        {isLoading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Connexion en cours...
          </>
        ) : (
          'Se connecter'
        )}
      </Button>
      <p className="text-xs text-muted-foreground text-center">
        Maximum 5 tentatives par période de 15 minutes
      </p>
    </form>
  )
}
