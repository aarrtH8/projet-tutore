'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { PanoptisLogo } from '@/components/panoptis-logo'
import { User } from '@/lib/auth'
import { LayoutDashboard, AlertTriangle, Calendar, History, Network, Settings, LogOut, Menu, Lock } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useToast } from '@/hooks/use-toast'

interface NavItem {
  label: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  adminOnly?: boolean
}

const navItems: NavItem[] = [
  { label: 'Tableau de bord', href: '/dashboard', icon: LayoutDashboard },
  { label: 'Vulnérabilités', href: '/dashboard/vulnerabilites', icon: AlertTriangle },
  { label: 'Calendrier de remédiation', href: '/dashboard/calendrier', icon: Calendar },
  { label: 'Historique des audits', href: '/dashboard/historique', icon: History },
  { label: 'Carte réseau', href: '/dashboard/carte-reseau', icon: Network },
  { label: 'Configuration', href: '/dashboard/configuration', icon: Settings, adminOnly: true },
]

export function DashboardNav({ user }: { user: User }) {
  const pathname = usePathname()
  const router = useRouter()
  const { toast } = useToast()
  const [isOpen, setIsOpen] = useState(false)

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      toast({
        title: 'Déconnexion réussie',
        description: 'À bientôt!',
      })
      router.push('/login')
      router.refresh()
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Erreur',
        description: 'Erreur lors de la déconnexion',
      })
    }
  }

  const NavContent = () => (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-border">
        <PanoptisLogo className="h-10 w-auto text-primary" />
        <div className="mt-4 text-sm">
          <p className="font-medium text-foreground">{user.username}</p>
          <p className="text-muted-foreground capitalize">
            {user.role === 'admin' ? 'Administrateur' : 'Client'}
          </p>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href
          const Icon = item.icon
          const canAccess = !item.adminOnly || user.role === 'admin'

          return (
            <Link
              key={item.href}
              href={canAccess ? item.href : '#'}
              onClick={(e) => {
                if (!canAccess) {
                  e.preventDefault()
                  toast({
                    variant: 'destructive',
                    title: 'Accès refusé',
                    description: 'Cette page est réservée aux administrateurs',
                  })
                } else {
                  setIsOpen(false)
                }
              }}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent hover:text-accent-foreground',
                !canAccess && 'opacity-50 cursor-not-allowed'
              )}
            >
              <Icon className="h-5 w-5" />
              {item.label}
              {item.adminOnly && <Lock className="h-3 w-3 ml-auto" />}
            </Link>
          )
        })}
      </nav>

      <div className="p-4 border-t border-border">
        <Button
          variant="ghost"
          className="w-full justify-start"
          onClick={handleLogout}
        >
          <LogOut className="h-5 w-5 mr-3" />
          Déconnexion
        </Button>
      </div>
    </div>
  )

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden lg:block w-64 border-r border-border bg-card">
        <NavContent />
      </aside>

      {/* Mobile Header */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-card border-b border-border">
        <div className="flex items-center justify-between p-4">
          <PanoptisLogo className="h-8 w-auto text-primary" />
          <Sheet open={isOpen} onOpenChange={setIsOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon">
                <Menu className="h-6 w-6" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 p-0">
              <NavContent />
            </SheetContent>
          </Sheet>
        </div>
      </div>

      {/* Mobile spacer */}
      <div className="lg:hidden h-16" />
    </>
  )
}
