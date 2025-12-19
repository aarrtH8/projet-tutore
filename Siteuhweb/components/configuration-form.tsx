'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertCircle, Loader2, Plus, Trash2 } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'

type AuditConfigClient = {
  networks: string[]
  hosts: string[]
  exclude: string[]
  options: {
    networkDiscovery: boolean
    searchExploits: boolean
    samba: boolean
    whatweb: boolean
    enableTopology: boolean
    topologyOnly: boolean
    logCommands: boolean
    commandLogFile: string
  }
  performance: {
    timing: string
    maxThreads: number
    scanAllPorts: boolean
    topPorts: number
    minRate: number
    hostTimeout: string
  }
}

const defaultConfig: AuditConfigClient = {
  networks: ['10.0.10.0/24'],
  hosts: [],
  exclude: [],
  options: {
    networkDiscovery: true,
    searchExploits: false,
    samba: true,
    whatweb: true,
    enableTopology: true,
    topologyOnly: false,
    logCommands: true,
    commandLogFile: 'nmap_commands.txt',
  },
  performance: {
    timing: 'T4',
    maxThreads: 10,
    scanAllPorts: false,
    topPorts: 1000,
    minRate: 1000,
    hostTimeout: '30m',
  },
}

function ensureEditable(list: string[]) {
  return list.length ? list : ['']
}

export function ConfigurationForm() {
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [networks, setNetworks] = useState<string[]>(defaultConfig.networks)
  const [hosts, setHosts] = useState<string[]>([])
  const [exclude, setExclude] = useState<string[]>([])
  const [options, setOptions] = useState(defaultConfig.options)
  const [performance, setPerformance] = useState(defaultConfig.performance)

  useEffect(() => {
    let cancelled = false
    async function loadConfig() {
      try {
        const response = await fetch('/api/config/audit', { cache: 'no-store' })
        if (!response.ok) {
          throw new Error('Impossible de charger la configuration actuelle.')
        }
        const payload = (await response.json()) as AuditConfigClient
        if (cancelled) return
        setNetworks(ensureEditable(payload.networks))
        setHosts(payload.hosts.length ? payload.hosts : [])
        setExclude(payload.exclude.length ? payload.exclude : [])
        setOptions(payload.options)
        setPerformance(payload.performance)
        setError(null)
      } catch (err) {
        console.error(err)
        if (!cancelled) {
          setError((err as Error).message)
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }
    loadConfig()
    return () => {
      cancelled = true
    }
  }, [])

  const handleSave = async () => {
    const cleanedNetworks = networks.map((range) => range.trim()).filter(Boolean)
    if (options.networkDiscovery && !cleanedNetworks.length) {
      toast({
        variant: 'destructive',
        title: 'Plages IP manquantes',
        description: 'Ajoute au moins une plage CIDR avant d’activer la découverte réseau.',
      })
      return
    }

    setIsSaving(true)
    try {
      const payload: AuditConfigClient = {
        networks: cleanedNetworks,
        hosts: hosts.map((host) => host.trim()).filter(Boolean),
        exclude: exclude.map((entry) => entry.trim()).filter(Boolean),
        options,
        performance,
      }

      const response = await fetch('/api/config/audit', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        const { error: message } = await response.json()
        throw new Error(message || 'Impossible d’enregistrer la configuration.')
      }

      toast({
        title: 'Configuration enregistrée',
        description: 'Le fichier Network/config.xml a été mis à jour.',
      })
      setError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Erreur inconnue'
      toast({
        variant: 'destructive',
        title: 'Erreur lors de la sauvegarde',
        description: message,
      })
      setError(message)
    } finally {
      setIsSaving(false)
    }
  }

  const renderListInputs = (
    label: string,
    values: string[],
    setValues: (next: string[]) => void,
    placeholder: string
  ) => {
    const safeValues = ensureEditable(values)
    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>{label}</Label>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setValues([...safeValues, ''])}
          >
            <Plus className="h-4 w-4 mr-2" />
            Ajouter
          </Button>
        </div>
        {safeValues.map((value, index) => (
          <div key={`${label}-${index}`} className="flex gap-2">
            <Input
              value={value}
              onChange={(event) => {
                const next = [...safeValues]
                next[index] = event.target.value
                setValues(next)
              }}
              placeholder={placeholder}
            />
            <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={() => setValues(safeValues.filter((_, i) => i !== index))}
              disabled={safeValues.length === 1}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
      </div>
    )
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Paramètres de Configuration</CardTitle>
          <CardDescription>Chargement de la configuration actuelle…</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="h-4 w-1/2 bg-muted animate-pulse rounded" />
          <div className="h-32 bg-muted animate-pulse rounded" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Paramètres de Configuration</CardTitle>
        <CardDescription>
          Ajuste la configuration utilisée par Network/Scanner.py avant de lancer un audit.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Accordion type="multiple" defaultValue={['network', 'options', 'performance']}>
          <AccordionItem value="network">
            <AccordionTrigger className="text-base font-semibold">
              Paramètres réseau
            </AccordionTrigger>
            <AccordionContent className="space-y-6 pt-4">
              {renderListInputs('Plages IP à scanner', networks, setNetworks, '10.0.10.0/24')}

              {renderListInputs(
                'Hôtes individuels',
                hosts.length ? hosts : [],
                setHosts,
                '10.0.10.11'
              )}

              {renderListInputs(
                'Plages ou hôtes exclus',
                exclude.length ? exclude : [],
                setExclude,
                '192.168.1.10-192.168.1.20'
              )}
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="options">
            <AccordionTrigger className="text-base font-semibold">
              Options de scan
            </AccordionTrigger>
            <AccordionContent className="space-y-6 pt-4">
              <SwitchRow
                id="networkDiscovery"
                label="Découverte automatique des réseaux"
                description="Active la phase nmap -sn pour trouver les hôtes sur les plages indiquées."
                checked={options.networkDiscovery}
                onCheckedChange={(checked) =>
                  setOptions((prev) => ({ ...prev, networkDiscovery: checked }))
                }
              />
              {!options.networkDiscovery && (
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    La découverte est désactivée : seules les machines listées dans « Hôtes individuels »
                    seront scannées.
                  </AlertDescription>
                </Alert>
              )}

              <div className="grid gap-4 md:grid-cols-2">
                <CheckboxRow
                  label="Recherche d’exploits (searchsploit)"
                  checked={options.searchExploits}
                  onCheckedChange={(checked) =>
                    setOptions((prev) => ({ ...prev, searchExploits: checked }))
                  }
                />
                <CheckboxRow
                  label="Enumérations Samba (enum4linux)"
                  checked={options.samba}
                  onCheckedChange={(checked) => setOptions((prev) => ({ ...prev, samba: checked }))}
                />
                <CheckboxRow
                  label="Fingerprinting web (whatweb)"
                  checked={options.whatweb}
                  onCheckedChange={(checked) =>
                    setOptions((prev) => ({ ...prev, whatweb: checked }))
                  }
                />
              </div>

              <div className="space-y-3">
                <SwitchRow
                  id="enable-topology"
                  label="Générer la topologie réseau"
                  description="Active la génération du JSON/HTML pour la carte réseau."
                  checked={options.enableTopology}
                  onCheckedChange={(checked) =>
                    setOptions((prev) => ({ ...prev, enableTopology: checked }))
                  }
                />
                <SwitchRow
                  id="topology-only"
                  label="Mode topologie uniquement"
                  description="Saute les scans détaillés et ne conserve que la découverte + topologie."
                  checked={options.topologyOnly}
                  onCheckedChange={(checked) =>
                    setOptions((prev) => ({ ...prev, topologyOnly: checked }))
                  }
                />
                <SwitchRow
                  id="log-commands"
                  label="Enregistrer les commandes Nmap"
                  description="Stocke toutes les commandes exécutées dans un fichier."
                  checked={options.logCommands}
                  onCheckedChange={(checked) =>
                    setOptions((prev) => ({ ...prev, logCommands: checked }))
                  }
                />
                <div className="space-y-2">
                  <Label htmlFor="commandLogFile">Nom du fichier de log</Label>
                  <Input
                    id="commandLogFile"
                    value={options.commandLogFile}
                    onChange={(event) =>
                      setOptions((prev) => ({ ...prev, commandLogFile: event.target.value }))
                    }
                    placeholder="nmap_commands.txt"
                  />
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          <AccordionItem value="performance">
            <AccordionTrigger className="text-base font-semibold">Performance</AccordionTrigger>
            <AccordionContent className="space-y-6 pt-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Profil de timing Nmap</Label>
                  <Select
                    value={performance.timing}
                    onValueChange={(value) =>
                      setPerformance((prev) => ({ ...prev, timing: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].map((timing) => (
                        <SelectItem key={timing} value={timing}>
                          {timing}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="maxThreads">Threads maximum</Label>
                  <Input
                    id="maxThreads"
                    type="number"
                    min={1}
                    max={100}
                    value={performance.maxThreads}
                    onChange={(event) =>
                      setPerformance((prev) => ({
                        ...prev,
                        maxThreads: Number(event.target.value),
                      }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="minRate">Taux minimum (paquets/s)</Label>
                  <Input
                    id="minRate"
                    type="number"
                    min={0}
                    value={performance.minRate}
                    onChange={(event) =>
                      setPerformance((prev) => ({
                        ...prev,
                        minRate: Number(event.target.value),
                      }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="hostTimeout">Timeout par hôte</Label>
                  <Input
                    id="hostTimeout"
                    value={performance.hostTimeout}
                    onChange={(event) =>
                      setPerformance((prev) => ({
                        ...prev,
                        hostTimeout: event.target.value,
                      }))
                    }
                    placeholder="30m"
                  />
                </div>
              </div>

              <SwitchRow
                id="scanAllPorts"
                label="Scanner tous les ports (1-65535)"
                description="Désactive les top ports et force un scan complet."
                checked={performance.scanAllPorts}
                onCheckedChange={(checked) =>
                  setPerformance((prev) => ({ ...prev, scanAllPorts: checked }))
                }
              />

              {!performance.scanAllPorts && (
                <div className="space-y-2">
                  <Label htmlFor="topPorts">Nombre de top ports</Label>
                  <Input
                    id="topPorts"
                    type="number"
                    min={100}
                    max={10000}
                    value={performance.topPorts}
                    onChange={(event) =>
                      setPerformance((prev) => ({
                        ...prev,
                        topPorts: Number(event.target.value),
                      }))
                    }
                  />
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        </Accordion>

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-muted-foreground">
            Les modifications sont écrites dans <code>Network/config.xml</code>.
          </p>
          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Enregistrer la configuration
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

type CheckboxRowProps = {
  label: string
  checked: boolean
  onCheckedChange: (checked: boolean) => void
}

function CheckboxRow({ label, checked, onCheckedChange }: CheckboxRowProps) {
  return (
    <label className="flex items-center space-x-2 rounded-md border px-3 py-2">
      <Checkbox
        checked={checked}
        onCheckedChange={(value) => onCheckedChange(Boolean(value))}
        className="mt-0.5"
      />
      <span className="text-sm text-foreground">{label}</span>
    </label>
  )
}

type SwitchRowProps = {
  id: string
  label: string
  description: string
  checked: boolean
  onCheckedChange: (checked: boolean) => void
}

function SwitchRow({ id, label, description, checked, onCheckedChange }: SwitchRowProps) {
  return (
    <div className="flex flex-col gap-1 border rounded-lg p-3">
      <div className="flex items-center justify-between">
        <Label htmlFor={id} className="font-medium">
          {label}
        </Label>
        <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
      </div>
      <p className="text-xs text-muted-foreground">{description}</p>
    </div>
  )
}
