'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { useToast } from '@/hooks/use-toast'
import { Plus, Trash2, Upload, AlertCircle } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'

export function ConfigurationForm() {
  const { toast } = useToast()
  const [excludedRanges, setExcludedRanges] = useState<string[]>(['192.168.1.200-192.168.1.210'])
  const [weights, setWeights] = useState({
    networkSecurity: 30,
    systemHardening: 25,
    adSecurity: 25,
    networkConfig: 20,
  })

  const handleSave = () => {
    toast({
      title: 'Configuration enregistrée',
      description: 'Les paramètres ont été enregistrés avec succès',
    })
  }

  const handleTest = () => {
    toast({
      title: 'Test en cours',
      description: 'Vérification de la configuration...',
    })
    setTimeout(() => {
      toast({
        title: 'Test réussi',
        description: 'La configuration est valide',
      })
    }, 2000)
  }

  const addExcludedRange = () => {
    setExcludedRanges([...excludedRanges, ''])
  }

  const removeExcludedRange = (index: number) => {
    setExcludedRanges(excludedRanges.filter((_, i) => i !== index))
  }

  const totalWeight = Object.values(weights).reduce((sum, val) => sum + val, 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Paramètres de Configuration</CardTitle>
        <CardDescription>
          Configurer les paramètres d'audit et de scan
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Accordion type="multiple" defaultValue={['network']} className="w-full">
          {/* Network Parameters */}
          <AccordionItem value="network">
            <AccordionTrigger className="text-base font-semibold">
              Paramètres Réseau
            </AccordionTrigger>
            <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label htmlFor="ip-range">Plage IP à scanner</Label>
                <Input
                  id="ip-range"
                  placeholder="192.168.1.0/24"
                  defaultValue="192.168.1.0/24"
                />
                <p className="text-xs text-muted-foreground">
                  Format CIDR (ex: 192.168.1.0/24)
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Plages IP exclues</Label>
                  <Button variant="outline" size="sm" onClick={addExcludedRange}>
                    <Plus className="h-4 w-4 mr-2" />
                    Ajouter
                  </Button>
                </div>
                {excludedRanges.map((range, index) => (
                  <div key={index} className="flex gap-2">
                    <Input
                      value={range}
                      onChange={(e) => {
                        const newRanges = [...excludedRanges]
                        newRanges[index] = e.target.value
                        setExcludedRanges(newRanges)
                      }}
                      placeholder="192.168.1.200-192.168.1.210"
                    />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => removeExcludedRange(index)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>

              <div className="space-y-2">
                <Label htmlFor="dns">Serveurs DNS (optionnel)</Label>
                <Input id="dns" placeholder="8.8.8.8, 1.1.1.1" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="timeout">
                  Délai d'expiration réseau: <span className="font-mono">30s</span>
                </Label>
                <Slider defaultValue={[30]} max={60} step={1} />
              </div>
            </AccordionContent>
          </AccordionItem>

          {/* Audit Scheduling */}
          <AccordionItem value="schedule">
            <AccordionTrigger className="text-base font-semibold">
              Planification des Audits
            </AccordionTrigger>
            <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label htmlFor="frequency">Fréquence</Label>
                <Select defaultValue="weekly">
                  <SelectTrigger id="frequency">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Quotidien</SelectItem>
                    <SelectItem value="weekly">Hebdomadaire</SelectItem>
                    <SelectItem value="monthly">Mensuel</SelectItem>
                    <SelectItem value="quarterly">Trimestriel</SelectItem>
                    <SelectItem value="biannual">Semestriel</SelectItem>
                    <SelectItem value="annual">Annuel</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="day">Jour</Label>
                  <Select defaultValue="monday">
                    <SelectTrigger id="day">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="monday">Lundi</SelectItem>
                      <SelectItem value="tuesday">Mardi</SelectItem>
                      <SelectItem value="wednesday">Mercredi</SelectItem>
                      <SelectItem value="thursday">Jeudi</SelectItem>
                      <SelectItem value="friday">Vendredi</SelectItem>
                      <SelectItem value="saturday">Samedi</SelectItem>
                      <SelectItem value="sunday">Dimanche</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="time">Heure</Label>
                  <Input id="time" type="time" defaultValue="02:00" />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="timezone">Fuseau horaire</Label>
                <Select defaultValue="europe-paris">
                  <SelectTrigger id="timezone">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="europe-paris">Europe/Paris (UTC+1)</SelectItem>
                    <SelectItem value="utc">UTC</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2">
                <Switch id="auto-audit" defaultChecked />
                <Label htmlFor="auto-audit">Activer les audits automatiques</Label>
              </div>
            </AccordionContent>
          </AccordionItem>

          {/* Scan Options */}
          <AccordionItem value="scan">
            <AccordionTrigger className="text-base font-semibold">
              Options de Scan
            </AccordionTrigger>
            <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-3">
                <Label>Modules de scan</Label>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Checkbox id="network-discovery" defaultChecked />
                    <Label htmlFor="network-discovery" className="font-normal">
                      Découverte réseau
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="vuln-scan" defaultChecked />
                    <Label htmlFor="vuln-scan" className="font-normal">
                      Scan de vulnérabilités
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="linux-audit" defaultChecked />
                    <Label htmlFor="linux-audit" className="font-normal">
                      Audit Linux (Lynis)
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="windows-audit" defaultChecked />
                    <Label htmlFor="windows-audit" className="font-normal">
                      Audit Windows (PingCastle/BloodHound)
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="ad-scan" defaultChecked />
                    <Label htmlFor="ad-scan" className="font-normal">
                      Scan Active Directory
                    </Label>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="intensity">Intensité du scan</Label>
                <Select defaultValue="normal">
                  <SelectTrigger id="intensity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="light">Léger</SelectItem>
                    <SelectItem value="normal">Normal</SelectItem>
                    <SelectItem value="aggressive">Agressif</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="ports">Plage de ports</Label>
                <Select defaultValue="common">
                  <SelectTrigger id="ports">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="common">Ports communs (1000 ports)</SelectItem>
                    <SelectItem value="full">Scan complet (65535 ports)</SelectItem>
                    <SelectItem value="custom">Personnalisé</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-3">
                <Label>Outils de scan</Label>
                <div className="grid gap-2 md:grid-cols-2">
                  <div className="flex items-center space-x-2">
                    <Checkbox id="nmap" defaultChecked />
                    <Label htmlFor="nmap" className="font-normal font-mono text-sm">
                      nmap
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="enum4linux" defaultChecked />
                    <Label htmlFor="enum4linux" className="font-normal font-mono text-sm">
                      enum4linux
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="whatweb" defaultChecked />
                    <Label htmlFor="whatweb" className="font-normal font-mono text-sm">
                      whatweb
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox id="searchsploit" defaultChecked />
                    <Label htmlFor="searchsploit" className="font-normal font-mono text-sm">
                      searchsploit
                    </Label>
                  </div>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          {/* Credentials */}
          <AccordionItem value="credentials">
            <AccordionTrigger className="text-base font-semibold">
              Gestion des Identifiants
            </AccordionTrigger>
            <AccordionContent className="space-y-4 pt-4">
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Les identifiants sont stockés chiffrés localement uniquement. Ils ne sont jamais
                  transmis à des serveurs externes.
                </AlertDescription>
              </Alert>

              <div className="space-y-4 pt-2">
                <h4 className="font-medium text-foreground">Windows / Active Directory</h4>
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="domain">Domaine</Label>
                    <Input id="domain" placeholder="ENTREPRISE.LOCAL" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="ad-username">Nom d'utilisateur</Label>
                    <Input id="ad-username" placeholder="administrateur" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="ad-password">Mot de passe</Label>
                    <Input id="ad-password" type="password" />
                  </div>
                </div>
              </div>

              <div className="space-y-4 pt-4 border-t">
                <h4 className="font-medium text-foreground">Linux SSH</h4>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="ssh-username">Nom d'utilisateur</Label>
                    <Input id="ssh-username" placeholder="root" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="ssh-password">Mot de passe</Label>
                    <Input id="ssh-password" type="password" />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ssh-key">Ou clé privée SSH</Label>
                  <div className="flex gap-2">
                    <Input id="ssh-key" placeholder="Aucun fichier sélectionné" disabled />
                    <Button variant="outline">
                      <Upload className="h-4 w-4 mr-2" />
                      Upload
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">Format: PEM, max 10KB</p>
                </div>
              </div>

              <Button variant="secondary" className="w-full mt-4">
                Tester les identifiants
              </Button>
            </AccordionContent>
          </AccordionItem>

          {/* Report Settings */}
          <AccordionItem value="report">
            <AccordionTrigger className="text-base font-semibold">
              Paramètres de Rapport
            </AccordionTrigger>
            <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label htmlFor="company-name">Nom de l'entreprise</Label>
                <Input id="company-name" defaultValue="Exemple Entreprise SAS" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="logo">Logo de l'entreprise</Label>
                <div className="flex gap-2">
                  <Input id="logo" placeholder="Aucun fichier sélectionné" disabled />
                  <Button variant="outline">
                    <Upload className="h-4 w-4 mr-2" />
                    Upload
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Format: PNG ou JPG, max 2MB
                </p>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="contact-email">Email de contact</Label>
                  <Input id="contact-email" type="email" placeholder="contact@entreprise.fr" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contact-phone">Téléphone</Label>
                  <Input id="contact-phone" type="tel" placeholder="+33 1 23 45 67 89" />
                </div>
              </div>

              <div className="space-y-4 pt-4 border-t">
                <div className="flex items-center justify-between">
                  <Label>Pondération personnalisée</Label>
                  <span className={`text-sm font-medium ${totalWeight === 100 ? 'text-low' : 'text-critical'}`}>
                    Total: {totalWeight}%
                  </span>
                </div>
                
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label>Sécurité Réseau</Label>
                      <span className="text-sm font-medium">{weights.networkSecurity}%</span>
                    </div>
                    <Slider
                      value={[weights.networkSecurity]}
                      onValueChange={([value]) => setWeights({ ...weights, networkSecurity: value })}
                      max={100}
                      step={5}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label>Durcissement Système</Label>
                      <span className="text-sm font-medium">{weights.systemHardening}%</span>
                    </div>
                    <Slider
                      value={[weights.systemHardening]}
                      onValueChange={([value]) => setWeights({ ...weights, systemHardening: value })}
                      max={100}
                      step={5}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label>Sécurité AD</Label>
                      <span className="text-sm font-medium">{weights.adSecurity}%</span>
                    </div>
                    <Slider
                      value={[weights.adSecurity]}
                      onValueChange={([value]) => setWeights({ ...weights, adSecurity: value })}
                      max={100}
                      step={5}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label>Configuration Réseau</Label>
                      <span className="text-sm font-medium">{weights.networkConfig}%</span>
                    </div>
                    <Slider
                      value={[weights.networkConfig]}
                      onValueChange={([value]) => setWeights({ ...weights, networkConfig: value })}
                      max={100}
                      step={5}
                    />
                  </div>
                </div>

                {totalWeight !== 100 && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      La somme des pondérations doit être égale à 100%
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-3 mt-6 pt-6 border-t">
          <Button onClick={handleSave} className="flex-1 md:flex-none">
            Enregistrer la Configuration
          </Button>
          <Button variant="secondary" onClick={handleTest} className="flex-1 md:flex-none">
            Tester la Configuration
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
