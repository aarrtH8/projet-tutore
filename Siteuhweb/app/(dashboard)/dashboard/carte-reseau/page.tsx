import { NetworkMap } from '@/components/network-map'
import {
  getNetworkDevices,
  getNetworkConnections,
  getNetworkMapHtml,
} from '@/lib/scan-data'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export default function CarteReseauPage() {
  const devices = getNetworkDevices()
  const connections = getNetworkConnections()
  const networkMapHtml = getNetworkMapHtml()

  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Carte Réseau</h1>
        <p className="text-muted-foreground mt-1">
          Topologie interactive du réseau avec indicateurs de sécurité
        </p>
      </div>

      <NetworkMap devices={devices} connections={connections} />

      {networkMapHtml && (
        <Card>
          <CardHeader>
            <CardTitle>Carte générée par le scanner</CardTitle>
            <CardDescription>
              Visualisation HTML issue du script d&apos;inventaire (vis.js)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="w-full h-[600px] border border-border rounded-lg overflow-hidden bg-muted">
              <iframe
                title="Carte réseau générée"
                srcDoc={networkMapHtml}
                className="w-full h-full border-0 bg-card text-foreground"
                sandbox="allow-same-origin allow-scripts"
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
