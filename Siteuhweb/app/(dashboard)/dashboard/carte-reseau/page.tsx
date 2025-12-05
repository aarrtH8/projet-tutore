import { NetworkMap } from '@/components/network-map'
import { networkDevices, networkConnections } from '@/lib/network-data'

export default function CarteReseauPage() {
  return (
    <div className="p-4 lg:p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Carte Réseau</h1>
        <p className="text-muted-foreground mt-1">
          Topologie interactive du réseau avec indicateurs de sécurité
        </p>
      </div>

      <NetworkMap devices={networkDevices} connections={networkConnections} />
    </div>
  )
}
