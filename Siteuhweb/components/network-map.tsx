'use client'

import { useCallback, useState } from 'react'
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Panel,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { NetworkDevice } from '@/lib/network-data'
import { Button } from '@/components/ui/button'
import { Download, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { NetworkDeviceNode } from '@/components/network-device-node'

interface NetworkMapProps {
  devices: NetworkDevice[]
  connections: Array<{ from: string; to: string }>
}

const nodeTypes = {
  device: NetworkDeviceNode,
}

export function NetworkMap({ devices, connections }: NetworkMapProps) {
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null)

  // Convert devices to nodes
  const initialNodes: Node[] = devices.map((device, index) => {
    const cols = 3
    const row = Math.floor(index / cols)
    const col = index % cols
    
    return {
      id: device.id,
      type: 'device',
      position: { x: col * 300 + 50, y: row * 200 + 50 },
      data: { device, onSelect: () => setSelectedDevice(device) },
    }
  })

  // Convert connections to edges
  const initialEdges: Edge[] = connections.map((conn, index) => ({
    id: `edge-${index}`,
    source: conn.from,
    target: conn.to,
    type: 'smoothstep',
    animated: false,
    style: { stroke: 'hsl(var(--border))', strokeWidth: 2 },
  }))

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  const exportAsPNG = useCallback(() => {
    // In a real implementation, this would use html-to-image or similar
    alert('Export PNG fonctionnalité à implémenter avec html-to-image')
  }, [])

  const exportAsSVG = useCallback(() => {
    alert('Export SVG fonctionnalité à implémenter')
  }, [])

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card className="h-[700px]">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Topologie du Réseau</CardTitle>
                <CardDescription>{devices.length} appareils détectés</CardDescription>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={exportAsPNG}>
                  <Download className="h-4 w-4 mr-2" />
                  PNG
                </Button>
                <Button variant="outline" size="sm" onClick={exportAsSVG}>
                  <Download className="h-4 w-4 mr-2" />
                  SVG
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="h-[calc(100%-100px)] p-0">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={nodeTypes}
              fitView
              minZoom={0.5}
              maxZoom={1.5}
            >
              <Background />
              <Controls />
              <MiniMap
                nodeColor={(node) => {
                  const device = devices.find((d) => d.id === node.id)
                  if (!device) return '#94a3b8'
                  if (device.severity === 'critical') return '#DC2626'
                  if (device.severity === 'high') return '#F59E0B'
                  if (device.severity === 'medium') return '#FBBF24'
                  return '#10B981'
                }}
                className="bg-card border border-border"
              />
            </ReactFlow>
          </CardContent>
        </Card>
      </div>

      <div className="lg:col-span-1">
        {selectedDevice ? (
          <Card>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle>{selectedDevice.hostname}</CardTitle>
                  <CardDescription>{selectedDevice.ip}</CardDescription>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setSelectedDevice(null)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">Type</h4>
                <Badge variant="secondary" className="capitalize">
                  {selectedDevice.type}
                </Badge>
              </div>

              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">
                  Système d'exploitation
                </h4>
                <p className="text-sm">{selectedDevice.os}</p>
              </div>

              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">Ports ouverts</h4>
                <div className="flex flex-wrap gap-1">
                  {selectedDevice.ports.map((port) => (
                    <Badge key={port} variant="outline" className="font-mono text-xs">
                      {port}
                    </Badge>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">Services</h4>
                <ul className="text-sm space-y-1">
                  {selectedDevice.services.map((service, index) => (
                    <li key={index} className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                      {service}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">
                  Vulnérabilités
                </h4>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{selectedDevice.vulnerabilityCount}</span>
                  <Badge
                    className={
                      selectedDevice.severity === 'critical'
                        ? 'bg-critical text-white'
                        : selectedDevice.severity === 'high'
                        ? 'bg-high text-white'
                        : selectedDevice.severity === 'medium'
                        ? 'bg-medium text-foreground'
                        : 'bg-low text-white'
                    }
                  >
                    {selectedDevice.severity === 'critical'
                      ? 'Critique'
                      : selectedDevice.severity === 'high'
                      ? 'Haute'
                      : selectedDevice.severity === 'medium'
                      ? 'Moyenne'
                      : 'Basse'}
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Détails de l'Appareil</CardTitle>
              <CardDescription>Cliquez sur un appareil pour voir les détails</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mb-4">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="32"
                    height="32"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="text-muted-foreground"
                  >
                    <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
                    <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
                    <line x1="6" x2="6.01" y1="6" y2="6" />
                    <line x1="6" x2="6.01" y1="18" y2="18" />
                  </svg>
                </div>
                <p className="text-sm text-muted-foreground">
                  Sélectionnez un appareil sur la carte pour afficher ses informations
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Legend */}
        <Card className="mt-6">
          <CardHeader>
            <CardTitle className="text-base">Légende</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-critical" />
              <span className="text-sm">Critique</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-high" />
              <span className="text-sm">Haute</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-medium" />
              <span className="text-sm">Moyenne</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-low" />
              <span className="text-sm">Basse / Aucune</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
