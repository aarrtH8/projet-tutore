import { memo } from 'react'
import { Handle, Position } from 'reactflow'
import { NetworkDevice } from '@/lib/network-data'
import { Server, Monitor, Shield, Network } from 'lucide-react'

interface NetworkDeviceNodeProps {
  data: {
    device: NetworkDevice
    onSelect: () => void
  }
}

export const NetworkDeviceNode = memo(({ data }: NetworkDeviceNodeProps) => {
  const { device, onSelect } = data

  const getIcon = () => {
    switch (device.type) {
      case 'server':
        return <Server className="h-6 w-6" />
      case 'workstation':
        return <Monitor className="h-6 w-6" />
      case 'firewall':
        return <Shield className="h-6 w-6" />
      case 'switch':
      case 'router':
        return <Network className="h-6 w-6" />
      case 'controller':
        return <Server className="h-6 w-6" />
      default:
        return <Server className="h-6 w-6" />
    }
  }

  const getSeverityColor = () => {
    switch (device.severity) {
      case 'critical':
        return 'border-critical bg-critical/10'
      case 'high':
        return 'border-high bg-high/10'
      case 'medium':
        return 'border-medium bg-medium/10'
      case 'low':
        return 'border-low bg-low/10'
      default:
        return 'border-border bg-card'
    }
  }

  const getSeverityIndicator = () => {
    switch (device.severity) {
      case 'critical':
        return 'bg-critical'
      case 'high':
        return 'bg-high'
      case 'medium':
        return 'bg-medium'
      case 'low':
        return 'bg-low'
      default:
        return 'bg-muted'
    }
  }

  return (
    <div
      onClick={onSelect}
      className={`relative px-4 py-3 rounded-lg border-2 min-w-[200px] cursor-pointer transition-all hover:shadow-lg ${getSeverityColor()}`}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2" />
      
      <div className="flex items-start gap-3">
        <div className="text-foreground">{getIcon()}</div>
        <div className="flex-1 min-w-0">
          <h3 className="font-semibold text-sm text-foreground truncate">{device.hostname}</h3>
          <p className="text-xs text-muted-foreground font-mono">{device.ip}</p>
          {device.vulnerabilityCount > 0 && (
            <div className="flex items-center gap-1 mt-1">
              <div className={`w-2 h-2 rounded-full ${getSeverityIndicator()}`} />
              <span className="text-xs font-medium">
                {device.vulnerabilityCount} vuln.
              </span>
            </div>
          )}
        </div>
      </div>
      
      <Handle type="source" position={Position.Bottom} className="w-2 h-2" />
    </div>
  )
})

NetworkDeviceNode.displayName = 'NetworkDeviceNode'
