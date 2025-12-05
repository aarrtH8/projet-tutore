export interface NetworkDevice {
  id: string
  hostname: string
  ip: string
  type: 'server' | 'workstation' | 'firewall' | 'switch' | 'router' | 'controller'
  os: string
  ports: string[]
  services: string[]
  vulnerabilityCount: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none'
}

export const networkDevices: NetworkDevice[] = [
  {
    id: 'firewall-01',
    hostname: 'firewall-01',
    ip: '192.168.1.1',
    type: 'firewall',
    os: 'pfSense 2.7.0',
    ports: ['80', '443', '22'],
    services: ['SSH', 'HTTPS Admin'],
    vulnerabilityCount: 1,
    severity: 'high',
  },
  {
    id: 'switch-core-01',
    hostname: 'switch-core-01',
    ip: '192.168.1.2',
    type: 'switch',
    os: 'Cisco IOS 15.2',
    ports: ['23', '22', '80'],
    services: ['Telnet', 'SSH', 'HTTP'],
    vulnerabilityCount: 1,
    severity: 'high',
  },
  {
    id: 'ad-controller-01',
    hostname: 'ad-controller-01',
    ip: '192.168.1.10',
    type: 'controller',
    os: 'Windows Server 2019',
    ports: ['88', '389', '636', '3389'],
    services: ['Kerberos', 'LDAP', 'LDAPS', 'RDP'],
    vulnerabilityCount: 1,
    severity: 'critical',
  },
  {
    id: 'serveur-web-01',
    hostname: 'serveur-web-01',
    ip: '192.168.1.50',
    type: 'server',
    os: 'Ubuntu 22.04',
    ports: ['80', '443', '22'],
    services: ['Apache 2.4.49', 'SSH'],
    vulnerabilityCount: 1,
    severity: 'critical',
  },
  {
    id: 'linux-server-03',
    hostname: 'linux-server-03',
    ip: '192.168.1.75',
    type: 'server',
    os: 'Debian 11',
    ports: ['22', '3306'],
    services: ['SSH', 'MySQL'],
    vulnerabilityCount: 1,
    severity: 'critical',
  },
  {
    id: 'workstation-01',
    hostname: 'workstation-01',
    ip: '192.168.1.100',
    type: 'workstation',
    os: 'Windows 11 Pro',
    ports: ['3389', '445'],
    services: ['RDP', 'SMB'],
    vulnerabilityCount: 2,
    severity: 'medium',
  },
  {
    id: 'workstation-02',
    hostname: 'workstation-02',
    ip: '192.168.1.101',
    type: 'workstation',
    os: 'Windows 11 Pro',
    ports: ['3389', '445'],
    services: ['RDP', 'SMB'],
    vulnerabilityCount: 1,
    severity: 'medium',
  },
  {
    id: 'workstation-03',
    hostname: 'workstation-03',
    ip: '192.168.1.102',
    type: 'workstation',
    os: 'Windows 10 Pro',
    ports: ['3389', '445'],
    services: ['RDP', 'SMB'],
    vulnerabilityCount: 0,
    severity: 'low',
  },
]

export const networkConnections = [
  { from: 'firewall-01', to: 'switch-core-01' },
  { from: 'switch-core-01', to: 'ad-controller-01' },
  { from: 'switch-core-01', to: 'serveur-web-01' },
  { from: 'switch-core-01', to: 'linux-server-03' },
  { from: 'switch-core-01', to: 'workstation-01' },
  { from: 'switch-core-01', to: 'workstation-02' },
  { from: 'switch-core-01', to: 'workstation-03' },
]
