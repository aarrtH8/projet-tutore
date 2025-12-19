export type SeverityLabel = 'Critique' | 'Haute' | 'Moyenne' | 'Basse'

export interface Vulnerability {
  id: string
  severity: SeverityLabel
  category: string
  cve: string
  affectedSystem: string
  cvssScore: number
  description: string
  remediation: string
}

export interface RemediationTask {
  id: string
  name: string
  severity: SeverityLabel
  workload: number // percentage of 35h week
  duration: number // in half-days (0.5 = 3h30, 1 = 7h)
  category: string
  dueDate?: string
}

export interface AuditData {
  id: string
  date: string
  companyName: string
  overallScore: number
  categoryScores: {
    networkSecurity: number
    systemHardening: number
    adSecurity: number
    networkConfig: number
  }
  stats: {
    totalVulnerabilities: number
    critical: number
    high: number
    medium: number
    low: number
    remediationProgress: number
  }
  vulnerabilities: Vulnerability[]
  remediationTasks: RemediationTask[]
  trend?: 'up' | 'down' | 'stable'
}

export interface AuditHistory {
  audits: AuditData[]
}

export interface ScorePoint {
  date: string
  score: number
}

export type DeviceType =
  | 'server'
  | 'workstation'
  | 'firewall'
  | 'switch'
  | 'router'
  | 'controller'
  | 'scanner'

export interface NetworkDevice {
  id: string
  hostname: string
  ip: string
  type: DeviceType
  os: string
  ports: string[]
  services: string[]
  vulnerabilityCount: number
  severity: 'critical' | 'high' | 'medium' | 'low'
}

export interface NetworkConnection {
  from: string
  to: string
}
