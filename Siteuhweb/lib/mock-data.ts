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

export interface Vulnerability {
  id: string
  severity: 'Critique' | 'Haute' | 'Moyenne' | 'Basse'
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
  severity: 'Critique' | 'Haute' | 'Moyenne' | 'Basse'
  workload: number // percentage of 35h week
  duration: number // in half-days (0.5 = 3h30, 1 = 7h)
  category: string
  dueDate?: string
}

export interface AuditHistory {
  audits: AuditData[]
}

export const currentAudit: AuditData = {
  id: 'audit_2025_11_14',
  date: '2025-11-14T09:30:00Z',
  companyName: 'Exemple Entreprise SAS',
  overallScore: 68,
  categoryScores: {
    networkSecurity: 65,
    systemHardening: 72,
    adSecurity: 60,
    networkConfig: 75,
  },
  stats: {
    totalVulnerabilities: 47,
    critical: 3,
    high: 12,
    medium: 18,
    low: 14,
    remediationProgress: 35,
  },
  vulnerabilities: [
    {
      id: 'vuln-1',
      severity: 'Critique',
      category: 'Sécurité Réseau',
      cve: 'CVE-2024-1234',
      affectedSystem: 'serveur-web-01 (192.168.1.50)',
      cvssScore: 9.8,
      description: 'Exécution de code à distance dans Apache HTTP Server',
      remediation: 'Mettre à jour Apache vers la version 2.4.51 ou supérieure',
    },
    {
      id: 'vuln-2',
      severity: 'Critique',
      category: 'Sécurité AD',
      cve: 'CVE-2024-5678',
      affectedSystem: 'ad-controller-01 (192.168.1.10)',
      cvssScore: 9.1,
      description: 'Élévation de privilèges dans Active Directory',
      remediation: 'Appliquer le correctif de sécurité Microsoft KB5012345',
    },
    {
      id: 'vuln-3',
      severity: 'Critique',
      category: 'Durcissement Système',
      cve: 'CVE-2024-9012',
      affectedSystem: 'linux-server-03 (192.168.1.75)',
      cvssScore: 8.8,
      description: 'Vulnérabilité dans le kernel Linux permettant l\'escalade de privilèges',
      remediation: 'Mettre à jour le kernel vers la version 5.15.0-91',
    },
    {
      id: 'vuln-4',
      severity: 'Haute',
      category: 'Sécurité Réseau',
      cve: 'CVE-2024-3456',
      affectedSystem: 'firewall-01 (192.168.1.1)',
      cvssScore: 7.5,
      description: 'Contournement de règles de pare-feu',
      remediation: 'Mettre à jour le firmware du pare-feu',
    },
    {
      id: 'vuln-5',
      severity: 'Haute',
      category: 'Configuration Réseau',
      cve: 'N/A',
      affectedSystem: 'switch-core-01 (192.168.1.2)',
      cvssScore: 7.2,
      description: 'Protocole Telnet activé sur le switch principal',
      remediation: 'Désactiver Telnet et utiliser SSH uniquement',
    },
  ],
  remediationTasks: [
    {
      id: 'task-1',
      name: 'Corriger CVE-2024-1234 (Apache)',
      severity: 'Critique',
      workload: 50,
      duration: 1,
      category: 'Sécurité Réseau',
      dueDate: '2025-11-15',
    },
    {
      id: 'task-2',
      name: 'Corriger CVE-2024-5678 (AD)',
      severity: 'Critique',
      workload: 60,
      duration: 1.5,
      category: 'Sécurité AD',
      dueDate: '2025-11-16',
    },
    {
      id: 'task-3',
      name: 'Mettre à jour kernel Linux',
      severity: 'Critique',
      workload: 40,
      duration: 0.5,
      category: 'Durcissement Système',
      dueDate: '2025-11-17',
    },
  ],
}

export const auditHistory: AuditHistory = {
  audits: [
    { ...currentAudit, trend: 'up' },
    {
      id: 'audit_2025_11_07',
      date: '2025-11-07T09:30:00Z',
      companyName: 'Exemple Entreprise SAS',
      overallScore: 62,
      categoryScores: {
        networkSecurity: 58,
        systemHardening: 68,
        adSecurity: 55,
        networkConfig: 72,
      },
      stats: {
        totalVulnerabilities: 53,
        critical: 5,
        high: 15,
        medium: 20,
        low: 13,
        remediationProgress: 25,
      },
      vulnerabilities: [],
      remediationTasks: [],
      trend: 'stable',
    },
    {
      id: 'audit_2025_10_31',
      date: '2025-10-31T09:30:00Z',
      companyName: 'Exemple Entreprise SAS',
      overallScore: 61,
      categoryScores: {
        networkSecurity: 55,
        systemHardening: 65,
        adSecurity: 58,
        networkConfig: 70,
      },
      stats: {
        totalVulnerabilities: 58,
        critical: 7,
        high: 16,
        medium: 22,
        low: 13,
        remediationProgress: 20,
      },
      vulnerabilities: [],
      remediationTasks: [],
      trend: 'down',
    },
  ],
}

// Score evolution data for charts
export const scoreEvolution = [
  { date: '2025-09-15', score: 52 },
  { date: '2025-09-22', score: 55 },
  { date: '2025-09-29', score: 58 },
  { date: '2025-10-06', score: 54 },
  { date: '2025-10-13', score: 57 },
  { date: '2025-10-20', score: 59 },
  { date: '2025-10-27', score: 61 },
  { date: '2025-11-03', score: 62 },
  { date: '2025-11-10', score: 68 },
]
