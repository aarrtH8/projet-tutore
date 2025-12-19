import fs from 'fs'
import { promises as fsp } from 'fs'
import path from 'path'
import { XMLBuilder, XMLParser } from 'fast-xml-parser'

export type AuditConfig = {
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

const repoRoot = path.resolve(process.cwd(), '..')
const configPath = path.join(repoRoot, 'Network', 'config.xml')

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
})

const builder = new XMLBuilder({
  ignoreAttributes: false,
  format: true,
  indentBy: '    ',
  suppressEmptyNode: true,
})

const defaultConfig: AuditConfig = {
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

type XmlConfig = {
  config?: {
    networks?: { network?: string | string[] }
    hosts?: { host?: string | string[] }
    exclude?: { entry?: string | string[] }
    options?: Record<string, string | number | boolean>
    performance?: Record<string, string | number | boolean>
  }
}

function toArray(value: string | string[] | undefined): string[] {
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

function toBool(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true' || value === '1'
  }
  if (typeof value === 'number') {
    return value !== 0
  }
  return fallback
}

function toNumber(value: unknown, fallback: number): number {
  const num = Number(value)
  return Number.isFinite(num) && num > 0 ? num : fallback
}

async function readXmlFile(): Promise<XmlConfig | null> {
  if (!fs.existsSync(configPath)) {
    return null
  }
  try {
    const xml = await fsp.readFile(configPath, 'utf-8')
    return parser.parse(xml) as XmlConfig
  } catch {
    return null
  }
}

export async function getAuditConfig(): Promise<AuditConfig> {
  const xmlConfig = await readXmlFile()
  if (!xmlConfig?.config) {
    return defaultConfig
  }

  const options = xmlConfig.config.options ?? {}
  const performance = xmlConfig.config.performance ?? {}

  return {
    networks: normalizeList(toArray(xmlConfig.config.networks?.network), defaultConfig.networks),
    hosts: normalizeList(toArray(xmlConfig.config.hosts?.host), []),
    exclude: normalizeList(toArray(xmlConfig.config.exclude?.entry), []),
    options: {
      networkDiscovery: toBool(options.network_discovery, defaultConfig.options.networkDiscovery),
      searchExploits: toBool(options.search_exploits, defaultConfig.options.searchExploits),
      samba: toBool(options.samba, defaultConfig.options.samba),
      whatweb: toBool(options.whatweb, defaultConfig.options.whatweb),
      enableTopology: toBool(options.enable_topology, defaultConfig.options.enableTopology),
      topologyOnly: toBool(options.topology_only, defaultConfig.options.topologyOnly),
      logCommands: toBool(options.log_commands, defaultConfig.options.logCommands),
      commandLogFile:
        typeof options.command_log_file === 'string'
          ? options.command_log_file
          : defaultConfig.options.commandLogFile,
    },
    performance: {
      timing: typeof performance.timing === 'string' ? performance.timing : defaultConfig.performance.timing,
      maxThreads: toNumber(performance.max_threads, defaultConfig.performance.maxThreads),
      scanAllPorts: toBool(performance.scan_all_ports, defaultConfig.performance.scanAllPorts),
      topPorts: toNumber(performance.top_ports, defaultConfig.performance.topPorts),
      minRate: toNumber(performance.min_rate, defaultConfig.performance.minRate),
      hostTimeout:
        typeof performance.host_timeout === 'string'
          ? performance.host_timeout
          : defaultConfig.performance.hostTimeout,
    },
  }
}

type AuditConfigInput = Partial<AuditConfig> & {
  networks?: string[]
  hosts?: string[]
  exclude?: string[]
}

function normalizeList(entries: string[], fallback: string[]): string[] {
  const sanitized = entries.map((entry) => entry.trim()).filter((entry) => entry.length > 0)
  return sanitized.length ? sanitized : fallback
}

function sanitizeInputList(entries: string[] | undefined, fallback: string[]): string[] {
  if (!entries) {
    return fallback
  }
  return entries.map((entry) => entry.trim()).filter((entry) => entry.length > 0)
}

export async function saveAuditConfig(input: AuditConfigInput): Promise<AuditConfig> {
  const current = await getAuditConfig()
  const merged: AuditConfig = {
    networks: sanitizeInputList(input.networks, current.networks),
    hosts: sanitizeInputList(input.hosts, current.hosts),
    exclude: sanitizeInputList(input.exclude, current.exclude),
    options: {
      networkDiscovery: input.options?.networkDiscovery ?? current.options.networkDiscovery,
      searchExploits: input.options?.searchExploits ?? current.options.searchExploits,
      samba: input.options?.samba ?? current.options.samba,
      whatweb: input.options?.whatweb ?? current.options.whatweb,
      enableTopology: input.options?.enableTopology ?? current.options.enableTopology,
      topologyOnly: input.options?.topologyOnly ?? current.options.topologyOnly,
      logCommands: input.options?.logCommands ?? current.options.logCommands,
      commandLogFile: input.options?.commandLogFile?.trim() || current.options.commandLogFile,
    },
    performance: {
      timing: input.performance?.timing ?? current.performance.timing,
      maxThreads: input.performance?.maxThreads ?? current.performance.maxThreads,
      scanAllPorts: input.performance?.scanAllPorts ?? current.performance.scanAllPorts,
      topPorts: input.performance?.topPorts ?? current.performance.topPorts,
      minRate: input.performance?.minRate ?? current.performance.minRate,
      hostTimeout: input.performance?.hostTimeout?.trim() || current.performance.hostTimeout,
    },
  }

  if (merged.options.networkDiscovery && !merged.networks.length) {
    throw new Error('Active la découverte réseau ou indique au moins une plage CIDR.')
  }

  const xmlPayload = {
    config: {
      networks: { network: merged.networks },
      hosts: merged.hosts.length ? { host: merged.hosts } : undefined,
      exclude: merged.exclude.length ? { entry: merged.exclude } : undefined,
      options: {
        network_discovery: toXmlBool(merged.options.networkDiscovery),
        search_exploits: toXmlBool(merged.options.searchExploits),
        samba: toXmlBool(merged.options.samba),
        whatweb: toXmlBool(merged.options.whatweb),
        enable_topology: toXmlBool(merged.options.enableTopology),
        topology_only: toXmlBool(merged.options.topologyOnly),
        log_commands: toXmlBool(merged.options.logCommands),
        command_log_file: merged.options.commandLogFile,
      },
      performance: {
        timing: merged.performance.timing,
        max_threads: merged.performance.maxThreads.toString(),
        scan_all_ports: toXmlBool(merged.performance.scanAllPorts),
        top_ports: merged.performance.topPorts.toString(),
        min_rate: merged.performance.minRate.toString(),
        host_timeout: merged.performance.hostTimeout,
      },
    },
  }

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n${builder.build(xmlPayload)}`
  await fsp.writeFile(configPath, xml, 'utf-8')
  return merged
}

function toXmlBool(value: boolean): string {
  return value ? 'true' : 'false'
}
