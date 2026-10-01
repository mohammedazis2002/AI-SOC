export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type AlertStatus = 'new' | 'in_review' | 'resolved' | 'false_positive' | 'escalated'
export type SourceSiem = 'Wazuh' | 'SentinelOne' | 'Splunk' | 'SumoLogic'

export interface Enrichment {
  ip_reputation: 'malicious' | 'suspicious' | 'clean'
  geoip: { country: string; city: string; flag: string }
  vt_score: number
  otx_indicator: string
  asset: { hostname: string; owner: string; criticality: string }
}

export interface MLScores {
  severity: number
  anomaly: number
  false_positive: number
  root_cause: string
}

export interface LLMReasoning {
  classification: string
  root_cause: string
  justification: string
  recommended_action: string
  verification: 'approved' | 'pending' | 'rejected'
}

export interface Alert {
  id: string
  severity: Severity
  description: string
  source_siem: SourceSiem
  source_ip: string
  dest_ip?: string
  correlation_group?: string
  confidence: number
  status: AlertStatus
  /** Mean time to detect — minutes from first event to alert creation */
  mttd_minutes: number
  /** Mean time to respond/resolve — minutes from alert to resolution; null if not yet closed */
  mttr_minutes: number | null
  timestamp: string
  enrichment?: Enrichment
  ml_scores?: MLScores
  llm_reasoning?: LLMReasoning
  executed_action?: { action: string; at: string; confidence: number } | null
  raw_payload?: Record<string, unknown>
}

const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const statuses: AlertStatus[] = ['new', 'in_review', 'resolved', 'false_positive', 'escalated']
const sources: SourceSiem[] = ['Wazuh', 'SentinelOne', 'Splunk', 'SumoLogic']
const descriptions = [
  'SSH brute-force attack detected on port 22',
  'Suspicious PowerShell execution',
  'Lateral movement detected from DC',
  'Malware signature match - Emotet',
  'Unusual outbound RDP from workstation',
  'Failed MFA attempts - possible credential stuffing',
  'Data exfiltration via DNS tunnel',
  'Privilege escalation attempt',
  'New scheduled task on critical server',
  'Anomalous login from new geography',
  'C2 beacon detected',
  'Ransomware file activity',
  'Suspicious registry modification',
  'Port scan from internal host',
  'Disabled Windows Defender',
  'Suspicious child process',
  'Kerberoasting indicators',
  'Mimikatz-like memory access',
  'Unusual service installation',
  'High volume of failed logins',
]

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomPastDate(daysBack: number): string {
  const d = new Date()
  d.setDate(d.getDate() - Math.floor(Math.random() * daysBack))
  d.setMinutes(d.getMinutes() - Math.floor(Math.random() * 60))
  return d.toISOString()
}

export const mockAlerts: Alert[] = Array.from({ length: 24 }, (_, i) => {
  const id = `A-${982300 + i}`
  const severity = i < 3 ? 'CRITICAL' : i < 8 ? 'HIGH' : randomChoice(severities)
  const status = i < 5 ? 'new' : i < 8 ? 'in_review' : randomChoice(statuses)
  const mttd_minutes = 2 + Math.floor(Math.random() * 14)
  const closed = status === 'resolved' || status === 'false_positive'
  const mttr_minutes = closed
    ? 8 + Math.floor(Math.random() * 40)
    : status === 'new' || status === 'in_review'
      ? null
      : 12 + Math.floor(Math.random() * 30)
  return {
    id,
    severity,
    description: descriptions[i % descriptions.length],
    source_siem: randomChoice(sources),
    source_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    dest_ip: `10.0.0.${Math.floor(Math.random() * 20)}`,
    correlation_group: i % 4 === 0 ? `CG-${100 + i}` : undefined,
    confidence: 0.7 + Math.random() * 0.25,
    status,
    mttd_minutes,
    mttr_minutes,
    timestamp: randomPastDate(2),
    enrichment: {
      ip_reputation: randomChoice(['malicious', 'suspicious', 'clean']),
      geoip: { country: 'Russia', city: 'Moscow', flag: '🇷🇺' },
      vt_score: Math.floor(Math.random() * 10),
      otx_indicator: 'Brute Force - SSH',
      asset: { hostname: 'web-prod-01', owner: 'Infra Team', criticality: 'high' },
    },
    ml_scores: {
      severity: 0.7 + Math.random() * 0.25,
      anomaly: 0.6 + Math.random() * 0.35,
      false_positive: Math.random() * 0.2,
      root_cause: 'Credential Attack',
    },
    llm_reasoning: {
      classification: 'Brute-force Attack',
      root_cause: 'Repeated failed SSH login attempts from a known malicious IP in Russia.',
      justification: 'Matches MITRE T1110. VirusTotal confirms malicious IP.',
      recommended_action: 'block_ip',
      verification: i % 3 === 0 ? 'approved' : 'pending',
    },
    executed_action: i === 2 ? { action: 'block_ip', at: new Date().toISOString(), confidence: 0.87 } : null,
    raw_payload: { rule_id: 5763, category: 'Authentication' },
  }
})

export const mockDashboardSummary = {
  totalAlerts: 1284,
  totalDelta: 0.12,
  criticalHigh: 47,
  criticalHighDelta: 5,
  autoResolved: 891,
  autoResolvedPct: 69,
  autoResolvedDelta: -0.02,
  pendingReview: 3,
  slaAtRisk: true,
  mttdTbd: true,
  mttdAvgMinutes: null,
  mttdDelta: null,
  mttdSparkline: [],
  mttrAvgMinutes: 18,
  mttrDelta: -0.05,
  mttrSampleCount: 42,
  mttrSparkline: [20, 18, 19, 18, 17, 16, 18],
  alertVolumeByDay: [
    { date: 'Mon', critical: 12, high: 45, medium: 89, low: 120, info: 34 },
    { date: 'Tue', critical: 8, high: 52, medium: 95, low: 110, info: 28 },
    { date: 'Wed', critical: 15, high: 48, medium: 102, low: 115, info: 40 },
    { date: 'Thu', critical: 10, high: 55, medium: 88, low: 125, info: 35 },
    { date: 'Fri', critical: 18, high: 62, medium: 98, low: 130, info: 42 },
    { date: 'Sat', critical: 5, high: 30, medium: 70, low: 95, info: 25 },
    { date: 'Sun', critical: 7, high: 38, medium: 75, low: 100, info: 30 },
  ],
  alertsBySource: [
    { name: 'Wazuh', value: 520, count: 520 },
    { name: 'SentinelOne', value: 312, count: 312 },
    { name: 'Splunk', value: 280, count: 280 },
    { name: 'SumoLogic', value: 172, count: 172 },
  ],
  recentAutomatedActions: [
    { type: 'block_ip', alertId: 'A-982372', confidence: 0.87, timestamp: new Date(Date.now() - 120000).toISOString() },
    { type: 'isolate_host', alertId: 'A-982371', confidence: 0.92, timestamp: new Date(Date.now() - 300000).toISOString() },
    { type: 'create_ticket', alertId: 'A-982370', confidence: 0.78, timestamp: new Date(Date.now() - 600000).toISOString() },
    { type: 'escalate', alertId: 'A-982369', confidence: 0.95, timestamp: new Date(Date.now() - 900000).toISOString() },
  ],
}

export const mockSystemHealth = {
  services: [
    { id: 'ingestion', name: 'Ingestion Svc', status: 'healthy', instances: '3/3', latency: '12ms', lastCheck: '30s ago', sparkline: [10, 12, 11, 14, 12, 13, 12] },
    { id: 'redis', name: 'Redis Streams', status: 'healthy', instances: '—', latency: '—', lastCheck: '15s ago', queueDepth: 247, consumerLag: 0 },
    { id: 'ai', name: 'AI Analysis Engine', status: 'healthy', instances: '2/2', latency: '450ms', lastCheck: '45s ago', sparkline: [400, 420, 450, 440, 460] },
    { id: 'enrichment', name: 'Enrichment Engine', status: 'healthy', instances: '—', lastCheck: '20s ago', vtQuota: 9500, otxQuota: 9800 },
    { id: 'executor', name: 'Response Executor', status: 'healthy', instances: '2/2', latency: '80ms', lastCheck: '25s ago' },
    { id: 'mongo', name: 'MongoDB', status: 'healthy', instances: '—', lastCheck: '10s ago', alertsStored: 284000 },
    { id: 'llm', name: 'LLM Inference', status: 'healthy', model: 'Mistral-7B', tokensPerSec: 42, vramUsed: 12, vramTotal: 24 },
    { id: 'vector', name: 'Vector DB', status: 'healthy', instances: '1/1', lastCheck: '5s ago' },
  ],
  queueDepth: {
    incoming: [100, 120, 115, 130, 125, 140, 135],
    priority: [50, 55, 52, 58, 60, 55, 52],
    dlq: [0, 0, 0, 0, 0, 0, 0],
  },
  recentErrors: [
    { service: 'Enrichment Engine', error: 'VirusTotal API rate limit hit', time: '3 min ago' },
    { service: 'AI Analysis Engine', error: 'LLM timeout after 30s', time: '17 min ago' },
  ],
}
