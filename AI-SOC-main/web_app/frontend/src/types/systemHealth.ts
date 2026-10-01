export type SystemServiceStatus = 'healthy' | 'degraded' | 'down'

export interface SystemHealthDetail {
  label: string
  value: string
}

export interface SystemHealthService {
  id: string
  name: string
  status: SystemServiceStatus
  description: string
  instances: string | null
  latency: string | null
  lastCheck: string
  endpoint: string | null
  details: SystemHealthDetail[]
}

export interface SystemHealthSummary {
  totalServices: number
  healthyServices: number
  degradedServices: number
  downServices: number
  alertsStored: number
  processedLastHour: number
  dlqBacklog: number
  pendingApprovals: number
}

export interface SystemHealthQueueDepth {
  labels: string[]
  incoming: number[]
  priority: number[]
  dlq: number[]
}

export interface SystemHealthError {
  service: string
  error: string
  time: string
}

export interface SystemHealthResponse {
  generatedAt: string
  summary: SystemHealthSummary
  services: SystemHealthService[]
  queueDepth: SystemHealthQueueDepth
  recentErrors: SystemHealthError[]
}
