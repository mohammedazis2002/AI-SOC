export interface AlertListItem {
  id: string
  severity: string
  description: string
  source_siem: string
  source_ip: string
  dest_ip: string | null
  correlation_group: string | null
  confidence: number
  status: string
  mttd_minutes: number | null
  mttr_minutes: number | null
  timestamp: string
}

export interface AlertsListResponse {
  alerts: AlertListItem[]
  total: number
  page: number
  limit: number
}

export interface ProcessedAlertSummary {
  id: string
  severity: string
  severity_id?: number
  severity_label?: string
  status: string
  description: string
  display_source: string
  siem_source?: string
  timestamp?: string
  ingestion_timestamp?: string
  processed_at?: string
  processing_status?: string
  category_name?: string
  class_name?: string
  activity_name?: string
  source_alert_id?: string
}

export interface ProcessedAlertDetailResponse {
  summary: ProcessedAlertSummary
  endpoints: { src: Record<string, unknown> | null; dst: Record<string, unknown> | null }
  asset: Record<string, unknown> | null
  asset_risk: Record<string, unknown> | null
  finding: Record<string, unknown> | null
  file: Record<string, unknown> | null
  enrichments: Record<string, unknown> | null
  correlation: Record<string, unknown> | null
  metadata: Record<string, unknown> | null
  unmapped: Record<string, unknown> | null
  raw_data: string | null
  list_row: AlertListItem
  raw: Record<string, unknown>
}
