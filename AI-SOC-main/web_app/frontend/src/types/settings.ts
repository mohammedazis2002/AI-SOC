export interface SiemConnectionRow {
  name: string
  /** `siem` = from `siem_source`; `agent` = fallback to endpoint hostname; `unknown` = neither. */
  sourceKind: 'siem' | 'agent' | 'unknown'
  status: 'active' | 'idle' | 'inactive'
  lastIngestAt: string | null
  alertsToday: number
  totalAlerts: number
}

export interface SiemConnectionsResponse {
  connections: SiemConnectionRow[]
}
