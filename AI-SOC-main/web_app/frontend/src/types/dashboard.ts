export interface AlertVolumeDayRow {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface AlertSourceSlice {
  name: string
  value: number
  count: number
}

export interface DashboardRecentAlert {
  id: string
  description: string
  severity: string
  status: string
  timestamp: string
}

export interface DashboardSummary {
  totalAlerts: number
  totalDelta: number
  criticalCount?: number
  highCount?: number
  criticalHigh: number
  criticalHighDelta: number
  autoResolved: number
  autoResolvedPct: number
  autoResolvedDelta: number
  pendingReview: number
  slaAtRisk: boolean
  /** When true, dashboard shows MTTD as TBD (no aggregate yet). */
  mttdTbd?: boolean
  mttdAvgMinutes: number | null
  mttdDelta: number | null
  mttrAvgMinutes: number
  mttrDelta: number
  /** Alerts used for MTTR average in the selected window (resolved + timestamps). */
  mttrSampleCount?: number
  mttdSparkline: number[]
  mttrSparkline: number[]
  alertVolumeByDay: AlertVolumeDayRow[]
  alertsBySource: AlertSourceSlice[]
  recentAutomatedActions: Array<{
    type: string
    alertId: string
    confidence: number
    timestamp: string
  }>
  recentAlerts?: DashboardRecentAlert[]
}
