export interface AnalyticsVolumeDayRow {
  date: string
  dateIso: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
  total: number
}

export interface AnalyticsMttdMttrDayRow {
  date: string
  dateIso: string
  mttd: number | null
  mttr: number
}

export interface AnalyticsAutoManualDayRow {
  date: string
  dateIso: string
  auto: number
  manual: number
}

export interface AnalyticsFpDayRow {
  date: string
  dateIso: string
  fpRate: number
}

export interface AnalyticsOverrideDayRow {
  date: string
  dateIso: string
  rate: number | null
}

export interface AnalyticsConfidenceBucket {
  range: string
  count: number
}

export interface AnalyticsTopTypeRow {
  name: string
  count: number
}

export interface AnalyticsTopCountryRow {
  country: string
  count: number
}

export interface AnalyticsSummary {
  days: number
  collection: string
  volumeByDay: AnalyticsVolumeDayRow[]
  volumeSummary: { periodTotal: number; peakDay: number; avgPerDay: number }
  mttdMttrTrend: AnalyticsMttdMttrDayRow[]
  mttdTbd: boolean
  currentMttdAvgMinutes: number | null
  currentMttrAvgMinutes: number
  autoVsManual: AnalyticsAutoManualDayRow[]
  autoResolvePct: number
  fpRateByDay: AnalyticsFpDayRow[]
  currentFpRatePct: number
  overrideAvailable: boolean
  overrideRateByDay: AnalyticsOverrideDayRow[]
  confidenceDistribution: AnalyticsConfidenceBucket[]
  topAlertTypes: AnalyticsTopTypeRow[]
  topAlertTypesMax: number
  topCountries: AnalyticsTopCountryRow[]
  topCountriesMax: number
}
