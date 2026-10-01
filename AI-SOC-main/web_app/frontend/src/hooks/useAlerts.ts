import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useAppStore } from '@/store/useAppStore'
import type { AlertsListResponse } from '@/types/alertApi'

export function buildAlertsSearchParams(filters: {
  page?: number
  limit?: number
  search?: string
  severity?: string[]
  source?: string[]
  status?: string[]
  dateRange?: string
}) {
  const sp = new URLSearchParams()
  sp.set('page', String(filters.page ?? 1))
  sp.set('limit', String(filters.limit ?? 50))
  if (filters.search?.trim()) sp.set('search', filters.search.trim())
  filters.severity?.forEach((s) => sp.append('severity', s))
  filters.status?.forEach((s) => sp.append('status', s))
  if (filters.source?.length) sp.set('source', filters.source[0])
  if (filters.dateRange) sp.set('date_range', filters.dateRange)
  return sp
}

export function useAlerts(filters?: {
  page?: number
  limit?: number
  severity?: string[]
  source?: string[]
  status?: string[]
  search?: string
  dateRange?: string
}) {
  const liveMode = useAppStore((s) => s.liveMode)

  return useQuery({
    queryKey: ['alerts', 'list', filters, liveMode],
    queryFn: async (): Promise<AlertsListResponse> => {
      const sp = buildAlertsSearchParams({
        page: filters?.page,
        limit: filters?.limit,
        search: filters?.search,
        severity: filters?.severity,
        source: filters?.source,
        status: filters?.status,
        dateRange: filters?.dateRange,
      })
      const { data } = await api.get<AlertsListResponse>(`/alerts?${sp.toString()}`)
      return data
    },
    refetchInterval: liveMode ? 20_000 : false,
    staleTime: liveMode ? 10_000 : 30_000,
  })
}
