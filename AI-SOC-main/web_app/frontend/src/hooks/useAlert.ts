import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { api } from '@/lib/api'
import type { AlertListItem, ProcessedAlertDetailResponse } from '@/types/alertApi'

export function useAlert(id: string | undefined) {
  return useQuery({
    queryKey: ['alerts', 'detail', id],
    queryFn: async (): Promise<ProcessedAlertDetailResponse | null> => {
      if (!id) return null
      try {
        const { data } = await api.get<ProcessedAlertDetailResponse>(`/alerts/${encodeURIComponent(id)}`)
        return data
      } catch (e) {
        if (isAxiosError(e) && e.response?.status === 404) return null
        throw e
      }
    },
    enabled: !!id,
    staleTime: 15_000,
  })
}

export function useSimilarAlerts(id: string | undefined) {
  return useQuery({
    queryKey: ['alerts', 'similar', id],
    queryFn: async (): Promise<AlertListItem[]> => {
      if (!id) return []
      try {
        const { data } = await api.get<{ alerts: AlertListItem[] }>(
          `/alerts/${encodeURIComponent(id)}/similar`
        )
        return data.alerts ?? []
      } catch {
        return []
      }
    },
    enabled: !!id,
    staleTime: 30_000,
  })
}
