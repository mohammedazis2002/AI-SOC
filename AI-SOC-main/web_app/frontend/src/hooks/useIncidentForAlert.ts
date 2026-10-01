import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { isAxiosError } from 'axios'

export function useIncidentForAlert(alertId: string | undefined) {
  return useQuery({
    queryKey: ['incidents', 'by-alert', alertId],
    queryFn: async (): Promise<Record<string, unknown> | null> => {
      if (!alertId) return null
      try {
        const { data } = await api.get<{ incident: Record<string, unknown> }>(
          `/incidents/by-alert/${encodeURIComponent(alertId)}`
        )
        return data.incident ?? null
      } catch (e) {
        if (isAxiosError(e) && e.response?.status === 404) {
          return null
        }
        throw e
      }
    },
    enabled: Boolean(alertId),
    staleTime: 30_000,
  })
}
