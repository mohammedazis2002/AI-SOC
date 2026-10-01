import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AnalyticsSummary } from '@/types/analytics'

const REFETCH_MS = 60_000

export function useAnalyticsSummary(days: number) {
  return useQuery({
    queryKey: ['analytics', 'summary', days],
    queryFn: async () => {
      const { data } = await api.get<AnalyticsSummary>('/analytics/summary', {
        params: { days },
      })
      return data
    },
    refetchInterval: REFETCH_MS,
    staleTime: 30_000,
  })
}
