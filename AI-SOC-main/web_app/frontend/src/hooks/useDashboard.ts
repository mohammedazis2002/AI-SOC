import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { DashboardSummary } from '@/types/dashboard'

const REFETCH_MS = 30_000

export function useDashboardSummary(filters?: { days?: number }) {
  const days = filters?.days ?? 14

  return useQuery({
    queryKey: ['dashboard', 'summary', days],
    queryFn: async () => {
      const { data } = await api.get<DashboardSummary>('/dashboard/summary', {
        params: { days },
      })
      return data
    },
    refetchInterval: REFETCH_MS,
    staleTime: 15_000,
  })
}
