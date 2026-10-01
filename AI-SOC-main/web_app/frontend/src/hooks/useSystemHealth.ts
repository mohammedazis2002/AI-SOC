import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { SystemHealthResponse } from '@/types/systemHealth'

async function fetchSystemHealth(): Promise<SystemHealthResponse> {
  const { data } = await api.get<SystemHealthResponse>('/system/health')
  return data
}

export function useSystemHealth() {
  return useQuery({
    queryKey: ['system', 'health'],
    queryFn: fetchSystemHealth,
    refetchInterval: 10000,
  })
}
