import { useQuery } from '@tanstack/react-query'
import { fetchAdminUsers, fetchSiemConnections } from '@/lib/auth-api'

export function useSiemConnectionsQuery() {
  return useQuery({
    queryKey: ['settings', 'siem-connections'],
    queryFn: fetchSiemConnections,
    staleTime: 20_000,
  })
}

export function useAdminUsersQuery(enabled: boolean) {
  return useQuery({
    queryKey: ['admin', 'users', 'all'],
    queryFn: fetchAdminUsers,
    enabled,
    staleTime: 15_000,
  })
}
