import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useAppStore } from '@/store/useAppStore'

interface SidebarCounts {
  newAlertsCount: number
  reviewQueueCount: number
  unmappedCount: number
}

/** Syncs sidebar badges with `alerts_processed` via GET /alerts/sidebar-counts */
export function useSidebarAlertCounts() {
  const liveMode = useAppStore((s) => s.liveMode)
  const setNewAlertsCount = useAppStore((s) => s.setNewAlertsCount)
  const setReviewQueueCount = useAppStore((s) => s.setReviewQueueCount)
  const setUnmappedQueueCount = useAppStore((s) => s.setUnmappedQueueCount)

  const { data } = useQuery({
    queryKey: ['alerts', 'sidebar-counts', liveMode],
    queryFn: async () => {
      const { data: body } = await api.get<SidebarCounts>('/alerts/sidebar-counts')
      return body
    },
    refetchInterval: liveMode ? 25_000 : 60_000,
    staleTime: 10_000,
  })

  useEffect(() => {
    if (!data) return
    setNewAlertsCount(data.newAlertsCount)
    setReviewQueueCount(data.reviewQueueCount)
    setUnmappedQueueCount(data.unmappedCount ?? 0)
  }, [data, setNewAlertsCount, setReviewQueueCount, setUnmappedQueueCount])
}
