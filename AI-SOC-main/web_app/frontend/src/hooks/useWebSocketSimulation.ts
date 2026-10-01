import { useEffect } from 'react'
import { useAppStore } from '@/store/useAppStore'

/**
 * In dev: simulate WebSocket connection status.
 * Swap to real WebSocket when backend is ready.
 */
export function useWebSocketSimulation() {
  const setWsStatus = useAppStore((s) => s.setWsStatus)

  useEffect(() => {
    setWsStatus('connected')
  }, [setWsStatus])
}
