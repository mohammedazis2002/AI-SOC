import { useEffect } from 'react'
import { useAuthStore } from '@/store/authStore'

/**
 * Revalidate JWT and load `/me` after persisted state is ready.
 * Must handle hydration that already finished before this effect runs — otherwise
 * `onFinishHydration` never fires and we stay stuck on "Restoring session…".
 */
export function AuthBootstrap() {
  useEffect(() => {
    const sync = () => {
      void useAuthStore.getState().refreshSession()
    }

    if (useAuthStore.persist.hasHydrated()) {
      sync()
      return
    }

    return useAuthStore.persist.onFinishHydration(() => {
      sync()
    })
  }, [])

  return null
}
