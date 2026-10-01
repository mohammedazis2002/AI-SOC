import { useEffect, useState } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'

export function RequireAuth() {
  const location = useLocation()
  const token = useAuthStore((s) => s.token)
  const user = useAuthStore((s) => s.user)
  const [storageReady, setStorageReady] = useState(() => useAuthStore.persist.hasHydrated())

  useEffect(() => {
    if (useAuthStore.persist.hasHydrated()) {
      setStorageReady(true)
      return
    }
    return useAuthStore.persist.onFinishHydration(() => {
      setStorageReady(true)
    })
  }, [])

  // Token without user (old storage or missed bootstrap): force /me — don’t rely only on AuthBootstrap timing.
  useEffect(() => {
    if (!storageReady || !token || user) return
    void useAuthStore.getState().refreshSession()
  }, [storageReady, token, user])

  if (!storageReady) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <p className="text-sm text-slate-500">Loading session…</p>
      </div>
    )
  }

  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  // Older persisted state had only token; AuthBootstrap’s refreshSession fills user.
  if (!user) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <p className="text-sm text-slate-500">Restoring session…</p>
      </div>
    )
  }

  return <Outlet />
}
