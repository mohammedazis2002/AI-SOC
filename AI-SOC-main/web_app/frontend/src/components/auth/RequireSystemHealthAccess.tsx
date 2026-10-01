import { Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import { hasAdminOrEngineerAccess } from '@/types/auth'

export function RequireSystemHealthAccess() {
  const user = useAuthStore((s) => s.user)
  if (!user) return <Navigate to="/login" replace />

  if (!hasAdminOrEngineerAccess(user)) {
    return <Navigate to="/" replace />
  }

  return <Outlet />
}
