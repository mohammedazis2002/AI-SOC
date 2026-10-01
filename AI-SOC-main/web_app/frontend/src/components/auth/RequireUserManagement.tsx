import { Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'

export function RequireUserManagement() {
  const user = useAuthStore((s) => s.user)
  if (!user) return <Navigate to="/login" replace />

  if (!user.is_superadmin && !user.permissions?.user_management) {
    return <Navigate to="/" replace />
  }

  return <Outlet />
}
