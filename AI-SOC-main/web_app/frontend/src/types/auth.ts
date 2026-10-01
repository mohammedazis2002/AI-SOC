export interface UserPermissions {
  user_management: boolean
  dashboard_access: boolean
  backend_access: boolean
}

export interface AuthUser {
  id: string
  name: string
  email: string
  status: string
  role_id: string | null
  role_name?: string | null
  is_superadmin: boolean
  created_at: string
  updated_at: string
  permissions?: UserPermissions | null
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface RegisterResponse {
  id: string
  email: string
  name: string
  status: string
  message: string
}

export interface RolePermissions {
  user_management: boolean
  dashboard_access: boolean
  backend_access: boolean
}

export interface RolePublic {
  id: string
  name: string
  permissions: RolePermissions
}

export interface PendingUser {
  id: string
  name: string
  email: string
  status: string
  created_at: string
}

export function hasAdminOrEngineerAccess(user: AuthUser | null | undefined): boolean {
  return Boolean(
    user?.is_superadmin ||
    user?.role_name === 'Admin' ||
    user?.role_name === 'Engineer'
  )
}

/** MITRE unmapped DLQ tab (Engineer / Admin). */
export function canSeeUnmappedQueue(user: AuthUser | null | undefined): boolean {
  return hasAdminOrEngineerAccess(user)
}

export interface ManualReviewTab {
  /** Query param for GET /alerts/review-queue/manual; omit = all tiers (Admin) or role default (L3). */
  tier?: string
  label: string
}

/** Tabs for Mongo `incidents` manual-review queue (not shown for Engineer-only). */
export function manualReviewTabs(user: AuthUser | null | undefined): ManualReviewTab[] {
  if (!user) return []
  if (user.is_superadmin || user.role_name === 'Admin') {
    return [
      { label: 'All tiers' },
      { tier: 'l1', label: 'L1' },
      { tier: 'l2', label: 'L2' },
      { tier: 'l3', label: 'L3' },
      { tier: 'ir', label: 'IR' },
    ]
  }
  if (user.role_name === 'Engineer') return []
  if (user.role_name === 'L1') return [{ tier: 'l1', label: 'Manual (L1)' }]
  if (user.role_name === 'L2') return [{ tier: 'l2', label: 'Manual (L2)' }]
  if (user.role_name === 'L3') {
    return [{ label: 'Manual (L3 & IR)' }]
  }
  return []
}
