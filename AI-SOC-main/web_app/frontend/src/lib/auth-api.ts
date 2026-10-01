import type {
  AuthUser,
  PendingUser,
  RegisterResponse,
  RolePublic,
  TokenResponse,
} from '@/types/auth'
import type { SiemConnectionsResponse } from '@/types/settings'
import { api } from './api'

export async function loginRequest(email: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>('/login', { email, password })
  return data
}

export async function registerRequest(
  name: string,
  email: string,
  password: string
): Promise<RegisterResponse> {
  const { data } = await api.post<RegisterResponse>('/register', { name, email, password })
  return data
}

export async function fetchMe(): Promise<AuthUser> {
  const { data } = await api.get<AuthUser>('/me')
  return data
}

export async function fetchRoles(): Promise<RolePublic[]> {
  const { data } = await api.get<RolePublic[]>('/admin/roles')
  return data
}

export async function fetchPendingUsers(): Promise<PendingUser[]> {
  const { data } = await api.get<PendingUser[]>('/admin/users/pending')
  return data
}

export async function fetchAdminUsers(): Promise<AuthUser[]> {
  const { data } = await api.get<AuthUser[]>('/admin/users')
  return data
}

export async function fetchSiemConnections(): Promise<SiemConnectionsResponse> {
  const { data } = await api.get<SiemConnectionsResponse>('/settings/siem-connections')
  return data
}

export async function approveUser(userId: string): Promise<void> {
  await api.post(`/admin/users/${userId}/approve`)
}

export async function rejectUser(userId: string): Promise<void> {
  await api.post(`/admin/users/${userId}/reject`)
}

export async function assignRole(userId: string, roleId: string): Promise<void> {
  await api.post(`/admin/users/${userId}/assign-role`, { role_id: roleId })
}

export async function revokeUserAccess(userId: string): Promise<AuthUser> {
  const { data } = await api.post<AuthUser>(`/admin/users/${userId}/revoke`)
  return data
}

export async function restoreUserAccess(userId: string): Promise<AuthUser> {
  const { data } = await api.post<AuthUser>(`/admin/users/${userId}/restore`)
  return data
}
