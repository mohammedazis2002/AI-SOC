import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, ShieldAlert, UserX } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  approveUser,
  assignRole,
  fetchPendingUsers,
  fetchRoles,
  rejectUser,
} from '@/lib/auth-api'
import type { PendingUser, RolePublic } from '@/types/auth'
import { useAppStore } from '@/store/useAppStore'

export function UserManagement() {
  const addNotification = useAppStore((s) => s.addNotification)
  const [pendingUsers, setPendingUsers] = useState<PendingUser[]>([])
  const [roles, setRoles] = useState<RolePublic[]>([])
  const [selectedRoleByUser, setSelectedRoleByUser] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [workingId, setWorkingId] = useState<string | null>(null)

  const adminRoleId = useMemo(
    () => roles.find((r) => r.name.toLowerCase() === 'admin')?.id,
    [roles]
  )

  async function load() {
    setLoading(true)
    try {
      const [users, roleList] = await Promise.all([fetchPendingUsers(), fetchRoles()])
      setPendingUsers(users)
      setRoles(roleList)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : undefined
      addNotification({
        type: 'error',
        message: typeof msg === 'string' ? msg : 'Unable to load pending users.',
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  async function onApprove(userId: string) {
    setWorkingId(userId)
    try {
      await approveUser(userId)
      const roleId = selectedRoleByUser[userId] || adminRoleId
      if (roleId) await assignRole(userId, roleId)
      addNotification({ type: 'success', message: 'User approved.' })
      await load()
    } catch {
      addNotification({ type: 'error', message: 'Failed to approve user.' })
    } finally {
      setWorkingId(null)
    }
  }

  async function onReject(userId: string) {
    setWorkingId(userId)
    try {
      await rejectUser(userId)
      addNotification({ type: 'warning', message: 'User rejected.' })
      await load()
    } catch {
      addNotification({ type: 'error', message: 'Failed to reject user.' })
    } finally {
      setWorkingId(null)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-semibold text-2xl text-slate-900">Admin - User Management</h1>
        <p className="text-sm text-slate-500 mt-1">Approve or reject pending registrations and assign roles.</p>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Pending Requests</CardTitle>
          <Button variant="outline" size="sm" onClick={() => void load()}>
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : pendingUsers.length === 0 ? (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-6 text-center">
              <ShieldAlert className="h-8 w-8 mx-auto text-slate-400" />
              <p className="text-sm text-slate-600 mt-2">No pending requests.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs font-medium uppercase tracking-wider text-slate-500">
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">Email</th>
                    <th className="py-2 pr-4">Requested At</th>
                    <th className="py-2 pr-4">Role</th>
                    <th className="py-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingUsers.map((u) => {
                    const busy = workingId === u.id
                    return (
                      <tr key={u.id} className="border-b border-slate-100 hover:bg-slate-50">
                        <td className="py-3 pr-4 text-slate-800">{u.name}</td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-600">{u.email}</td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-500">
                          {new Date(u.created_at).toLocaleString()}
                        </td>
                        <td className="py-3 pr-4">
                          <Select
                            value={selectedRoleByUser[u.id] || adminRoleId || ''}
                            onValueChange={(v) =>
                              setSelectedRoleByUser((prev) => ({
                                ...prev,
                                [u.id]: v,
                              }))
                            }
                          >
                            <SelectTrigger className="w-[160px]">
                              <SelectValue placeholder="Select role" />
                            </SelectTrigger>
                            <SelectContent>
                              {roles.map((r) => (
                                <SelectItem key={r.id} value={r.id}>
                                  {r.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </td>
                        <td className="py-3">
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              onClick={() => void onApprove(u.id)}
                              disabled={busy}
                            >
                              <CheckCircle2 className="h-4 w-4" /> Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => void onReject(u.id)}
                              disabled={busy}
                            >
                              <UserX className="h-4 w-4" /> Reject
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
