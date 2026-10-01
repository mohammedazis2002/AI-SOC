import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useAuthStore } from '@/store/authStore'
import { useAppStore } from '@/store/useAppStore'
import { CertificateManager } from '@/components/settings/CertificateManager'
import { hasAdminOrEngineerAccess } from '@/types/auth'
import { useSiemConnectionsQuery, useAdminUsersQuery } from '@/hooks/useSettingsData'
import { formatRelativeTime } from '@/lib/utils'
import { restoreUserAccess, revokeUserAccess } from '@/lib/auth-api'
import type { SiemConnectionRow } from '@/types/settings'

function siemStatusLabel(status: string) {
  if (status === 'active') return <span className="text-green-600">● Active</span>
  if (status === 'idle') return <span className="text-amber-600">● Recent</span>
  return <span className="text-slate-400">○ Inactive</span>
}

function sourceKindBadge(row: SiemConnectionRow) {
  const k = row.sourceKind ?? 'unknown'
  if (k === 'siem') {
    return (
      <span className="text-xs rounded-md bg-blue-50 text-blue-800 px-2 py-0.5 border border-blue-100">
        SIEM name
      </span>
    )
  }
  if (k === 'agent') {
    return (
      <span
        className="text-xs rounded-md bg-slate-100 text-slate-700 px-2 py-0.5 border border-slate-200"
        title="No `siem_source` on this alert — label is the agent or endpoint hostname"
      >
        Agent / host
      </span>
    )
  }
  return <span className="text-xs rounded-md bg-slate-50 text-slate-500 px-2 py-0.5">Unknown</span>
}

function axiosDetail(e: unknown): string | undefined {
  if (e && typeof e === 'object' && 'response' in e) {
    const d = (e as { response?: { data?: { detail?: string } } }).response?.data?.detail
    return typeof d === 'string' ? d : undefined
  }
  return undefined
}

function formatUserStatus(s: string) {
  if (s === 'disabled') return 'Disabled'
  return s
}

export function Settings() {
  const user = useAuthStore((s) => s.user)
  const canSeeCerts = hasAdminOrEngineerAccess(user)
  const canListUsers = Boolean(user?.is_superadmin || user?.permissions?.user_management)

  const addNotification = useAppStore((s) => s.addNotification)
  const queryClient = useQueryClient()

  const siemQ = useSiemConnectionsQuery()
  const usersQ = useAdminUsersQuery(canListUsers)

  const revokeMut = useMutation({
    mutationFn: revokeUserAccess,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'all'] })
      addNotification({
        type: 'success',
        message: 'Access revoked. That user can no longer sign in.',
      })
    },
    onError: (e: unknown) => {
      addNotification({ type: 'error', message: axiosDetail(e) ?? 'Failed to revoke access.' })
    },
  })

  const restoreMut = useMutation({
    mutationFn: restoreUserAccess,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'all'] })
      addNotification({ type: 'success', message: 'Access restored. User can sign in again.' })
    },
    onError: (e: unknown) => {
      addNotification({ type: 'error', message: axiosDetail(e) ?? 'Failed to restore access.' })
    },
  })

  return (
    <div className="space-y-6">
      <h1 className="font-semibold text-2xl text-slate-900">Settings</h1>

      <Tabs defaultValue="general">
        <TabsList className="mb-4">
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="siem">SIEM Connections</TabsTrigger>
          <TabsTrigger value="automation">Automation Policies</TabsTrigger>
          <TabsTrigger value="users">User Management</TabsTrigger>
          {canSeeCerts && <TabsTrigger value="certs">Certificates</TabsTrigger>}
        </TabsList>

        <TabsContent value="general">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">General</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 max-w-md">
              <div>
                <label className="text-sm font-medium text-slate-700 block mb-1">Platform name</label>
                <Input defaultValue="Cybolt" />
              </div>
              <div>
                <label className="text-sm font-medium text-slate-700 block mb-1">Default timezone</label>
                <select className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm bg-white">
                  <option>UTC</option>
                  <option>America/New_York</option>
                  <option>Europe/London</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-700 block mb-1">Alert retention period</label>
                <select className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm bg-white">
                  <option>30 days</option>
                  <option>60 days</option>
                  <option>90 days</option>
                  <option>180 days</option>
                </select>
              </div>
              <Button>Save Changes</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="siem">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-2">
              <div>
                <CardTitle className="text-sm">SIEM Connections</CardTitle>
                <p className="text-xs text-slate-500 font-normal mt-1">
                  Sources are inferred from <span className="font-mono">alerts_processed</span>, not a connector
                  registry. If <span className="font-mono">siem_source</span> is empty or “unknown”, the UI falls
                  back to the agent or endpoint <strong>hostname</strong> (for example Barracuda or other vendor
                  agents). Those rows are labeled <strong>Agent / host</strong> — they are not a separate SIEM
                  integration record.
                </p>
              </div>
              <Button size="sm" variant="outline" disabled title="Connector registration is not available in this build">
                + Add SIEM Connection
              </Button>
            </CardHeader>
            <CardContent>
              {siemQ.isLoading && (
                <p className="text-sm text-slate-500 py-6">Loading sources…</p>
              )}
              {siemQ.isError && (
                <p className="text-sm text-red-600 py-6">Could not load SIEM source stats.</p>
              )}
              {siemQ.data && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                      <th className="pb-2 pr-4">Source</th>
                      <th className="pb-2 pr-4">How labeled</th>
                      <th className="pb-2 pr-4">Status</th>
                      <th className="pb-2 pr-4">Last ingest</th>
                      <th className="pb-2 pr-4">Alerts today (UTC)</th>
                      <th className="pb-2">Total (all time)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {siemQ.data.connections.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-slate-500">
                          No alerts in the database yet.
                        </td>
                      </tr>
                    ) : (
                      siemQ.data.connections.map((row) => (
                        <tr key={`${row.name}-${row.sourceKind ?? 'x'}`} className="border-b border-slate-100">
                          <td className="py-3 font-medium text-slate-800">{row.name}</td>
                          <td className="py-3">{sourceKindBadge(row)}</td>
                          <td className="py-3">{siemStatusLabel(row.status)}</td>
                          <td className="py-3 font-mono text-slate-600 text-xs">
                            {row.lastIngestAt ? formatRelativeTime(row.lastIngestAt) : '—'}
                          </td>
                          <td className="py-3 tabular-nums">{row.alertsToday}</td>
                          <td className="py-3 tabular-nums text-slate-600">{row.totalAlerts}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="automation">
          <Card>
            <CardContent className="pt-6 min-h-[12rem] flex items-center justify-center">
              <p className="text-sm text-slate-500 text-center max-w-md">
                Automation policies are not configured in the web app. When policy editing is supported, it will appear here.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="users">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-2">
              <CardTitle className="text-sm">User Management</CardTitle>
              <div className="flex gap-2">
                {canListUsers && (
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/admin/users">Pending approvals</Link>
                  </Button>
                )}
                <Button size="sm" variant="outline" disabled title="Invite flow is not enabled in this build">
                  + Invite User
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {!canListUsers && (
                <p className="text-sm text-slate-500 py-4">
                  You do not have permission to list users. Ask an administrator for the user management role.
                </p>
              )}
              {canListUsers && usersQ.isLoading && (
                <p className="text-sm text-slate-500 py-6">Loading users…</p>
              )}
              {canListUsers && usersQ.isError && (
                <p className="text-sm text-red-600 py-6">Could not load users.</p>
              )}
              {canListUsers && usersQ.data && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                      <th className="pb-2 pr-4">User</th>
                      <th className="pb-2 pr-4">Email</th>
                      <th className="pb-2 pr-4">Role</th>
                      <th className="pb-2 pr-4">Status</th>
                      <th className="pb-2 pr-4">Last updated</th>
                      <th className="pb-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {usersQ.data.map((u) => {
                      const isSelf = u.id === user?.id
                      const isSuper = u.is_superadmin
                      const busyRevoke = revokeMut.isPending && revokeMut.variables === u.id
                      const busyRestore = restoreMut.isPending && restoreMut.variables === u.id

                      return (
                        <tr key={u.id} className="border-b border-slate-100">
                          <td className="py-3">{u.name}</td>
                          <td className="py-3 font-mono text-xs text-slate-600">{u.email}</td>
                          <td className="py-3">{u.role_name ?? '—'}</td>
                          <td className="py-3 capitalize">{formatUserStatus(u.status)}</td>
                          <td className="py-3 font-mono text-xs text-slate-500" title={u.updated_at}>
                            {formatRelativeTime(u.updated_at)}
                          </td>
                          <td className="py-3 text-right whitespace-nowrap">
                            {u.status === 'pending' && (
                              <span className="text-xs text-slate-500">Use Pending approvals</span>
                            )}
                            {u.status === 'rejected' && (
                              <span className="text-xs text-slate-400">—</span>
                            )}
                            {u.status === 'active' && (isSelf || isSuper) && (
                              <span className="text-xs text-slate-400" title="You cannot revoke your own account or the superadmin">
                                —
                              </span>
                            )}
                            {u.status === 'active' && !isSuper && !isSelf && (
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-red-700 hover:text-red-800"
                                disabled={busyRevoke || busyRestore}
                                onClick={() => {
                                  if (
                                    !window.confirm(
                                      `Revoke access for ${u.email}? They will not be able to sign in until an admin restores access.`
                                    )
                                  ) {
                                    return
                                  }
                                  revokeMut.mutate(u.id)
                                }}
                              >
                                {busyRevoke ? '…' : 'Revoke access'}
                              </Button>
                            )}
                            {u.status === 'disabled' && !isSuper && (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={busyRevoke || busyRestore}
                                onClick={() => {
                                  if (
                                    !window.confirm(
                                      `Restore access for ${u.email}? They will be able to sign in again.`
                                    )
                                  ) {
                                    return
                                  }
                                  restoreMut.mutate(u.id)
                                }}
                              >
                                {busyRestore ? '…' : 'Restore access'}
                              </Button>
                            )}
                            {u.status === 'disabled' && isSuper && (
                              <span className="text-xs text-slate-400">—</span>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {canSeeCerts && (
          <TabsContent value="certs">
            <CertificateManager />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}
