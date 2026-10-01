import { Link } from 'react-router-dom'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  LineChart,
  Line,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Skeleton } from '@/components/ui/skeleton'
import { useDashboardSummary } from '@/hooks/useDashboard'
import { formatRelativeTime, getStatusLabel } from '@/lib/utils'
import type { AlertStatus } from '@/data/mockAlerts'
import type { Severity } from '@/lib/utils'
import type { AlertVolumeDayRow } from '@/types/dashboard'
import {
  Shield,
  CheckCircle2,
  ArrowUpRight,
  Server,
  Ticket,
  ArrowUp,
} from 'lucide-react'


function volumeRowTotal(d: AlertVolumeDayRow) {
  return d.critical + d.high + d.medium + d.low + d.info
}

function formatPercentDelta(frac: number | undefined): string {
  if (frac == null || !Number.isFinite(frac)) return '—'
  const p = Math.round(frac * 100)
  const mag = Math.min(Math.abs(p), 999)
  return `${p >= 0 ? '↑' : '↓'} ${mag}%`
}

/** MTTR: higher is worse — positive delta is red, negative is green. */
function mttrDeltaLabel(frac: number | null | undefined): { text: string; className: string } {
  if (frac == null || !Number.isFinite(frac)) {
    return { text: '—', className: 'text-slate-500' }
  }
  const p = Math.round(frac * 100)
  const mag = Math.min(Math.abs(p), 999)
  if (frac > 0) return { text: `↑ ${mag}% vs prior half`, className: 'text-red-600' }
  if (frac < 0) return { text: `↓ ${mag}% vs prior half`, className: 'text-green-600' }
  return { text: 'flat vs prior half', className: 'text-slate-500' }
}

const actionIcons: Record<string, React.ReactNode> = {
  block_ip: <Shield className="h-4 w-4 text-red-500" />,
  isolate_host: <Server className="h-4 w-4 text-orange-500" />,
  create_ticket: <Ticket className="h-4 w-4 text-blue-500" />,
  escalate: <ArrowUp className="h-4 w-4 text-purple-500" />,
}

export function Dashboard() {
  const { data, isLoading } = useDashboardSummary({ days: 14 })
  const summary = data ?? null
  const recentAlerts = summary?.recentAlerts ?? []
  const volumeData = summary?.alertVolumeByDay ?? []
  const sourceData = summary?.alertsBySource ?? []
  const mttrDeltaUi = mttrDeltaLabel(summary?.mttrDelta)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-20 mb-2" />
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-12 w-full mt-2" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  const automatedActions = summary?.recentAutomatedActions ?? []
  const resolvedPerDayEst =
    volumeData.length > 0 ? Math.round((summary?.autoResolved ?? 0) / volumeData.length) : 0
  const pendingPerDayEst =
    volumeData.length > 0 ? Math.round((summary?.pendingReview ?? 0) / volumeData.length) : 0

  return (
    <div className="space-y-6">
      <h1 className="font-semibold text-2xl text-slate-900">Dashboard</h1>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className={summary?.pendingReview && summary?.slaAtRisk ? 'border-amber-200 border-b-4 border-b-amber-400' : ''}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">Total Alerts</CardTitle>
            <span className="text-xs font-mono text-green-600">{formatPercentDelta(summary?.totalDelta)} today</span>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono">{(summary?.totalAlerts ?? 0).toLocaleString()}</div>
            <p className="text-xs text-slate-500 mt-1">
              Critical {(summary?.criticalCount ?? 0).toLocaleString()} · High {(summary?.highCount ?? 0).toLocaleString()}
            </p>
            <div className="mt-2 h-10">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={volumeData.map((d) => ({ ...d, total: volumeRowTotal(d) }))}>
                  <Line type="monotone" dataKey="total" stroke="#2563eb" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">Critical / High</CardTitle>
            <span className="text-xs font-mono text-red-600">
              {summary?.criticalHighDelta != null && summary.criticalHighDelta >= 0 ? '↑' : '↓'}{' '}
              {Math.abs(summary?.criticalHighDelta ?? 0)} vs prior {volumeData.length || 14}d
            </span>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono">{summary?.criticalHigh ?? 0}</div>
            <div className="mt-2 h-10">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={volumeData}>
                  <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={1.5} dot={false} />
                  <Line type="monotone" dataKey="high" stroke="#ea580c" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">Auto-Resolved</CardTitle>
            <span className="text-xs font-mono text-slate-500">
              {summary?.autoResolvedPct ?? 0}% of corpus
            </span>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono">{summary?.autoResolved ?? 0} <span className="text-sm font-normal text-slate-500">({summary?.autoResolvedPct ?? 0}%)</span></div>
            <div className="mt-2 h-10">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={volumeData.map(() => ({ v: resolvedPerDayEst }))}>
                  <Line type="monotone" dataKey="v" stroke="#16a34a" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className={summary?.pendingReview && summary?.slaAtRisk ? 'border-amber-200 border-b-4 border-b-amber-400' : ''}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">Pending Review</CardTitle>
            {summary?.slaAtRisk && <span className="text-xs font-medium text-amber-600">SLA at risk</span>}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono">{summary?.pendingReview ?? 0}</div>
            <div className="mt-2 h-10">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={volumeData.map(() => ({ v: pendingPerDayEst }))}>
                  <Line type="monotone" dataKey="v" stroke="#d97706" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">MTTD (avg)</CardTitle>
            <span className="text-xs font-mono text-slate-500">TBD</span>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono tracking-wide text-slate-600">TBD</div>
            <p className="text-xs text-slate-500 mt-0.5">
              Mean time to detect — SOC-wide definition and telemetry wiring pending
            </p>
            <div className="mt-2 h-10 flex items-center justify-center rounded border border-dashed border-slate-200 text-xs text-slate-400">
              —
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-500">MTTR (avg)</CardTitle>
            <span className={`text-xs font-mono ${mttrDeltaUi.className}`}>{mttrDeltaUi.text}</span>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold font-mono">{summary?.mttrAvgMinutes ?? 0} min</div>
            <p className="text-xs text-slate-500 mt-0.5">
              Mean resolve time (resolved / closed / FP in window){' '}
              {summary?.mttrSampleCount != null && summary.mttrSampleCount > 0 && (
                <span className="font-mono text-slate-400">· n={summary.mttrSampleCount}</span>
              )}
            </p>
            <div className="mt-2 h-10">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={(summary?.mttrSparkline?.length ? summary.mttrSparkline : [0]).map((v: number, i: number) => ({
                    i,
                    v,
                  }))}
                >
                  <Line type="monotone" dataKey="v" stroke="#2563eb" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[10px] text-slate-400 mt-1 leading-snug">
              End = resolved_at → closed_at → updated_at → processed_at. Refreshes every 30s.
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-slate-500">Alert Volume Over Time</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={volumeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} stroke="#94a3b8" />
                  <YAxis tick={{ fontSize: 12 }} stroke="#94a3b8" />
                  <Tooltip />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" fill="#dc2626" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#ea580c" fill="#ea580c" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#d97706" fill="#d97706" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#2563eb" fill="#2563eb" fillOpacity={0.7} />
                  <Area type="monotone" dataKey="info" stackId="1" stroke="#64748b" fill="#64748b" fillOpacity={0.7} />
                  <Legend />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-slate-500">Alerts by SIEM Source</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              {sourceData.length === 0 ? (
                <p className="flex h-full items-center justify-center text-sm text-slate-500">
                  No SIEM source breakdown yet (empty <span className="font-mono px-1">alerts_processed</span>).
                </p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sourceData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={2}
                      label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                    >
                      {sourceData.map((_: { name: string }, i: number) => (
                        <Cell key={i} fill={['#2563eb', '#ea580c', '#16a34a', '#7c3aed', '#0d9488', '#c026d3'][i % 6]} />
                      ))}
                    </Pie>
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-slate-500">Recent Alerts</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link to="/alerts">View all alerts <ArrowUpRight className="h-4 w-4 ml-1" /></Link>
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-0">
              {recentAlerts.length === 0 ? (
                <p className="text-sm text-slate-500 py-6 text-center">No recent alerts in the database.</p>
              ) : (
                recentAlerts.map((alert) => {
                  const desc =
                    alert.description.length > 40
                      ? `${alert.description.slice(0, 40)}…`
                      : alert.description
                  return (
                    <Link
                      key={alert.id}
                      to={`/alerts/${encodeURIComponent(alert.id)}`}
                      className="flex items-center gap-3 py-2 px-2 -mx-2 rounded-lg hover:bg-slate-50 transition-colors border-b border-slate-50 last:border-0"
                    >
                      <SeverityBadge severity={alert.severity as Severity} />
                      <span className="font-mono text-xs text-blue-600 hover:underline truncate max-w-[140px]">
                        {alert.id}
                      </span>
                      <span className="text-sm text-slate-600 truncate flex-1" title={alert.description}>
                        {desc}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">{formatRelativeTime(alert.timestamp)}</span>
                      <span
                        className={`text-xs px-2 py-0.5 rounded border ${alert.status === 'new' ? 'text-purple-700 bg-purple-50 border-purple-200' : 'text-slate-600 bg-slate-100'}`}
                      >
                        {getStatusLabel(alert.status as AlertStatus)}
                      </span>
                      <span className="text-slate-400 text-xs">View →</span>
                    </Link>
                  )
                })
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-slate-500">Recent Automated Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {automatedActions.length === 0 && (
                <p className="text-sm text-slate-500 py-4 text-center">No automated actions recorded (not wired to Mongo).</p>
              )}
              {automatedActions.map((action: { type: string; alertId: string; confidence: number; timestamp: string }, i: number) => (
                <div key={i} className="flex items-center gap-3 py-2 px-2 rounded-lg hover:bg-slate-50">
                  {actionIcons[action.type] ?? <CheckCircle2 className="h-4 w-4 text-slate-400" />}
                  <span className="text-sm text-slate-700 capitalize">{action.type.replace('_', ' ')}</span>
                  <span className="font-mono text-xs text-slate-500">{action.alertId}</span>
                  <span className="text-xs text-slate-400 ml-auto">{formatRelativeTime(action.timestamp)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
