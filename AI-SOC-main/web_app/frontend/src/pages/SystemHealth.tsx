import { AlertTriangle, Database, Server, ShieldAlert, Workflow } from 'lucide-react'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, XAxis, YAxis } from 'recharts'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useSystemHealth } from '@/hooks/useSystemHealth'
import type { SystemHealthService, SystemServiceStatus } from '@/types/systemHealth'

const statusTone: Record<SystemServiceStatus, { dot: string; pill: string; label: string }> = {
  healthy: {
    dot: 'bg-green-500',
    pill: 'border-green-200 bg-green-50 text-green-700',
    label: 'Healthy',
  },
  degraded: {
    dot: 'bg-amber-500',
    pill: 'border-amber-200 bg-amber-50 text-amber-700',
    label: 'Degraded',
  },
  down: {
    dot: 'bg-red-500',
    pill: 'border-red-200 bg-red-50 text-red-700',
    label: 'Down',
  },
}

function SummaryCard({
  title,
  value,
  hint,
  icon: Icon,
}: {
  title: string
  value: string | number
  hint: string
  icon: typeof Server
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.2em] text-slate-500">{title}</p>
          <CardTitle className="mt-2 text-2xl">{value}</CardTitle>
        </div>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-2">
          <Icon className="h-4 w-4 text-slate-600" />
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-slate-500">{hint}</p>
      </CardContent>
    </Card>
  )
}

function ServiceCard({ service }: { service: SystemHealthService }) {
  const tone = statusTone[service.status]

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle className="text-base">{service.name}</CardTitle>
            <p className="text-sm text-slate-500">{service.description}</p>
          </div>
          <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium ${tone.pill}`}>
            <span className={`mr-2 inline-block h-2 w-2 rounded-full ${tone.dot}`} />
            {tone.label}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="grid grid-cols-2 gap-3 text-slate-600">
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-400">Instances</p>
            <p className="mt-1 font-medium text-slate-800">{service.instances || 'n/a'}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-400">Latency</p>
            <p className="mt-1 font-medium text-slate-800">{service.latency || 'n/a'}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-400">Last check</p>
            <p className="mt-1 font-medium text-slate-800">{service.lastCheck}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-400">Endpoint</p>
            <p className="mt-1 truncate font-mono text-xs text-slate-700">{service.endpoint || 'internal'}</p>
          </div>
        </div>

        {service.details.length > 0 && (
          <div className="space-y-2 border-t border-slate-100 pt-3">
            {service.details.map((detail) => (
              <div key={`${service.id}-${detail.label}`} className="flex items-center justify-between gap-3">
                <span className="text-slate-500">{detail.label}</span>
                <span className="font-medium text-slate-800">{detail.value}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function SystemHealth() {
  const { data, isLoading, isError, error } = useSystemHealth()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="font-semibold text-2xl text-slate-900">System Health</h1>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {Array.from({ length: 9 }).map((_, i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="space-y-6">
        <h1 className="font-semibold text-2xl text-slate-900">System Health</h1>
        <Card className="border-red-200 bg-red-50">
          <CardContent className="flex items-start gap-3 pt-6">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-red-600" />
            <div>
              <p className="font-medium text-red-900">Unable to load system analytics.</p>
              <p className="mt-1 text-sm text-red-700">
                {error instanceof Error ? error.message : 'The system health API returned an unexpected response.'}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  const chartData = data.queueDepth.labels.map((label, index) => ({
    label,
    incoming: data.queueDepth.incoming[index] ?? 0,
    priority: data.queueDepth.priority[index] ?? 0,
    dlq: data.queueDepth.dlq[index] ?? 0,
  }))

  return (
    <div className="space-y-6">
      <h1 className="font-semibold text-2xl text-slate-900">System Health</h1>
      <p className="max-w-3xl text-sm text-slate-500">
        System analytics for the platform services, background workers, queue pressure, and recent processing failures.
      </p>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          title="Healthy Services"
          value={`${data.summary.healthyServices}/${data.summary.totalServices}`}
          hint={`${data.summary.degradedServices} degraded, ${data.summary.downServices} down`}
          icon={Server}
        />
        <SummaryCard
          title="Alerts Stored"
          value={data.summary.alertsStored.toLocaleString()}
          hint={`${data.summary.processedLastHour.toLocaleString()} processed in the last hour`}
          icon={Database}
        />
        <SummaryCard
          title="DLQ Backlog"
          value={data.summary.dlqBacklog.toLocaleString()}
          hint="Normalization and unmapped alerts awaiting follow-up"
          icon={ShieldAlert}
        />
        <SummaryCard
          title="Pending Approvals"
          value={data.summary.pendingApprovals.toLocaleString()}
          hint={`Snapshot generated ${new Date(data.generatedAt).toLocaleTimeString()}`}
          icon={Workflow}
        />
      </div>

      <div className="space-y-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900">System Analytics</h2>
          <p className="text-sm text-slate-500">Live health status for the platform microservices and supporting infrastructure.</p>
        </div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {data.services.map((service) => (
            <ServiceCard key={service.id} service={service} />
          ))}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Queue And Throughput (last 60 min)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <Line type="monotone" dataKey="incoming" stroke="#2563eb" dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="priority" stroke="#16a34a" dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="dlq" stroke="#dc2626" dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Recent Errors</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 text-left text-xs text-slate-500">
                <th className="pb-2 pr-4">SERVICE</th>
                <th className="pb-2 pr-4">ERROR</th>
                <th className="pb-2">TIME</th>
              </tr>
            </thead>
            <tbody>
              {data.recentErrors.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-slate-500">
                    No recent processing errors detected.
                  </td>
                </tr>
              )}
              {data.recentErrors.map((err, i) => (
                <tr key={i} className="border-b border-slate-50">
                  <td className="py-2 font-mono text-slate-700">{err.service}</td>
                  <td className="py-2 text-slate-600">{err.error}</td>
                  <td className="py-2 text-slate-500">{err.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
