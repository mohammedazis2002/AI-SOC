import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, Download, MoreVertical, Flag, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Progress } from '@/components/ui/progress'
import { Checkbox } from '@/components/ui/checkbox'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { buildAlertsSearchParams, useAlerts } from '@/hooks/useAlerts'
import { api } from '@/lib/api'
import { useAppStore, type SourceFilter } from '@/store/useAppStore'
import { formatRelativeTime, formatMinutes, getStatusLabel } from '@/lib/utils'
import type { AlertStatus, Severity } from '@/lib/utils'
import type { AlertListItem, AlertsListResponse, ProcessedAlertDetailResponse } from '@/types/alertApi'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const SOURCE_LABELS: Record<string, string> = {
  Wazuh: 'Wazuh',
  SentinelOne: 'SentinelOne',
  Splunk: 'Splunk',
  SumoLogic: 'SumoLogic',
}

const DETAIL_FETCH_BATCH = 12

export function Alerts() {
  const { filters, setFilters, liveMode, setLiveMode, addNotification } = useAppStore()
  const [page, setPage] = useState(1)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    setPage(1)
  }, [filters.search, filters.severity, filters.source, filters.status, filters.dateRange])

  const { data, isLoading } = useAlerts({
    page,
    limit: 50,
    search: filters.search || undefined,
    severity: filters.severity.length ? filters.severity : undefined,
    source: filters.source.length ? filters.source : undefined,
    status: filters.status.length ? filters.status : undefined,
    dateRange: filters.dateRange,
  })

  const alerts: AlertListItem[] = data?.alerts ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / 50)

  const handleExportJson = useCallback(async () => {
    setExporting(true)
    try {
      const sp = buildAlertsSearchParams({
        page: 1,
        limit: 200,
        search: filters.search || undefined,
        severity: filters.severity.length ? filters.severity : undefined,
        source: filters.source.length ? filters.source : undefined,
        status: filters.status.length ? filters.status : undefined,
        dateRange: filters.dateRange,
      })
      const { data: list } = await api.get<AlertsListResponse>(`/alerts?${sp.toString()}`)
      const ids = list.alerts.map((a) => a.id)
      const details: ProcessedAlertDetailResponse[] = []
      for (let i = 0; i < ids.length; i += DETAIL_FETCH_BATCH) {
        const chunk = ids.slice(i, i + DETAIL_FETCH_BATCH)
        const batch = await Promise.all(
          chunk.map((id) =>
            api
              .get<ProcessedAlertDetailResponse>(`/alerts/${encodeURIComponent(id)}`)
              .then((r) => r.data)
          )
        )
        details.push(...batch)
      }
      const payload = {
        exported_at: new Date().toISOString(),
        note: 'Full enriched alert payloads from GET /alerts/{id} (summary, endpoints, enrichments, correlation, raw Mongo document in raw, etc.).',
        total_matching: list.total,
        exported_count: details.length,
        alerts: details,
      }
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: 'application/json;charset=utf-8',
      })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `alerts-export-${new Date().toISOString().slice(0, 10)}.json`
      anchor.click()
      URL.revokeObjectURL(url)
      addNotification({
        type: 'success',
        message:
          details.length >= list.total
            ? `Exported ${details.length} enriched alert(s) as JSON.`
            : `Exported ${details.length} of ${list.total} matching alert(s) as JSON (max 200 per export).`,
      })
    } catch (e) {
      addNotification({
        type: 'error',
        message: e instanceof Error ? e.message : 'Export failed.',
      })
    } finally {
      setExporting(false)
    }
  }, [filters, addNotification])

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === alerts.length) setSelectedIds(new Set())
    else setSelectedIds(new Set(alerts.map((a) => a.id)))
  }

  const clearSelection = () => setSelectedIds(new Set())

  const activeFilterCount = [
    filters.severity.length,
    filters.source.length,
    filters.status.length,
    filters.search ? 1 : 0,
  ].reduce((a, b) => a + b, 0)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="font-semibold text-2xl text-slate-900">Alerts</h1>
      </div>

      <Card>
        <CardContent className="p-4 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <Input
                placeholder="Search alerts..."
                value={filters.search}
                onChange={(e) => setFilters({ search: e.target.value })}
                className="pl-9"
              />
            </div>
            <select
              className="h-9 rounded-lg border border-slate-200 px-3 text-sm bg-white"
              value={filters.severity[0] ?? ''}
              onChange={(e) => setFilters({ severity: e.target.value ? [e.target.value as Severity] : [] })}
            >
              <option value="">Severity</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              className="h-9 rounded-lg border border-slate-200 px-3 text-sm bg-white"
              value={filters.source[0] ?? ''}
              onChange={(e) => setFilters({ source: e.target.value ? [e.target.value as SourceFilter] : [] })}
            >
              <option value="">Source</option>
              {['Wazuh', 'SentinelOne', 'Splunk', 'SumoLogic'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              className="h-9 rounded-lg border border-slate-200 px-3 text-sm bg-white"
              value={filters.status[0] ?? ''}
              onChange={(e) => setFilters({ status: e.target.value ? [e.target.value as AlertStatus] : [] })}
            >
              <option value="">Status</option>
              {['new', 'in_review', 'resolved', 'false_positive', 'escalated'].map((s) => (
                <option key={s} value={s}>{getStatusLabel(s as AlertStatus)}</option>
              ))}
            </select>
            <select
              className="h-9 rounded-lg border border-slate-200 px-3 text-sm bg-white"
              value={filters.dateRange}
              onChange={(e) => setFilters({ dateRange: e.target.value as '1h' | '24h' | '7d' | 'custom' })}
            >
              <option value="1h">Last hour</option>
              <option value="24h">24h</option>
              <option value="7d">7 days</option>
              <option value="custom">Custom</option>
            </select>
            <Button
              type="button"
              variant={liveMode ? 'default' : 'outline'}
              size="sm"
              className="gap-1.5"
              aria-pressed={liveMode}
              title={
                liveMode
                  ? 'Auto-refresh every 20s (on). Click to pause.'
                  : 'Auto-refresh paused. Click to resume every 20s.'
              }
              onClick={() => setLiveMode(!liveMode)}
            >
              <span className={cn('h-2 w-2 rounded-full', liveMode ? 'bg-green-500' : 'bg-slate-300')} />
              Live
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={exporting}
              onClick={() => void handleExportJson()}
            >
              <Download className="h-4 w-4 mr-1" /> {exporting ? 'Exporting…' : 'Export JSON'}
            </Button>
          </div>

          {activeFilterCount > 0 && (
            <div className="flex flex-wrap gap-2">
              {filters.severity.map((s) => (
                <span key={s} className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs">
                  Severity: {s}
                  <button type="button" onClick={() => setFilters({ severity: filters.severity.filter((x) => x !== s) })} aria-label={`Remove ${s}`}>
                    <XCircle className="h-3 w-3" />
                  </button>
                </span>
              ))}
              {filters.search && (
                <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs">
                  Search: {filters.search}
                  <button type="button" onClick={() => setFilters({ search: '' })} aria-label="Clear search">
                    <XCircle className="h-3 w-3" />
                  </button>
                </span>
              )}
            </div>
          )}

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-4 py-2 px-3 rounded-lg bg-blue-50 border border-blue-200">
              <span className="text-sm font-medium text-slate-700">{selectedIds.size} alerts selected</span>
              <Button size="sm" variant="outline">Mark as False Positive</Button>
              <Button size="sm" variant="outline">Escalate</Button>
              <Button size="sm" variant="outline">Assign to me</Button>
              <Button size="sm" variant="ghost" onClick={clearSelection}>✕ Clear</Button>
            </div>
          )}

          <div className="rounded-lg border border-slate-200 overflow-hidden">
            {isLoading ? (
              <div className="divide-y divide-slate-100">
                {Array.from({ length: 10 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-4 p-4">
                    <Skeleton className="h-4 w-4" />
                    <Skeleton className="h-5 w-20" />
                    <Skeleton className="h-4 w-24" />
                    <Skeleton className="h-4 flex-1 max-w-[200px]" />
                    <Skeleton className="h-4 w-16" />
                  </div>
                ))}
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="text-left p-3 w-10"><Checkbox checked={selectedIds.size === alerts.length && alerts.length > 0} onCheckedChange={toggleSelectAll} aria-label="Select all" /></th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">SEV</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">ALERT ID</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">DESCRIPTION</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">SOURCE</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">SOURCE IP</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">CORR</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">CONFIDENCE</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">STATUS</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500">TIME</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500 w-16">MTTD</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500 w-16">MTTR</th>
                    <th className="text-left p-3 text-xs font-medium uppercase tracking-wider text-slate-500 w-24">ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className="border-b border-slate-100 hover:bg-slate-50 transition-colors"
                    >
                      <td className="p-3"><Checkbox checked={selectedIds.has(alert.id)} onCheckedChange={() => toggleSelect(alert.id)} aria-label={`Select ${alert.id}`} /></td>
                      <td className="p-3"><SeverityBadge severity={alert.severity as Severity} /></td>
                      <td className="p-3"><Link to={`/alerts/${alert.id}`} className="font-mono text-xs text-blue-600 hover:underline">{alert.id}</Link></td>
                      <td className="p-3 max-w-[220px]" title={alert.description}><span className="text-slate-600 truncate block">{alert.description.length > 55 ? alert.description.slice(0, 55) + '…' : alert.description}</span></td>
                      <td className="p-3 text-slate-600">
                        {SOURCE_LABELS[alert.source_siem as keyof typeof SOURCE_LABELS] ?? alert.source_siem}
                      </td>
                      <td className="p-3 font-mono text-xs">{alert.source_ip}</td>
                      <td className="p-3">{alert.correlation_group ? <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-mono">{alert.correlation_group}</span> : '—'}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <Progress value={alert.confidence * 100} className="h-1.5 w-12" />
                          <span className="font-mono text-xs">{Math.round(alert.confidence * 100)}%</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border ${alert.status === 'new' ? 'text-purple-700 bg-purple-50 border-purple-200' : alert.status === 'in_review' ? 'text-amber-700 bg-amber-50' : 'text-slate-600 bg-slate-100'}`}>
                          <span className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
                          {getStatusLabel(alert.status as AlertStatus)}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-500" title={alert.timestamp}>{formatRelativeTime(alert.timestamp)}</td>
                      <td className="p-3 font-mono text-xs text-slate-600" title="Mean time to detect (min)">{formatMinutes(alert.mttd_minutes)}</td>
                      <td className="p-3 font-mono text-xs text-slate-600" title="Mean time to respond / resolve (min)">{formatMinutes(alert.mttr_minutes)}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-1">
                          <Button variant="ghost" size="sm" asChild><Link to={`/alerts/${alert.id}`}>View</Link></Button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="More actions"><MoreVertical className="h-4 w-4" /></Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem asChild>
                                <Link to={`/alerts/${encodeURIComponent(alert.id)}#alert-feedback`}>
                                  Plan feedback…
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem><Flag className="h-4 w-4 mr-2" /> Flag</DropdownMenuItem>
                              <DropdownMenuItem>Mark FP</DropdownMenuItem>
                              <DropdownMenuItem>Escalate</DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="flex items-center justify-between text-sm text-slate-500">
            <span className="font-mono">Showing {(page - 1) * 50 + 1}–{Math.min(page * 50, total)} of {total} alerts</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</Button>
              <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
