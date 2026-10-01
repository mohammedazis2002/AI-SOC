import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SeverityBadge } from '@/components/SeverityBadge'
import { formatRelativeTime } from '@/lib/utils'
import type { Severity } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { api } from '@/lib/api'
import { useAuthStore } from '@/store/authStore'
import { canSeeUnmappedQueue, manualReviewTabs } from '@/types/auth'
import type { AlertListItem } from '@/types/alertApi'

type QueueRow = AlertListItem & {
  queue_kind?: string
  incident_id?: string
  alert_id?: string
  final_tier?: string
  decision_reason?: string
  dlq_reason?: string
  mapping_method?: string
  technique_confidence?: number
}

interface QueueListResponse {
  alerts: QueueRow[]
  total: number
  page: number
  limit: number
  queue: string
}

function escalationTargets(tier: string | undefined): string[] {
  const t = (tier || '').toLowerCase()
  if (t === 'l1') return ['l2']
  if (t === 'l2') return ['l3', 'ir']
  if (t === 'l3') return ['ir']
  return []
}

async function fetchManualQueue(tier?: string): Promise<QueueListResponse> {
  const { data } = await api.get<QueueListResponse>('/alerts/review-queue/manual', {
    params: { limit: 100, page: 1, ...(tier ? { tier } : {}) },
  })
  return data
}

async function fetchUnmappedQueue(): Promise<QueueListResponse> {
  const { data } = await api.get<QueueListResponse>('/alerts/review-queue/unmapped?limit=100&page=1')
  return data
}

export function ReviewQueue() {
  const user = useAuthStore((s) => s.user)
  const showUnmapped = canSeeUnmappedQueue(user)
  const manualTabs = manualReviewTabs(user)
  const showManual = manualTabs.length > 0

  const [section, setSection] = useState<'manual' | 'unmapped'>(() =>
    showManual ? 'manual' : 'unmapped'
  )
  const [manualTierIdx, setManualTierIdx] = useState(0)

  useEffect(() => {
    if (section === 'unmapped' && !showUnmapped && showManual) setSection('manual')
    if (section === 'manual' && !showManual && showUnmapped) setSection('unmapped')
  }, [section, showManual, showUnmapped])

  const activeManualSpec = manualTabs[manualTierIdx] ?? manualTabs[0]
  const manualTierParam = activeManualSpec?.tier

  const manualQuery = useQuery({
    queryKey: ['review-queue', 'manual', manualTierParam ?? 'default'],
    queryFn: () => fetchManualQueue(manualTierParam),
    enabled: showManual,
    staleTime: 15_000,
  })

  const unmappedQuery = useQuery({
    queryKey: ['review-queue', 'unmapped'],
    queryFn: fetchUnmappedQueue,
    enabled: showUnmapped,
    staleTime: 15_000,
  })

  if (!showManual && !showUnmapped) {
    return (
      <div className="p-6">
        <h1 className="font-semibold text-2xl text-slate-900 mb-2">Review Queue</h1>
        <Card>
          <CardContent className="py-10 text-center text-slate-600">
            No review queues are assigned to your role.
          </CardContent>
        </Card>
      </div>
    )
  }

  const manualSection = (
    <>
      {manualTabs.length > 1 && (
        <div className="flex flex-wrap gap-2 mb-3">
          {manualTabs.map((tab, i) => (
            <Button
              key={`${tab.label}-${tab.tier ?? 'all'}`}
              type="button"
              variant={manualTierIdx === i ? 'default' : 'outline'}
              size="sm"
              onClick={() => setManualTierIdx(i)}
            >
              {tab.label}
              {manualQuery.data != null && manualTierIdx === i && (
                <span className="ml-1.5 font-mono text-xs opacity-80">({manualQuery.data.total})</span>
              )}
            </Button>
          ))}
        </div>
      )}
      <QueueSplit isLoading={manualQuery.isLoading} rows={manualQuery.data?.alerts ?? []} mode="manual" />
    </>
  )

  const unmappedSection = (
    <QueueSplit isLoading={unmappedQuery.isLoading} rows={unmappedQuery.data?.alerts ?? []} mode="unmapped" />
  )

  if (showManual && !showUnmapped) {
    return (
      <div className="flex flex-col h-[calc(100vh-8rem)]">
        <h1 className="font-semibold text-2xl text-slate-900 mb-4">Review Queue</h1>
        <div className="flex flex-col flex-1 min-h-0">{manualSection}</div>
      </div>
    )
  }

  if (!showManual && showUnmapped) {
    return (
      <div className="flex flex-col h-[calc(100vh-8rem)]">
        <h1 className="font-semibold text-2xl text-slate-900 mb-4">Review Queue</h1>
        <div className="flex flex-col flex-1 min-h-0">{unmappedSection}</div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]">
      <h1 className="font-semibold text-2xl text-slate-900 mb-4">Review Queue</h1>

      <Tabs
        value={section}
        onValueChange={(v) => setSection(v as 'manual' | 'unmapped')}
        className="flex flex-col flex-1 min-h-0 gap-4"
      >
        <TabsList className="w-fit">
          <TabsTrigger value="manual">Manual review</TabsTrigger>
          <TabsTrigger value="unmapped">Unmapped (MITRE)</TabsTrigger>
        </TabsList>

        <TabsContent value="manual" className="flex-1 flex flex-col min-h-0 mt-0 data-[state=inactive]:hidden">
          {manualSection}
        </TabsContent>

        <TabsContent value="unmapped" className="flex-1 flex flex-col min-h-0 mt-0 data-[state=inactive]:hidden">
          {unmappedSection}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function QueueSplit({
  isLoading,
  rows,
  mode,
}: {
  isLoading: boolean
  rows: QueueRow[]
  mode: 'manual' | 'unmapped'
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    if (!rows.length) {
      setSelectedId(null)
      return
    }
    setSelectedId((prev) => (prev && rows.some((a) => a.id === prev) ? prev : rows[0].id))
  }, [rows, mode])

  const selected = rows.find((r) => r.id === selectedId) ?? rows[0]
  const isUnmapped = mode === 'unmapped' || selected?.queue_kind === 'unmapped'

  return (
    <div className="flex-1 flex gap-4 min-h-0">
      <div className="w-[360px] shrink-0 flex flex-col border border-slate-200 rounded-xl bg-white overflow-hidden">
        <div className="p-2 border-b border-slate-100 text-xs text-slate-500">
          {mode === 'manual'
            ? 'Agentic MANUAL_REVIEW — Mongo incidents collection (tier matches your role).'
            : 'MITRE DLQ — assign technique and promote into alerts_processed.'}
        </div>
        <div className="flex-1 overflow-auto p-2 space-y-2">
          {isLoading && <p className="text-sm text-slate-500 p-4">Loading…</p>}
          {!isLoading && rows.length === 0 && (
            <p className="text-sm text-slate-500 p-4">No items in this queue.</p>
          )}
          {!isLoading &&
            rows.map((row) => (
              <button
                key={row.id}
                type="button"
                onClick={() => setSelectedId(row.id)}
                className={cn(
                  'w-full text-left p-3 rounded-lg border transition-colors',
                  selectedId === row.id
                    ? 'border-blue-500 border-l-4 bg-blue-50/50'
                    : 'border-slate-200 hover:bg-slate-50'
                )}
              >
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <SeverityBadge severity={row.severity as Severity} />
                  <span className="font-mono text-sm font-medium text-slate-900">{row.id}</span>
                  {row.final_tier && (
                    <span className="text-[10px] uppercase tracking-wide bg-slate-100 px-1.5 py-0.5 rounded text-slate-600">
                      {row.final_tier}
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-600 truncate">{row.description}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {row.source_siem} · {row.source_ip || '—'} · {formatRelativeTime(row.timestamp)}
                </p>
              </button>
            ))}
        </div>
      </div>

      <div className="flex-1 min-w-0 overflow-auto min-h-0">
        {selected ? (
          <DetailPanel row={selected} mode={mode} isUnmapped={isUnmapped} />
        ) : (
          <Card>
            <CardContent className="py-12 text-center text-slate-500">
              <p className="font-medium">Select an item</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}

function DetailPanel({
  row,
  mode,
  isUnmapped,
}: {
  row: QueueRow
  mode: 'manual' | 'unmapped'
  isUnmapped: boolean
}) {
  const [detailTab, setDetailTab] = useState('overview')
  const alertIdForIncident = row.alert_id || row.id
  const skipIncidentFetch = isUnmapped && mode === 'unmapped'
  const incidentQuery = useQuery({
    queryKey: ['incident', row.incident_id, alertIdForIncident, mode],
    queryFn: async () => {
      if (mode === 'manual' && row.incident_id) {
        const { data } = await api.get<{ incident: Record<string, unknown> }>(`/incidents/${row.incident_id}`)
        return data.incident
      }
      const { data } = await api.get<{ incident: Record<string, unknown> }>(
        `/incidents/by-alert/${encodeURIComponent(alertIdForIncident)}`
      )
      return data.incident
    },
    enabled:
      detailTab === 'incident' &&
      !skipIncidentFetch &&
      (mode === 'manual' ? Boolean(row.incident_id) : Boolean(alertIdForIncident)),
    retry: false,
  })

  return (
    <Card className="min-h-[320px]">
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div>
          <CardTitle className="text-base font-mono">{row.id}</CardTitle>
          {!isUnmapped && row.alert_id && (
            <Button size="sm" className="mt-2" asChild>
              <Link to={`/alerts/${row.alert_id}`}>Open in Alerts</Link>
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <Tabs value={detailTab} onValueChange={setDetailTab}>
          <TabsList className="mb-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="incident">Incident record</TabsTrigger>
          </TabsList>
          <TabsContent value="overview" className="space-y-4">
            {isUnmapped ? (
              <UnmappedOverview alertId={row.id} row={row} />
            ) : (
              <ManualOverview row={row} />
            )}
          </TabsContent>
          <TabsContent value="incident">
            <IncidentRecordTab query={incidentQuery} mode={mode} isUnmapped={isUnmapped} alertId={row.id} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

function IncidentRecordTab({
  query,
  mode,
  isUnmapped,
  alertId,
}: {
  query: ReturnType<typeof useQuery<Record<string, unknown>>>
  mode: string
  isUnmapped: boolean
  alertId: string
}) {
  if (isUnmapped && mode === 'unmapped') {
    return (
      <p className="text-sm text-slate-600">
        Unmapped DLQ items are not in the agentic <code className="font-mono text-xs">incidents</code> collection
        until the SOAR pipeline runs. After promote, use{' '}
        <Link className="text-blue-600 underline" to={`/alerts/${alertId}`}>
          Alerts
        </Link>{' '}
        for the processed document.
      </p>
    )
  }

  if (query.isLoading) return <p className="text-sm text-slate-500">Loading incident…</p>
  if (query.isError || !query.data) {
    return <p className="text-sm text-amber-800">No incident document found for this item.</p>
  }
  return (
    <pre className="text-xs bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-auto max-h-[480px] font-mono">
      {JSON.stringify(query.data, null, 2)}
    </pre>
  )
}

function ManualOverview({ row }: { row: QueueRow }) {
  const qc = useQueryClient()
  const [escTo, setEscTo] = useState<string>('')
  const [alertJson, setAlertJson] = useState('')
  const [notes, setNotes] = useState('')

  const incidentId = row.incident_id
  const targets = useMemo(() => escalationTargets(row.final_tier), [row.final_tier])

  const { data: incidentDoc } = useQuery({
    queryKey: ['incident-prefetch', incidentId],
    queryFn: async () => {
      if (!incidentId) return null
      const { data } = await api.get<{ incident: Record<string, unknown> }>(`/incidents/${incidentId}`)
      return data.incident
    },
    enabled: Boolean(incidentId),
  })

  useEffect(() => {
    const a = incidentDoc?.alert
    if (a && typeof a === 'object') {
      setAlertJson(JSON.stringify(a, null, 2))
    }
  }, [incidentDoc])

  const escalateMut = useMutation({
    mutationFn: async () => {
      if (!incidentId || !escTo) return
      await api.post(`/incidents/${incidentId}/escalate`, { to_tier: escTo })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['review-queue', 'manual'] })
      qc.invalidateQueries({ queryKey: ['incident-prefetch', incidentId] })
      qc.invalidateQueries({ queryKey: ['alerts', 'sidebar-counts'] })
    },
  })

  const saveMut = useMutation({
    mutationFn: async () => {
      if (!incidentId) throw new Error('No incident')
      let patch: Record<string, unknown> | undefined
      try {
        patch = alertJson.trim() ? (JSON.parse(alertJson) as Record<string, unknown>) : undefined
      } catch {
        throw new Error('Invalid JSON in alert patch')
      }
      await api.patch(`/incidents/${incidentId}`, {
        alert_patch: patch,
        analyst_notes: notes.trim() || undefined,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-prefetch', incidentId] })
    },
  })

  if (!incidentId) {
    return <p className="text-sm text-slate-600">Missing incident_id on this queue row.</p>
  }

  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className="text-slate-700">{row.description}</p>
        {row.decision_reason && (
          <p className="mt-2 text-slate-600">
            <span className="font-medium">Decision reason:</span> {row.decision_reason}
          </p>
        )}
      </div>

      {targets.length > 0 && (
        <div className="rounded-lg border border-slate-200 p-3 space-y-2">
          <p className="font-medium text-slate-800">Escalate tier</p>
          <div className="flex flex-wrap items-center gap-2">
            <Select value={escTo} onValueChange={setEscTo}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Select target tier" />
              </SelectTrigger>
              <SelectContent>
                {targets.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t.toUpperCase()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              disabled={!escTo || escalateMut.isPending}
              onClick={() => escalateMut.mutate()}
            >
              Escalate
            </Button>
          </div>
          {escalateMut.isError && (
            <p className="text-xs text-red-600">{(escalateMut.error as Error)?.message || 'Escalation failed'}</p>
          )}
        </div>
      )}

      <div className="rounded-lg border border-slate-200 p-3 space-y-2">
        <p className="font-medium text-slate-800">Edit embedded alert (JSON merge)</p>
        <Textarea
          value={alertJson}
          onChange={(e) => setAlertJson(e.target.value)}
          className="font-mono text-xs min-h-[160px]"
          placeholder="{}"
        />
        <Input
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Analyst notes (optional)"
          className="text-sm"
        />
        <Button size="sm" disabled={saveMut.isPending} onClick={() => saveMut.mutate()}>
          Save changes
        </Button>
        {saveMut.isError && (
          <p className="text-xs text-red-600">{(saveMut.error as Error)?.message || 'Save failed'}</p>
        )}
      </div>
    </div>
  )
}

function UnmappedOverview({ alertId, row }: { alertId: string; row: QueueRow }) {
  const qc = useQueryClient()
  const detail = useQuery({
    queryKey: ['unmapped-detail', alertId],
    queryFn: async () => {
      const { data } = await api.get<{ unmapped: Record<string, unknown> }>(`/alerts/unmapped/${encodeURIComponent(alertId)}`)
      return data.unmapped
    },
  })

  const [techniqueId, setTechniqueId] = useState('')
  const [tacticId, setTacticId] = useState('')
  const [tacticName, setTacticName] = useState('')

  const promoteMut = useMutation({
    mutationFn: async () => {
      await api.post(`/alerts/unmapped/${encodeURIComponent(alertId)}/promote`, {
        technique_id: techniqueId.trim(),
        tactic_id: tacticId.trim() || undefined,
        tactic_name: tacticName.trim() || undefined,
        technique_confidence: 0.95,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['review-queue', 'unmapped'] })
      qc.invalidateQueries({ queryKey: ['alerts', 'sidebar-counts'] })
      qc.invalidateQueries({ queryKey: ['unmapped-detail', alertId] })
    },
  })

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-amber-50 border border-amber-100 p-3 text-sm text-slate-800 space-y-1">
        <p>
          <span className="font-medium">DLQ reason:</span> {String(row.dlq_reason ?? '—')}
        </p>
        <p>
          <span className="font-medium">Mapping method:</span> {String(row.mapping_method ?? '—')}
        </p>
      </div>

      {detail.isLoading && <p className="text-sm text-slate-500">Loading DLQ document…</p>}
      {detail.data && (
        <pre className="text-xs bg-slate-50 border rounded-lg p-3 max-h-56 overflow-auto font-mono">
          {JSON.stringify(detail.data, null, 2)}
        </pre>
      )}

      <div className="rounded-lg border border-slate-200 p-3 space-y-3">
        <p className="font-medium text-slate-800">Promote to alerts_processed</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <div>
            <label className="text-xs text-slate-500">MITRE technique_id *</label>
            <Input value={techniqueId} onChange={(e) => setTechniqueId(e.target.value)} placeholder="T1059" />
          </div>
          <div>
            <label className="text-xs text-slate-500">tactic_id</label>
            <Input value={tacticId} onChange={(e) => setTacticId(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs text-slate-500">tactic_name</label>
            <Input value={tacticName} onChange={(e) => setTacticName(e.target.value)} />
          </div>
        </div>
        <Button
          disabled={!techniqueId.trim() || promoteMut.isPending}
          onClick={() => promoteMut.mutate()}
        >
          Promote to processed alerts
        </Button>
        {promoteMut.isError && (
          <p className="text-xs text-red-600">
            {(promoteMut.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
              'Promote failed'}
          </p>
        )}
        {promoteMut.isSuccess && <p className="text-xs text-green-700">Promoted. Alert is in alerts_processed.</p>}
      </div>
    </div>
  )
}
