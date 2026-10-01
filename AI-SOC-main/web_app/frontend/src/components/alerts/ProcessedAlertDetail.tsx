import { Link } from 'react-router-dom'
import { ChevronDown, ChevronUp, Cpu, FileJson } from 'lucide-react'
import { useMemo, useState } from 'react'
import { AlertFeedbackPanel } from '@/components/alerts/AlertFeedbackPanel'
import { useIncidentForAlert } from '@/hooks/useIncidentForAlert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/SeverityBadge'
import { formatRelativeTime, getStatusLabel } from '@/lib/utils'
import type { Severity } from '@/lib/utils'
import type { AlertStatus } from '@/lib/utils'
import type { AlertListItem, ProcessedAlertDetailResponse } from '@/types/alertApi'

function JsonBlock({ value, className = '' }: { value: unknown; className?: string }) {
  return (
    <pre
      className={`bg-slate-950 text-slate-100 font-mono text-xs rounded-lg p-4 overflow-auto max-h-96 ${className}`}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

function KeyVal({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="text-sm">
      <span className="text-slate-500">{label}</span>
      <div className="text-slate-900 mt-0.5 break-words">{children}</div>
    </div>
  )
}

export function ProcessedAlertDetail({
  data,
  similarAlerts,
}: {
  data: ProcessedAlertDetailResponse
  similarAlerts: AlertListItem[]
}) {
  const s = data.summary
  const [rawOpen, setRawOpen] = useState(false)
  const [tiOpen, setTiOpen] = useState(true)
  const [mlReportOpen, setMlReportOpen] = useState(false)
  const [incidentJsonOpen, setIncidentJsonOpen] = useState(false)

  const incidentQuery = useIncidentForAlert(s.id)
  const incident = incidentQuery.data
  const mlOutputs = incident?.ml_outputs as Record<string, unknown> | undefined
  const hasMlPayload = mlOutputs != null && typeof mlOutputs === 'object' && Object.keys(mlOutputs).length > 0

  const feedbackAlertId = s.id || data.list_row?.id

  const mitre = data.enrichments?.mitre as Record<string, unknown> | undefined
  const ti = data.enrichments?.threat_intel as Record<string, unknown> | undefined
  const perIndicator = useMemo(() => {
    const pi = ti?.per_indicator
    if (!pi || typeof pi !== 'object') return []
    return Object.entries(pi as Record<string, unknown>).slice(0, 12)
  }, [ti])

  const src = data.endpoints?.src as Record<string, string | number | null> | null
  const dst = data.endpoints?.dst as Record<string, string | number | null> | null

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/alerts" className="gap-1">
            ← Back to Alerts
          </Link>
        </Button>
        <span className="font-mono font-semibold text-slate-900">{s.id}</span>
        <SeverityBadge severity={s.severity as Severity} />
        <span
          className={`text-xs px-2 py-1 rounded border ${
            s.status === 'new' ? 'text-purple-700 bg-purple-50 border-purple-200' : 'text-slate-600 bg-slate-100'
          }`}
        >
          {getStatusLabel(s.status as AlertStatus)}
        </span>
        {s.processing_status && (
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600">
            {String(s.processing_status)}
          </span>
        )}
      </div>

      <p className="text-slate-700 text-sm leading-relaxed max-w-4xl">{s.description}</p>
      <p className="text-xs text-slate-500">
        <span className="font-medium text-slate-600">{s.display_source}</span>
        {s.siem_source && s.siem_source !== s.display_source && (
          <span className="ml-2">· SIEM field: {s.siem_source}</span>
        )}
        {s.timestamp && (
          <span className="ml-2">
            · Event {formatRelativeTime(s.timestamp)} ({new Date(s.timestamp).toUTCString()})
          </span>
        )}
      </p>

      <div className="grid lg:grid-cols-[1fr_minmax(300px,420px)] gap-6">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Overview</CardTitle>
            </CardHeader>
            <CardContent className="grid sm:grid-cols-2 gap-4">
              <KeyVal label="Category">{s.category_name ?? '—'}</KeyVal>
              <KeyVal label="Class">{s.class_name ?? '—'}</KeyVal>
              <KeyVal label="Activity">{s.activity_name ?? '—'}</KeyVal>
              <KeyVal label="Source alert ID">
                {s.source_alert_id ? <span className="font-mono">{s.source_alert_id}</span> : '—'}
              </KeyVal>
              <KeyVal label="Severity (OCSF)">
                {s.severity_label ?? '—'} (id {s.severity_id ?? '—'})
              </KeyVal>
              <KeyVal label="Ingested">{s.ingestion_timestamp ? formatRelativeTime(s.ingestion_timestamp) : '—'}</KeyVal>
              <KeyVal label="Processed">{s.processed_at ? formatRelativeTime(s.processed_at) : '—'}</KeyVal>
              {data.file && Object.keys(data.file).length > 0 && (
                <KeyVal label="File / path">
                  <span className="font-mono text-xs">
                    {String((data.file as { path?: string }).path ?? JSON.stringify(data.file))}
                  </span>
                </KeyVal>
              )}
            </CardContent>
          </Card>

          {feedbackAlertId ? <AlertFeedbackPanel alertId={feedbackAlertId} /> : null}

          <Card>
            <CardHeader>
              <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Endpoints</CardTitle>
            </CardHeader>
            <CardContent className="grid sm:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-slate-500">Source</span>
                <div className="font-mono text-xs mt-1 space-y-0.5">
                  <div>IP: {src?.ip ?? '—'}</div>
                  <div>Port: {src?.port ?? '—'}</div>
                  <div>Host: {src?.hostname ?? '—'}</div>
                </div>
              </div>
              <div>
                <span className="text-slate-500">Destination</span>
                <div className="font-mono text-xs mt-1 space-y-0.5">
                  <div>IP: {dst?.ip ?? '—'}</div>
                  <div>Port: {dst?.port ?? '—'}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {data.finding && Object.keys(data.finding).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Finding</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <KeyVal label="Title">{String((data.finding as { title?: string }).title ?? '—')}</KeyVal>
                <KeyVal label="UID">
                  <span className="font-mono text-xs">
                    {String((data.finding as { uid?: string }).uid ?? '—')}
                  </span>
                </KeyVal>
                {(data.finding as { desc?: string }).desc && (
                  <KeyVal label="Description">{(data.finding as { desc: string }).desc}</KeyVal>
                )}
              </CardContent>
            </Card>
          )}

          {data.asset && Object.keys(data.asset).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Asset</CardTitle>
              </CardHeader>
              <CardContent>
                <JsonBlock value={data.asset} className="max-h-56" />
              </CardContent>
            </Card>
          )}

          {data.asset_risk && Object.keys(data.asset_risk).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Asset risk</CardTitle>
              </CardHeader>
              <CardContent className="text-sm">
                <JsonBlock value={data.asset_risk} className="max-h-40" />
              </CardContent>
            </Card>
          )}

          {mitre && Object.keys(mitre).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">{`MITRE ATT&CK`}</CardTitle>
              </CardHeader>
              <CardContent className="grid sm:grid-cols-2 gap-3 text-sm">
                <KeyVal label="Tactic">
                  {String(mitre.tactic_name ?? '—')} ({String(mitre.tactic_id ?? '')})
                </KeyVal>
                <KeyVal label="Technique">
                  {String(mitre.technique_name ?? '—')} ({String(mitre.technique_id ?? '')})
                </KeyVal>
                {Boolean(mitre.subtechnique_name) && (
                  <KeyVal label="Sub-technique">
                    {String(mitre.subtechnique_name)} ({String(mitre.subtechnique_id ?? '')})
                  </KeyVal>
                )}
                <KeyVal label="Confidence">
                  {typeof mitre.technique_confidence === 'number'
                    ? `${(mitre.technique_confidence * 100).toFixed(1)}%`
                    : '—'}
                </KeyVal>
                {Array.isArray(mitre.platforms) && mitre.platforms.length > 0 && (
                  <KeyVal label="Platforms">{mitre.platforms.join(', ')}</KeyVal>
                )}
              </CardContent>
            </Card>
          )}

          {ti && Object.keys(ti).length > 0 && (
            <Card>
              <button
                type="button"
                className="w-full flex items-center justify-between p-4 text-left"
                onClick={() => setTiOpen((o) => !o)}
              >
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">
                  Threat intelligence
                </CardTitle>
                {tiOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {tiOpen && (
                <CardContent className="space-y-4 pt-0">
                  <div className="flex flex-wrap gap-4 text-sm">
                    <KeyVal label="Aggregate score">
                      {typeof ti.aggregate_score === 'number' ? ti.aggregate_score.toFixed(3) : '—'}
                    </KeyVal>
                    <KeyVal label="Malicious (enrichment)">
                      {String(ti.is_malicious ?? '—')}
                    </KeyVal>
                    <KeyVal label="Malicious indicators">
                      {String(ti.malicious_indicator_count ?? '—')}
                    </KeyVal>
                  </div>
                  {ti.geolocation_summary != null &&
                    typeof ti.geolocation_summary === 'object' &&
                    !Array.isArray(ti.geolocation_summary) && (
                    <div>
                      <p className="text-xs font-medium text-slate-500 mb-1">Geolocation (primary)</p>
                      <JsonBlock value={ti.geolocation_summary} className="max-h-40" />
                    </div>
                  )}
                  {ti.infrastructure_summary != null &&
                    typeof ti.infrastructure_summary === 'object' &&
                    !Array.isArray(ti.infrastructure_summary) && (
                    <div>
                      <p className="text-xs font-medium text-slate-500 mb-1">Infrastructure</p>
                      <JsonBlock value={ti.infrastructure_summary} className="max-h-40" />
                    </div>
                  )}
                  {perIndicator.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-slate-500 mb-2">Indicators (sample)</p>
                      <div className="rounded-lg border border-slate-200 overflow-hidden text-xs">
                        <table className="w-full">
                          <thead className="bg-slate-50 text-slate-600">
                            <tr>
                              <th className="text-left p-2 font-medium">IOC</th>
                              <th className="text-left p-2 font-medium">Score</th>
                              <th className="text-left p-2 font-medium">Malicious</th>
                            </tr>
                          </thead>
                          <tbody>
                            {perIndicator.map(([key, val]) => {
                              const row = val as Record<string, unknown>
                              const score = row.indicator_score
                              const mal = row.is_malicious
                              return (
                                <tr key={key} className="border-t border-slate-100">
                                  <td className="p-2 font-mono break-all">{key}</td>
                                  <td className="p-2 font-mono">
                                    {typeof score === 'number' ? score.toFixed(3) : '—'}
                                  </td>
                                  <td className="p-2">{String(mal ?? '—')}</td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          )}

          {data.correlation && Object.keys(data.correlation).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Correlation</CardTitle>
              </CardHeader>
              <CardContent>
                <JsonBlock value={data.correlation} className="max-h-48" />
              </CardContent>
            </Card>
          )}

          {data.metadata && Object.keys(data.metadata).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Metadata</CardTitle>
              </CardHeader>
              <CardContent>
                <JsonBlock value={data.metadata} className="max-h-56" />
              </CardContent>
            </Card>
          )}

          {data.unmapped && Object.keys(data.unmapped).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Unmapped / notes</CardTitle>
              </CardHeader>
              <CardContent>
                <JsonBlock value={data.unmapped} className="max-h-48" />
              </CardContent>
            </Card>
          )}

          {data.raw_data && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Original raw payload (string)</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="bg-slate-950 text-green-400 font-mono text-xs rounded-lg p-4 overflow-auto max-h-72 whitespace-pre-wrap break-all">
                  {data.raw_data}
                </pre>
              </CardContent>
            </Card>
          )}

          <Card>
            <button
              type="button"
              className="w-full flex items-center justify-between p-4 text-left"
              onClick={() => setRawOpen((e) => !e)}
            >
              <CardTitle className="text-sm uppercase tracking-wider text-slate-500">
                Full normalised document (JSON)
              </CardTitle>
              {rawOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            {rawOpen && (
              <CardContent className="pt-0">
                <JsonBlock value={data.raw} />
              </CardContent>
            )}
          </Card>
        </div>

        <div className="space-y-4 lg:sticky lg:top-4 lg:self-start">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm uppercase tracking-wider text-slate-500 flex items-center gap-2">
                <Cpu className="h-4 w-4 text-slate-400" />
                SOAR incident
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {incidentQuery.isPending && (
                <p className="text-slate-500 text-xs">Loading incident…</p>
              )}
              {incidentQuery.isError && (
                <p className="text-amber-800 text-xs">
                  Could not load incident (try again). Alert detail above is unchanged.
                </p>
              )}
              {incidentQuery.isSuccess && !incident && (
                <p className="text-slate-600 text-xs leading-relaxed">
                  No agentic incident is stored for this alert yet. Incidents appear after the SOAR pipeline runs
                  and persists to Mongo <code className="font-mono text-[11px]">incidents</code>.
                </p>
              )}
              {incident && (
                <>
                  <div className="space-y-1.5 text-xs">
                    <KeyVal label="incident_id">
                      <span className="font-mono">{String(incident.incident_id ?? '—')}</span>
                    </KeyVal>
                    <KeyVal label="Decision">{String(incident.decision ?? '—')}</KeyVal>
                    <KeyVal label="Tier">{String(incident.final_tier ?? '—')}</KeyVal>
                    {incident.triage_score != null && (
                      <KeyVal label="Triage score">{String(incident.triage_score)}</KeyVal>
                    )}
                    {incident.priority != null && (
                      <KeyVal label="Priority">{String(incident.priority)}</KeyVal>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <Button
                      type="button"
                      variant={mlReportOpen ? 'secondary' : 'outline'}
                      size="sm"
                      className="text-xs h-8"
                      onClick={() => setMlReportOpen((o) => !o)}
                    >
                      {mlReportOpen ? 'Hide ML report' : 'Show ML report'}
                    </Button>
                    <Button
                      type="button"
                      variant={incidentJsonOpen ? 'secondary' : 'outline'}
                      size="sm"
                      className="text-xs h-8 gap-1"
                      onClick={() => setIncidentJsonOpen((o) => !o)}
                    >
                      <FileJson className="h-3.5 w-3.5" />
                      {incidentJsonOpen ? 'Hide full incident' : 'Full incident JSON'}
                    </Button>
                  </div>
                  {mlReportOpen && (
                    <div className="pt-1">
                      {hasMlPayload ? (
                        <JsonBlock value={mlOutputs} className="max-h-[min(70vh,520px)]" />
                      ) : (
                        <p className="text-xs text-slate-500">This incident has no `ml_outputs` payload.</p>
                      )}
                    </div>
                  )}
                  {incidentJsonOpen && (
                    <div className="pt-1">
                      <JsonBlock value={incident} className="max-h-[min(70vh,520px)]" />
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Quick stats</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-slate-600">
              <div className="flex justify-between">
                <span>TI confidence (list)</span>
                <span className="font-mono">{Math.round((data.list_row.confidence ?? 0) * 100)}%</span>
              </div>
              <div className="flex justify-between">
                <span>MTTD (est.)</span>
                <span className="font-mono">
                  {data.list_row.mttd_minutes != null ? `${data.list_row.mttd_minutes} min` : '—'}
                </span>
              </div>
            </CardContent>
          </Card>

          {similarAlerts.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Related alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {similarAlerts.map((a) => (
                    <li key={a.id} className="flex flex-col gap-1 text-sm border-b border-slate-100 pb-2 last:border-0">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={a.severity as Severity} />
                        <Link
                          to={`/alerts/${encodeURIComponent(a.id)}`}
                          className="font-mono text-blue-600 hover:underline text-xs"
                        >
                          {a.id}
                        </Link>
                      </div>
                      <span className="text-slate-500 truncate text-xs">{a.description.slice(0, 80)}…</span>
                      <span className="text-xs text-slate-400">{formatRelativeTime(a.timestamp)}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
