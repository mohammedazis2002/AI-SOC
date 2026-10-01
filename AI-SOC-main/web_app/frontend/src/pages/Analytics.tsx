import { useMemo, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  Legend,
  ReferenceLine,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { useAnalyticsSummary } from '@/hooks/useAnalyticsSummary'

function rangeToDays(range: string): number {
  if (range === '7d') return 7
  if (range === '90d') return 90
  return 30
}

export function Analytics() {
  const [range, setRange] = useState('30d')
  const days = useMemo(() => rangeToDays(range), [range])
  const { data, isLoading, isError, error } = useAnalyticsSummary(days)

  const volume = data?.volumeByDay ?? []
  const mttdMttr = data?.mttdMttrTrend ?? []
  const autoManual = data?.autoVsManual ?? []
  const fpSeries = data?.fpRateByDay ?? []
  const overrideSeries = data?.overrideRateByDay ?? []
  const confidence = data?.confidenceDistribution ?? []
  const topTypes = data?.topAlertTypes ?? []
  const typeMax = data?.topAlertTypesMax ?? 1
  const countries = data?.topCountries ?? []
  const countryMax = data?.topCountriesMax ?? 1

  if (isError) {
    return (
      <div className="space-y-4">
        <h1 className="font-semibold text-2xl text-slate-900">Analytics</h1>
        <Card>
          <CardContent className="py-8 text-center text-sm text-red-600">
            {(error as Error)?.message ?? 'Failed to load analytics.'}
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="font-semibold text-2xl text-slate-900">Analytics</h1>
        <div className="flex gap-2">
          <select
            className="h-9 rounded-lg border border-slate-200 px-3 text-sm bg-white"
            value={range}
            onChange={(e) => setRange(e.target.value)}
            disabled={isLoading}
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>
          <Button variant="outline" size="sm" disabled>
            ↓ Export
          </Button>
        </div>
      </div>

      <div>
        <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">Alert Volume</h2>
        <Card>
          <CardContent className="pt-4">
            <div className="h-64">
              {isLoading ? (
                <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={volume}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                    <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                    <YAxis tick={{ fontSize: 11 }} />
                    <Tooltip />
                    <Area type="monotone" dataKey="critical" stackId="1" fill="#dc2626" stroke="#dc2626" fillOpacity={0.7} />
                    <Area type="monotone" dataKey="high" stackId="1" fill="#ea580c" stroke="#ea580c" fillOpacity={0.7} />
                    <Area type="monotone" dataKey="medium" stackId="1" fill="#d97706" stroke="#d97706" fillOpacity={0.7} />
                    <Area type="monotone" dataKey="low" stackId="1" fill="#2563eb" stroke="#2563eb" fillOpacity={0.7} />
                    <Area type="monotone" dataKey="info" stackId="1" fill="#94a3b8" stroke="#94a3b8" fillOpacity={0.6} name="Info" />
                    <Legend />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="grid grid-cols-3 gap-4 mt-4">
              <div className="text-center p-2 rounded-lg bg-slate-50">
                <div className="text-2xl font-semibold font-mono">
                  {isLoading ? '—' : data?.volumeSummary.periodTotal ?? 0}
                </div>
                <div className="text-xs text-slate-500">Total this period</div>
              </div>
              <div className="text-center p-2 rounded-lg bg-slate-50">
                <div className="text-2xl font-semibold font-mono">
                  {isLoading ? '—' : data?.volumeSummary.peakDay ?? 0}
                </div>
                <div className="text-xs text-slate-500">Peak day</div>
              </div>
              <div className="text-center p-2 rounded-lg bg-slate-50">
                <div className="text-2xl font-semibold font-mono">
                  {isLoading ? '—' : data?.volumeSummary.avgPerDay ?? 0}
                </div>
                <div className="text-xs text-slate-500">Avg per day</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div>
          <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">
            MTTR trend (min); MTTD not yet measured
          </h2>
          <Card>
            <CardContent className="pt-4">
              <div className="h-48">
                {isLoading ? (
                  <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={mttdMttr}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                      <YAxis tick={{ fontSize: 10 }} />
                      <Tooltip />
                      <Legend />
                      <Line type="monotone" dataKey="mttr" name="MTTR" stroke="#2563eb" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="text-sm text-slate-500 mt-2 flex flex-wrap gap-4">
                <span>
                  Current MTTD avg:{' '}
                  <span className="font-mono font-medium text-slate-700">
                    {data?.mttdTbd ? 'TBD' : `${data?.currentMttdAvgMinutes ?? '—'} min`}
                  </span>
                </span>
                <span>
                  Current MTTR avg:{' '}
                  <span className="font-mono font-medium text-slate-700">
                    {isLoading ? '—' : `${data?.currentMttrAvgMinutes ?? 0} min`}
                  </span>
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
        <div>
          <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">Auto-resolved vs Manual</h2>
          <Card>
            <CardContent className="pt-4">
              <div className="h-48">
                {isLoading ? (
                  <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={autoManual} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                      <YAxis tick={{ fontSize: 10 }} domain={[0, 100]} />
                      <Tooltip />
                      <Bar dataKey="auto" stackId="a" fill="#16a34a" name="Auto %" />
                      <Bar dataKey="manual" stackId="a" fill="#64748b" name="Manual %" />
                      <Legend />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="text-sm text-slate-500 mt-2">
                Auto-resolve rate:{' '}
                <span className="font-mono font-medium text-slate-700">
                  {isLoading ? '—' : `${data?.autoResolvePct ?? 0}%`}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div>
          <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">False Positive Rate (target 5%)</h2>
          <Card>
            <CardContent className="pt-4">
              <div className="h-48">
                {isLoading ? (
                  <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={fpSeries}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                      <YAxis tick={{ fontSize: 10 }} domain={[0, 'auto']} />
                      <Tooltip />
                      <ReferenceLine y={5} stroke="#16a34a" strokeDasharray="4 4" strokeWidth={1} label={{ value: '5%', position: 'right', fontSize: 10 }} />
                      <Line type="monotone" dataKey="fpRate" stroke="#dc2626" strokeWidth={2} dot={false} name="FP Rate %" />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="text-sm text-slate-500 mt-2">
                Current FP rate (rolling 7d of series):{' '}
                <span className="font-mono font-medium text-slate-700">
                  {isLoading ? '—' : `${data?.currentFpRatePct ?? 0}%`}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>
        <div>
          <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">Analyst Override Rate</h2>
          <Card>
            <CardContent className="pt-4">
              {!isLoading && !data?.overrideAvailable ? (
                <div className="h-48 flex items-center justify-center text-sm text-slate-500 text-center px-4">
                  Override telemetry is not available yet. When analysts override model decisions, rates will appear here.
                </div>
              ) : isLoading ? (
                <div className="h-48 flex items-center justify-center text-sm text-slate-500">Loading…</div>
              ) : (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={overrideSeries.filter((d) => d.rate != null)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                      <YAxis tick={{ fontSize: 10 }} />
                      <Tooltip />
                      <Bar dataKey="rate" fill="#d97706" name="Override %" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
              <div className="text-sm text-slate-500 mt-2">
                {!data?.overrideAvailable ? (
                  <span className="font-mono font-medium text-slate-500">—</span>
                ) : (
                  <span>
                    Override rate:{' '}
                    <span className="font-mono font-medium text-slate-700">see chart</span>
                  </span>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div>
        <h2 className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">Confidence Score Distribution</h2>
        <Card>
          <CardContent className="pt-4">
            <div className="h-48">
              {isLoading ? (
                <div className="h-full flex items-center justify-center text-sm text-slate-500">Loading…</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={confidence} layout="vertical" margin={{ left: 50 }}>
                    <XAxis type="number" tick={{ fontSize: 10 }} />
                    <YAxis type="category" dataKey="range" tick={{ fontSize: 10 }} width={50} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#2563eb" name="Alerts" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Top 10 Alert Types</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="py-8 text-center text-sm text-slate-500">Loading…</div>
            ) : topTypes.length === 0 ? (
              <div className="py-8 text-center text-sm text-slate-500">No alert type breakdown for this period.</div>
            ) : (
              <div className="space-y-2">
                {topTypes.map((row, i) => (
                  <div key={`${row.name}-${i}`} className="flex items-center gap-2">
                    <span className="text-slate-500 w-6">{i + 1}.</span>
                    <div className="flex-1 flex items-center gap-2">
                      <div className="flex-1 bg-slate-100 rounded h-6 overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded"
                          style={{ width: `${Math.min(100, (row.count / typeMax) * 100)}%` }}
                        />
                      </div>
                      <span className="font-mono text-sm w-12 text-right">{row.count}</span>
                    </div>
                    <span className="text-sm text-slate-700 truncate max-w-[140px]" title={row.name}>
                      {row.name}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm uppercase tracking-wider text-slate-500">Top Source Countries</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="py-8 text-center text-sm text-slate-500">Loading…</div>
            ) : countries.length === 0 ? (
              <div className="py-8 text-center text-sm text-slate-500">No geolocation data for this period.</div>
            ) : (
              <ul className="space-y-2">
                {countries.map((c) => (
                  <li key={c.country} className="flex items-center gap-3">
                    <span className="text-sm text-slate-700 flex-1">{c.country}</span>
                    <span className="font-mono text-sm text-slate-600">{c.count}</span>
                    <div className="w-20 bg-slate-100 rounded h-2 overflow-hidden">
                      <div
                        className="h-full bg-slate-500 rounded"
                        style={{ width: `${Math.min(100, (c.count / countryMax) * 100)}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
