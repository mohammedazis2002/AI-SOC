import { useMemo, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { useAppStore } from '@/store/useAppStore'
import axios from 'axios'
import {
  issueWazuhClientCert,
  renewWazuhClientCert,
  revokeClientCert,
} from '@/lib/mtls-certs-api'

function formatCertApiError(e: unknown): string {
  if (axios.isAxiosError(e) && e.response?.data != null) {
    const d = e.response.data as { detail?: unknown }
    if (typeof d.detail === 'string') return d.detail
    if (Array.isArray(d.detail)) return JSON.stringify(d.detail)
    if (d.detail != null) return String(d.detail)
  }
  return e instanceof Error ? e.message : String(e)
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function pickString(obj: Record<string, unknown>, key: string): string | null {
  const v = obj[key]
  return typeof v === 'string' ? v : null
}

function pickStringArray(obj: Record<string, unknown>, key: string): string[] {
  const v = obj[key]
  if (!Array.isArray(v)) return []
  return v.filter((x) => typeof x === 'string') as string[]
}

export function CertificateManager() {
  const addNotification = useAppStore((s) => s.addNotification)
  const [commonName, setCommonName] = useState('wazuh-manager.local')
  const [ttl, setTtl] = useState('720h')
  const [serial, setSerial] = useState('')

  const issue = useMutation({
    mutationFn: () => issueWazuhClientCert({ common_name: commonName, ttl: ttl || undefined }),
    onSuccess: () => addNotification({ type: 'success', message: 'Certificate issued.' }),
    onError: (e) =>
      addNotification({ type: 'error', message: `Issue failed: ${formatCertApiError(e)}` }),
  })
  const renew = useMutation({
    mutationFn: () => renewWazuhClientCert({ common_name: commonName, ttl: ttl || undefined }),
    onSuccess: () => addNotification({ type: 'success', message: 'Certificate renewed.' }),
    onError: (e) =>
      addNotification({ type: 'error', message: `Renew failed: ${formatCertApiError(e)}` }),
  })
  const revoke = useMutation({
    mutationFn: () => revokeClientCert({ serial_number: serial }),
    onSuccess: () => addNotification({ type: 'success', message: 'Certificate revoked.' }),
    onError: (e) =>
      addNotification({ type: 'error', message: `Revoke failed: ${formatCertApiError(e)}` }),
  })

  const last = (issue.data ?? renew.data) as Record<string, unknown> | undefined
  const cert = useMemo(() => (last ? pickString(last, 'certificate') : null), [last])
  const key = useMemo(() => (last ? pickString(last, 'private_key') : null), [last])
  const chainList = useMemo(() => (last ? pickStringArray(last, 'ca_chain') : []), [last])
  const chainPem = useMemo(() => (chainList.length ? `${chainList.join('\n')}\n` : null), [chainList])
  const serialNumber = useMemo(() => (last ? pickString(last, 'serial_number') : null), [last])

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Client Certificates (Wazuh)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 max-w-2xl">
          <p className="text-sm text-slate-600">
            Issues/renews Wazuh client certs via the mTLS service (Vault PKI). Use the generated
            <span className="font-mono px-1">certificate</span> and <span className="font-mono px-1">private_key</span> on the Wazuh manager.
            Common Name must be <span className="font-mono">wazuh-manager.local</span>,{' '}
            <span className="font-mono">wazuh.internal</span>, or a subdomain of those. If you see connection errors
            while running the API on your machine, set <span className="font-mono">MTLS_CERT_API_URL</span> to a URL
            that reaches the certificate API (e.g. <span className="font-mono">https://127.0.0.1:8444/api/v1/certificates</span> when Docker maps host 8444 to the mTLS service).
          </p>

          <div className="grid sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="text-sm font-medium text-slate-700 block mb-1">Common Name</label>
              <Input value={commonName} onChange={(e) => setCommonName(e.target.value)} />
            </div>
            <div>
              <label className="text-sm font-medium text-slate-700 block mb-1">TTL</label>
              <Input value={ttl} onChange={(e) => setTtl(e.target.value)} placeholder="720h" />
            </div>
          </div>

          <div className="flex gap-2 flex-wrap">
            <Button onClick={() => issue.mutate()} disabled={issue.isPending || renew.isPending}>
              Issue
            </Button>
            <Button variant="outline" onClick={() => renew.mutate()} disabled={renew.isPending || issue.isPending}>
              Renew
            </Button>
          </div>

          {last && (
            <div className="rounded-lg border border-slate-200 p-3 space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="text-sm text-slate-700">
                  <span className="font-medium">Serial</span>{' '}
                  <span className="font-mono text-xs">{serialNumber ?? '—'}</span>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {cert && (
                    <Button size="sm" variant="secondary" onClick={() => downloadText(`${commonName}.crt.pem`, cert)}>
                      Download cert
                    </Button>
                  )}
                  {key && (
                    <Button size="sm" variant="secondary" onClick={() => downloadText(`${commonName}.key.pem`, key)}>
                      Download key
                    </Button>
                  )}
                  {chainPem && (
                    <Button size="sm" variant="secondary" onClick={() => downloadText(`ca_chain.pem`, chainPem)}>
                      Download CA chain
                    </Button>
                  )}
                </div>
              </div>
              <details>
                <summary className="text-xs text-slate-500 cursor-pointer select-none">Show PEM</summary>
                <pre className="mt-2 bg-slate-950 text-slate-100 font-mono text-xs rounded-lg p-3 overflow-auto max-h-64">
                  {JSON.stringify(last, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Revoke certificate</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 max-w-2xl">
          <div>
            <label className="text-sm font-medium text-slate-700 block mb-1">Serial number</label>
            <Input value={serial} onChange={(e) => setSerial(e.target.value)} placeholder="e.g. 3a:bf:..." />
          </div>
          <Button variant="destructive" onClick={() => revoke.mutate()} disabled={!serial || revoke.isPending}>
            Revoke
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}

