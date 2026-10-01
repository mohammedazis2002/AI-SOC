import { api } from '@/lib/api'

export interface IssueCertRequest {
  common_name: string
  ttl?: string
}

export interface RevokeCertRequest {
  serial_number: string
}

// Pass-through payload from mTLS service (Vault PKI response fields)
export type CertResponse = Record<string, unknown>

export async function issueWazuhClientCert(body: IssueCertRequest): Promise<CertResponse> {
  const { data } = await api.post<CertResponse>('/mtls/certificates/issue', body)
  return data
}

export async function renewWazuhClientCert(body: IssueCertRequest): Promise<CertResponse> {
  const { data } = await api.post<CertResponse>('/mtls/certificates/renew', body)
  return data
}

export async function revokeClientCert(body: RevokeCertRequest): Promise<CertResponse> {
  const { data } = await api.post<CertResponse>('/mtls/certificates/revoke', body)
  return data
}

