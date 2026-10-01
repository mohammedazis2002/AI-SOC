import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export function getSeverityClasses(severity: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: 'bg-red-50 text-red-700 border border-red-200',
    HIGH: 'bg-orange-50 text-orange-700 border border-orange-200',
    MEDIUM: 'bg-amber-50 text-amber-700 border border-amber-200',
    LOW: 'bg-blue-50 text-blue-700 border border-blue-200',
    INFO: 'bg-slate-100 text-slate-600 border border-slate-200',
  }
  return map[severity] ?? map.INFO
}

export type AlertStatus = 'new' | 'in_review' | 'resolved' | 'false_positive' | 'escalated'

export function getStatusClasses(status: AlertStatus): string {
  const map: Record<AlertStatus, string> = {
    new: 'text-purple-700 bg-purple-50 border-purple-200',
    in_review: 'text-amber-700 bg-amber-50 border-amber-200',
    resolved: 'text-green-700 bg-green-50 border-green-200',
    false_positive: 'text-slate-600 bg-slate-100 border-slate-200',
    escalated: 'text-red-700 bg-red-50 border-red-200',
  }
  return map[status] ?? 'text-slate-600 bg-slate-100'
}

export function getStatusLabel(status: AlertStatus): string {
  const map: Record<AlertStatus, string> = {
    new: 'New',
    in_review: 'In Review',
    resolved: 'Resolved',
    false_positive: 'False Positive',
    escalated: 'Escalated',
  }
  return map[status] ?? status
}

/** Format minutes for MTTD / MTTR display */
export function formatMinutes(m: number | null | undefined): string {
  if (m == null || Number.isNaN(m)) return '—'
  return `${m}m`
}

export function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins} min ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}
