import { create } from 'zustand'

export type SeverityFilter = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type SourceFilter = 'Wazuh' | 'SentinelOne' | 'Splunk' | 'SumoLogic'
export type StatusFilter = 'new' | 'in_review' | 'resolved' | 'false_positive' | 'escalated'

export interface AlertFilters {
  severity: SeverityFilter[]
  source: SourceFilter[]
  status: StatusFilter[]
  dateRange: '1h' | '24h' | '7d' | 'custom'
  from?: string
  to?: string
  search: string
}

export interface Notification {
  id: string
  type: 'success' | 'error' | 'warning'
  message: string
  duration?: number
}

interface AppState {
  sidebarCollapsed: boolean
  setSidebarCollapsed: (v: boolean) => void
  toggleSidebar: () => void

  filters: AlertFilters
  setFilters: (f: Partial<AlertFilters>) => void
  clearFilters: () => void

  liveMode: boolean
  setLiveMode: (v: boolean) => void

  wsStatus: 'connected' | 'disconnected' | 'reconnecting'
  setWsStatus: (s: 'connected' | 'disconnected' | 'reconnecting') => void

  notifications: Notification[]
  addNotification: (n: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void

  reviewQueueCount: number
  setReviewQueueCount: (n: number) => void
  /** MITRE unmapped DLQ count (Mongo `unmapped_alerts`); shown in badge for Admin/Engineer. */
  unmappedQueueCount: number
  setUnmappedQueueCount: (n: number) => void
  newAlertsCount: number
  setNewAlertsCount: (n: number) => void

  commandPaletteOpen: boolean
  setCommandPaletteOpen: (v: boolean) => void
}

const defaultFilters: AlertFilters = {
  severity: [],
  source: [],
  status: [],
  dateRange: '24h',
  search: '',
}

export const useAppStore = create<AppState>((set) => ({
  sidebarCollapsed: false,
  setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  filters: defaultFilters,
  setFilters: (f) =>
    set((s) => ({ filters: { ...s.filters, ...f } })),
  clearFilters: () => set({ filters: defaultFilters }),

  liveMode: true,
  setLiveMode: (v) => set({ liveMode: v }),

  wsStatus: 'connected',
  setWsStatus: (s) => set({ wsStatus: s }),

  notifications: [],
  addNotification: (n) =>
    set((s) => ({
      notifications: [
        ...s.notifications,
        { ...n, id: `n-${Date.now()}-${Math.random().toString(36).slice(2)}` },
      ],
    })),
  removeNotification: (id) =>
    set((s) => ({
      notifications: s.notifications.filter((x) => x.id !== id),
    })),

  reviewQueueCount: 0,
  setReviewQueueCount: (n) => set({ reviewQueueCount: n }),
  unmappedQueueCount: 0,
  setUnmappedQueueCount: (n) => set({ unmappedQueueCount: n }),
  newAlertsCount: 0,
  setNewAlertsCount: (n) => set({ newAlertsCount: n }),

  commandPaletteOpen: false,
  setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
}))
