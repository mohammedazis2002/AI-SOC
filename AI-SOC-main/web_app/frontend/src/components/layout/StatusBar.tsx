import { useAppStore } from '@/store/useAppStore'

export function StatusBar() {
  const { wsStatus } = useAppStore()

  return (
    <footer className="fixed bottom-0 left-0 right-0 z-40 h-8 border-t border-slate-200 bg-white px-4 flex items-center gap-4 text-xs font-mono text-slate-500">
      <span className="flex items-center gap-1.5">
        <span
          className={wsStatus === 'connected' ? 'text-green-500' : wsStatus === 'reconnecting' ? 'text-amber-500' : 'text-red-500'}
          aria-hidden
        >
          ●
        </span>
        {wsStatus === 'connected' && 'WS Connected'}
        {wsStatus === 'reconnecting' && 'Reconnecting...'}
        {wsStatus === 'disconnected' && 'WS Disconnected'}
      </span>
      <span>|</span>
      <span>Queue: 247 pending</span>
      <span>|</span>
      <span>142 alerts/hr</span>
      <span>|</span>
      <span>Model: Mistral-7B</span>
    </footer>
  )
}
