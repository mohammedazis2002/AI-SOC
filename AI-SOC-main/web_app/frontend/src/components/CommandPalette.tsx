import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Bell, LayoutDashboard, ClipboardList, BarChart3, Activity } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { useAppStore } from '@/store/useAppStore'
import { useAuthStore } from '@/store/authStore'
import { hasAdminOrEngineerAccess } from '@/types/auth'

const quickNav = [
  { label: 'Dashboard', to: '/', icon: LayoutDashboard },
  { label: 'Alerts', to: '/alerts', icon: Bell },
  { label: 'Review Queue', to: '/review', icon: ClipboardList },
  { label: 'Analytics', to: '/analytics', icon: BarChart3 },
  { label: 'System Health', to: '/system', icon: Activity },
]

export function CommandPalette() {
  const { commandPaletteOpen, setCommandPaletteOpen } = useAppStore()
  const user = useAuthStore((s) => s.user)
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  const navItems = quickNav.filter((item) =>
    item.to === '/system' ? hasAdminOrEngineerAccess(user) : true
  )

  useEffect(() => {
    if (!commandPaletteOpen) setQuery('')
  }, [commandPaletteOpen])

  const handleSelect = (to: string) => {
    navigate(to)
    setCommandPaletteOpen(false)
  }

  return (
    <Dialog open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen}>
      <DialogContent showClose={true} className="max-w-xl p-0 gap-0" aria-describedby={undefined}>
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <DialogHeader className="p-4 pb-0">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-slate-400" />
            <Input
              placeholder="Search or navigate..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="border-0 shadow-none focus-visible:ring-0 text-base"
              autoFocus
            />
          </div>
        </DialogHeader>
        <div className="p-4 pt-2 max-h-[60vh] overflow-auto">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-2">Navigation</p>
          <div className="space-y-0.5">
            {navItems.map(({ label, to, icon: Icon }) => (
              <button
                key={to}
                type="button"
                onClick={() => handleSelect(to)}
                className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-700 hover:bg-slate-100 text-left"
              >
                <Icon className="h-4 w-4 text-slate-400" />
                {label}
              </button>
            ))}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
