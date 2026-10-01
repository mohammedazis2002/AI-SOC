import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Bell,
  BarChart3,
  Activity,
  Settings,
  Shield,
  ClipboardList,
  Users,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/useAppStore'
import { useAuthStore } from '@/store/authStore'
import { hasAdminOrEngineerAccess } from '@/types/auth'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts', icon: Bell, label: 'Alerts', badge: 'newAlertsCount' },
  { to: '/review', icon: ClipboardList, label: 'Review Queue', badge: 'reviewQueueCount' },
]
const secondaryItems = [
  { to: '/analytics', icon: BarChart3, label: 'Analytics' },
  { to: '/system', icon: Activity, label: 'System Health' },
]

export function Sidebar() {
  const { sidebarCollapsed, newAlertsCount, reviewQueueCount } = useAppStore()
  const user = useAuthStore((s) => s.user)
  const canSeeSystemHealth = hasAdminOrEngineerAccess(user)
  const visibleSecondaryItems = secondaryItems.filter((item) =>
    item.to === '/system' ? canSeeSystemHealth : true
  )

  const bottomItems = [
    ...(user?.is_superadmin || user?.permissions?.user_management
      ? [{ to: '/admin/users', icon: Users, label: 'User Management' }]
      : []),
    { to: '/settings', icon: Settings, label: 'Settings' },
  ]

  const getBadge = (key: string) => {
    if (key === 'newAlertsCount') return newAlertsCount
    if (key === 'reviewQueueCount') return reviewQueueCount
    return 0
  }

  return (
    <aside
      className={cn(
        'fixed left-0 top-14 bottom-8 z-30 flex flex-col border-r border-slate-200 bg-white transition-[width] duration-200',
        sidebarCollapsed ? 'w-[60px]' : 'w-60'
      )}
    >
      <div className="flex flex-col gap-1 p-2">
        {!sidebarCollapsed && (
          <div className="mb-2 flex items-center gap-2 px-2 py-1">
            <Shield className="h-5 w-5 text-blue-600 shrink-0" />
            <span className="font-mono font-bold text-slate-900 text-sm">Cybolt</span>
          </div>
        )}

        <nav className="space-y-0.5">
          {navItems.map(({ to, icon: Icon, label, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  sidebarCollapsed && 'justify-center px-0',
                  isActive
                    ? 'bg-blue-50 text-blue-700 font-medium border-l-2 border-blue-600 ml-0 pl-3'
                    : 'text-slate-600 hover:bg-slate-50'
                )
              }
              title={sidebarCollapsed ? label : undefined}
            >
              <Icon className="h-5 w-5 shrink-0" />
              {!sidebarCollapsed && (
                <>
                  <span className="flex-1">{label}</span>
                  {badge && getBadge(badge) > 0 && (
                    <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs font-mono">
                      {getBadge(badge)}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="my-2 border-t border-slate-100" />
        <nav className="space-y-0.5">
          {visibleSecondaryItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  sidebarCollapsed && 'justify-center px-0',
                  isActive
                    ? 'bg-blue-50 text-blue-700 font-medium border-l-2 border-blue-600 ml-0 pl-3'
                    : 'text-slate-600 hover:bg-slate-50'
                )
              }
              title={sidebarCollapsed ? label : undefined}
            >
              <Icon className="h-5 w-5 shrink-0" />
              {!sidebarCollapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="my-2 border-t border-slate-100" />
        <nav className="space-y-0.5">
          {bottomItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  sidebarCollapsed && 'justify-center px-0',
                  isActive
                    ? 'bg-blue-50 text-blue-700 font-medium border-l-2 border-blue-600 ml-0 pl-3'
                    : 'text-slate-600 hover:bg-slate-50'
                )
              }
              title={sidebarCollapsed ? label : undefined}
            >
              <Icon className="h-5 w-5 shrink-0" />
              {!sidebarCollapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>
      </div>
    </aside>
  )
}
