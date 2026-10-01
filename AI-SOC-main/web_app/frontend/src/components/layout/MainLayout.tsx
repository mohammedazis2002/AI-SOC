import { Outlet } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useWebSocketSimulation } from '@/hooks/useWebSocketSimulation'
import { useSidebarAlertCounts } from '@/hooks/useSidebarAlertCounts'
import { Topbar } from './Topbar'
import { Sidebar } from './Sidebar'
import { StatusBar } from './StatusBar'
import { useAppStore } from '@/store/useAppStore'

export function MainLayout() {
  const { sidebarCollapsed } = useAppStore()
  useWebSocketSimulation()
  useSidebarAlertCounts()

  return (
    <div className="min-h-screen bg-[var(--bg-base)]">
      <Topbar />
      <Sidebar />
      <main
        className={cn(
          'pt-14 pb-8 min-h-screen transition-[margin-left] duration-200',
          sidebarCollapsed ? 'ml-[60px]' : 'ml-60'
        )}
      >
        <div className="p-4">
          <Outlet />
        </div>
      </main>
      <StatusBar />
    </div>
  )
}
