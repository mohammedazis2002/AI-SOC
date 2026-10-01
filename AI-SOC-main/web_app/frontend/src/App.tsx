import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { MainLayout } from '@/components/layout/MainLayout'
import { CommandPalette } from '@/components/CommandPalette'
import { Toaster } from '@/components/Toaster'
import { AuthBootstrap } from '@/components/AuthBootstrap'
import { RequireAuth } from '@/components/auth/RequireAuth'
import { RequireSystemHealthAccess } from '@/components/auth/RequireSystemHealthAccess'
import { RequireUserManagement } from '@/components/auth/RequireUserManagement'
import { Dashboard } from '@/pages/Dashboard'
import { Alerts } from '@/pages/Alerts'
import { AlertDetail } from '@/pages/AlertDetail'
import { Analytics } from '@/pages/Analytics'
import { SystemHealth } from '@/pages/SystemHealth'
import { Settings } from '@/pages/Settings'
import { ReviewQueue } from '@/pages/ReviewQueue'
import { Login } from '@/pages/Login'
import { Register } from '@/pages/Register'
import { UserManagement } from '@/pages/admin/UserManagement'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <BrowserRouter>
          <AuthBootstrap />
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            <Route element={<RequireAuth />}>
              <Route path="/" element={<MainLayout />}>
                <Route index element={<Dashboard />} />
                <Route path="alerts" element={<Alerts />} />
                <Route path="alerts/:id" element={<AlertDetail />} />
                <Route path="review" element={<ReviewQueue />} />
                <Route path="analytics" element={<Analytics />} />
                <Route element={<RequireSystemHealthAccess />}>
                  <Route path="system" element={<SystemHealth />} />
                </Route>
                <Route path="settings" element={<Settings />} />
                <Route element={<RequireUserManagement />}>
                  <Route path="admin/users" element={<UserManagement />} />
                </Route>
              </Route>
            </Route>
          </Routes>
          <CommandPalette />
          <Toaster />
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  )
}
