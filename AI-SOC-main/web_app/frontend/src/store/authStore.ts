import { create } from 'zustand'
import { persist } from 'zustand/middleware'

import { fetchMe, loginRequest } from '@/lib/auth-api'
import type { AuthUser } from '@/types/auth'

interface AuthState {
  token: string | null
  user: AuthUser | null
  setToken: (token: string | null) => void
  setUser: (user: AuthUser | null) => void
  logout: () => void
  /** Set token and load current user from GET /me */
  loginWithToken: (token: string) => Promise<void>
  /** Validate token and refresh user (e.g. after persist rehydrate) */
  refreshSession: () => Promise<void>
  loginWithCredentials: (email: string, password: string) => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      setToken: (token) => set({ token }),
      setUser: (user) => set({ user }),
      logout: () => set({ token: null, user: null }),
      loginWithToken: async (token) => {
        set({ token })
        const user = await fetchMe()
        set({ user })
      },
      refreshSession: async () => {
        const { token } = get()
        if (!token) {
          set({ user: null })
          return
        }
        try {
          const user = await fetchMe()
          set({ user })
        } catch {
          set({ token: null, user: null })
        }
      },
      loginWithCredentials: async (email, password) => {
        set({ token: null, user: null })
        const { access_token } = await loginRequest(email, password)
        await get().loginWithToken(access_token)
      },
    }),
    {
      name: 'cybolt-auth',
      // Persist user too so a refresh doesn’t briefly see token+null user and get bounced by RequireAuth.
      partialize: (state) => ({ token: state.token, user: state.user }),
    }
  )
)
