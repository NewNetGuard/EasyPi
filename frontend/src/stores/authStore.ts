import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface User {
  id: number
  username: string
  email: string | null
  role: string
  is_active: boolean
  created_at: string
  last_login: string | null
  last_login_ip: string | null
  last_login_user_agent: string | null
}

interface AuthState {
  // No more tokens in store - they're in httpOnly cookies!
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  
  // Actions
  setAuth: (user: User) => void
  logout: () => void
  setLoading: (loading: boolean) => void
  setUser: (user: User | null) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      isLoading: true,
      
      setAuth: (user) => {
        // Tokens are now in httpOnly cookies - not stored in JS!
        // Clear any old localStorage tokens (migration)
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
        set({
          user,
          isAuthenticated: true,
          isLoading: false,
        })
      },
      
      logout: () => {
        // Clear any legacy localStorage tokens
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
        localStorage.removeItem('easypi-auth')
        set({
          user: null,
          isAuthenticated: false,
          isLoading: false,
        })
      },
      
      setLoading: (loading) => set({ isLoading: loading }),
      
      setUser: (user) => set({ 
        user, 
        isAuthenticated: user !== null 
      }),
    }),
    {
      name: 'easypi-auth',
      partialize: (state) => ({
        // Only persist user info, not tokens (they're in cookies)
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
