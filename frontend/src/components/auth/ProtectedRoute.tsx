import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import type { User } from '../../stores/authStore'
import { refreshAuthSession } from '../../api/authSession'
import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'

interface ProtectedRouteProps {
  children: React.ReactNode
}

const API_BASE = '/api/v1'

export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const location = useLocation()
  const { isAuthenticated, setAuth, logout, setLoading } = useAuthStore()
  const [isChecking, setIsChecking] = useState(true)

  useEffect(() => {
    const verifyAuth = async () => {
      try {
        // Verify auth via cookie (no localStorage token needed)
        const response = await fetch(`${API_BASE}/auth/me`, {
          credentials: 'include',  // Send httpOnly cookies
        })

        if (response.ok) {
          const user = await response.json()
          setAuth(user)
        } else if (response.status === 401) {
          const user = await refreshAuthSession<User>()
          setAuth(user)
        } else {
          logout()
        }
      } catch {
        // Silent fail - just logout
        logout()
      } finally {
        setLoading(false)
        setIsChecking(false)
      }
    }

    verifyAuth()
  }, [logout, setAuth, setLoading])

  if (isChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
          <p className="text-gray-400">Loading...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    // Redirect to login, save the attempted URL
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}
