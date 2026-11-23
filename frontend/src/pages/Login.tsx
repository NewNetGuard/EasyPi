import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Lock, User, AlertCircle, Loader2, Shield, Key, ArrowRight } from 'lucide-react'
import { useAuthStore } from '../stores/authStore'

const API_BASE = '/api/v1'
const REGISTRATION_STATUS_PATH = `${API_BASE}/auth/registration-status`
const REGISTRATION_STATUS_TIMEOUT_MS = 20000
const REGISTRATION_STATUS_RETRY_MAX_DELAY_MS = 10000

interface RegistrationStatus {
  registration_allowed: boolean
  requires_setup_token: boolean
  message: string
}

export default function Login() {
  const navigate = useNavigate()
  const { setAuth, logout } = useAuthStore()
  
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [setupToken, setSetupToken] = useState('')
  const [recoveryToken, setRecoveryToken] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [requires2FA, setRequires2FA] = useState(false)
  const [registrationStatus, setRegistrationStatus] = useState<RegistrationStatus | null>(null)
  const [registrationStatusLoading, setRegistrationStatusLoading] = useState(true)
  const [showSetupInstructions, setShowSetupInstructions] = useState(true)
  const [showRecoveryModal, setShowRecoveryModal] = useState(false)
  const [recoveryError, setRecoveryError] = useState('')
  const [recoveryLoading, setRecoveryLoading] = useState(false)
  const [recoveryTotpCode, setRecoveryTotpCode] = useState('')
  const [setupCheckAttempts, setSetupCheckAttempts] = useState(0)
  const [setupCheckError, setSetupCheckError] = useState<string | null>(null)

  // Check registration status on mount
  useEffect(() => {
    let cancelled = false
    let retryTimer: number | null = null
    let attempt = 0

    const computeDelayMs = (attemptNo: number) => {
      // Exponential-ish backoff with a cap; keeps the UX fast on first boot but avoids tight loops.
      const base = Math.min(REGISTRATION_STATUS_RETRY_MAX_DELAY_MS, 1200 * Math.pow(1.4, Math.max(attemptNo - 1, 0)))
      const jitter = Math.floor(Math.random() * 250)
      return Math.min(REGISTRATION_STATUS_RETRY_MAX_DELAY_MS, Math.max(800, base + jitter))
    }

    const scheduleRetry = () => {
      const delay = computeDelayMs(attempt)
      retryTimer = window.setTimeout(() => {
        checkRegistrationStatus()
      }, delay)
    }

    const isTransientGatewayError = (response: Response, contentType: string) => {
      const ct = (contentType || '').toLowerCase()
      // Nginx "502 Bad Gateway" often comes as text/html while backend is booting.
      if (ct.includes('text/html') && response.status >= 500) return true
      return response.status === 502 || response.status === 503 || response.status === 504
    }

    const checkRegistrationStatus = async () => {
      if (cancelled) return
      attempt += 1
      setSetupCheckAttempts(attempt)

      const controller = new AbortController()
      const timeout = window.setTimeout(() => controller.abort(), REGISTRATION_STATUS_TIMEOUT_MS)
      try {
        const response = await fetch(REGISTRATION_STATUS_PATH, {
          signal: controller.signal,
          cache: 'no-store',
        })

        const contentType = response.headers.get('content-type') || ''

        if (!response.ok) {
          if (isTransientGatewayError(response, contentType)) {
            setSetupCheckError('EasyPi is starting… waiting for backend to be ready')
            scheduleRetry()
            return
          }

          // Non-transient error: fall back to login UI.
          setSetupCheckError(null)
          setRegistrationStatusLoading(false)
          return
        }

        // Expect JSON.
        if (!contentType.toLowerCase().includes('application/json')) {
          setSetupCheckError('EasyPi is starting… waiting for backend to be ready')
          scheduleRetry()
          return
        }

        const status = await response.json()
        setRegistrationStatus(status)
        setSetupCheckError(null)

        // If first-time setup, clear any old tokens that might interfere
        if (status.registration_allowed && status.requires_setup_token) {
          // Clear all old auth data to prevent stale token issues
          localStorage.removeItem('accessToken')
          localStorage.removeItem('refreshToken')
          localStorage.removeItem('easypi-auth')
          logout()
        }

        setRegistrationStatusLoading(false)
      } catch (err) {
        // Network error / timeout: backend likely still starting.
        console.error('Failed to check registration status:', err)
        setSetupCheckError('EasyPi is starting… waiting for backend to be ready')
        scheduleRetry()
      } finally {
        window.clearTimeout(timeout)
      }
    }

    checkRegistrationStatus()

    return () => {
      cancelled = true
      if (retryTimer) window.clearTimeout(retryTimer)
    }
  }, [logout])

  // Handle recovery login
  const handleRecoveryLogin = async () => {
    setRecoveryError('')
    setRecoveryLoading(true)

    try {
      const body: Record<string, string> = {
        recovery_token: recoveryToken,
      }
      if (recoveryTotpCode) body.totp_code = recoveryTotpCode
      
      const response = await fetch(`${API_BASE}/auth/recovery-login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',  // Send/receive httpOnly cookies
        body: JSON.stringify(body),
      })

      let data
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        data = await response.json()
      } else {
        // Server returned HTML (nginx error when backend is down)
        window.dispatchEvent(new CustomEvent('easypi:server-error'))
        throw new Error('Server unavailable. Please try again later.')
      }

      if (!response.ok) {
        // Handle validation errors (422) - detail can be array of objects
        let errorMessage = 'Invalid recovery token'
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            // Pydantic validation errors
            errorMessage = data.detail.map((e: any) => e.msg || e.message || String(e)).join('; ')
          } else if (typeof data.detail === 'object') {
            errorMessage = data.detail.msg || data.detail.message || JSON.stringify(data.detail)
          } else {
            errorMessage = String(data.detail)
          }
        }
        throw new Error(errorMessage)
      }

      // Check if 2FA is required
      if (data.requires_2fa) {
        setRecoveryError('Enter the current two-factor code for this account.')
        setRecoveryLoading(false)
        return
      }

      // Save auth state (only user info - tokens are in httpOnly cookies)
      setAuth(data.user)
      
      // Redirect to dashboard
      navigate('/dashboard', { replace: true })
    } catch (err) {
      // Check for network errors (server down)
      if (err instanceof TypeError && err.message.includes('fetch')) {
        window.dispatchEvent(new CustomEvent('easypi:server-error'))
        setRecoveryError('Server unavailable. Please check if the backend is running.')
      } else {
        setRecoveryError(err instanceof Error ? err.message : 'Recovery failed')
      }
    } finally {
      setRecoveryLoading(false)
    }
  }

  // Determine if we're in first-time setup mode
  const isFirstTimeSetup = registrationStatus?.registration_allowed && registrationStatus?.requires_setup_token

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      // If first time setup - register, otherwise login
      const endpoint = isFirstTimeSetup ? '/auth/register' : '/auth/login'
      const body: any = { username, password }
      
      // Add TOTP code if 2FA is required
      if (requires2FA && totpCode) {
        body.totp_code = totpCode
      }
      
      // Add setup token if first time setup
      if (isFirstTimeSetup && setupToken) {
        body.setup_token = setupToken
      }
      
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',  // Send/receive httpOnly cookies
        body: JSON.stringify(body),
      })

      // Check if response is HTML (server error from nginx)
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('text/html')) {
        // Dispatch server error event for banner
        window.dispatchEvent(new CustomEvent('easypi:server-error'))
        throw new Error('Server unavailable. Please try again later.')
      }

      const data = await response.json()

      if (!response.ok) {
        // Handle validation errors (422) - detail can be array of objects
        let errorMessage = 'Authentication failed'
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            // Pydantic validation errors
            errorMessage = data.detail.map((e: any) => e.msg || e.message || String(e)).join('; ')
          } else if (typeof data.detail === 'object') {
            errorMessage = data.detail.msg || data.detail.message || JSON.stringify(data.detail)
          } else {
            errorMessage = String(data.detail)
          }
        }

        // If first-time setup registration fails, re-check setup status.
        // It's possible the user was created but the response failed (e.g. backend restart).
        if (isFirstTimeSetup && endpoint === '/auth/register') {
          try {
            const statusRes = await fetch(REGISTRATION_STATUS_PATH, { cache: 'no-store' })
            const ct = (statusRes.headers.get('content-type') || '').toLowerCase()
            if (statusRes.ok && ct.includes('application/json')) {
              const status = await statusRes.json()
              setRegistrationStatus(status)
              if (!status.registration_allowed) {
                errorMessage = 'Registration may have completed. Please log in.'
              }
            }
          } catch {
            // Ignore status refresh errors and keep the original error message.
          }
        }
        throw new Error(errorMessage)
      }

      // Check if 2FA is required
      if (data.requires_2fa) {
        setRequires2FA(true)
        setIsLoading(false)
        return
      }

      // Save auth state (only user info - tokens are in httpOnly cookies)
      setAuth(data.user)
      
      // Redirect to dashboard
      navigate('/dashboard', { replace: true })
    } catch (err) {
      // Check for network errors (server down)
      if (err instanceof TypeError && err.message.includes('fetch')) {
        window.dispatchEvent(new CustomEvent('easypi:server-error'))
        setError('Server unavailable. Please check if the backend is running.')
      } else {
        setError(err instanceof Error ? err.message : 'An error occurred')
      }
    } finally {
      setIsLoading(false)
    }
  }

  // First time setup: Show token screen first
  if (registrationStatusLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-4">
        <div className="w-full max-w-md">
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl border border-gray-700/50 p-8 shadow-2xl text-center">
            <Loader2 className="w-8 h-8 text-blue-400 animate-spin mx-auto mb-3" />
            <p className="text-white font-medium">
              {setupCheckError ? 'Starting EasyPi…' : 'Checking setup status…'}
            </p>
            {setupCheckError && (
              <p className="text-gray-400 text-sm mt-2">
                {setupCheckError}
              </p>
            )}
            {setupCheckAttempts > 1 && (
              <p className="text-gray-500 text-xs mt-3">
                Attempt {setupCheckAttempts} — this usually takes a few seconds after installation
              </p>
            )}
          </div>
        </div>
      </div>
    )
  }

  // First time setup: Show token screen first
  if (isFirstTimeSetup && showSetupInstructions) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-4">
        <div className="w-full max-w-md">
          {/* Logo */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-yellow-500 to-orange-600 mb-4">
              <Key className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-white">EasyPi Setup</h1>
            <p className="text-gray-400 mt-2">First Time Configuration</p>
          </div>

          {/* Token Card */}
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl border border-yellow-600/50 p-8 shadow-2xl">
            <h2 className="text-xl font-semibold text-white mb-4 text-center">
              🔐 Recovery Token
            </h2>
            
            {/* Warning */}
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 mb-4">
              <p className="text-red-400 text-sm text-center font-medium">
                ⚠️ SAVE THIS TOKEN!
              </p>
              <p className="text-red-400/80 text-xs text-center mt-1">
                This is the only way to recover access if you forget your password
              </p>
            </div>

            {/* Token Display */}
            <div className="bg-gray-900/80 border border-yellow-600/30 rounded-xl p-4 mb-6 overflow-hidden">
              <div className="text-center font-mono text-lg text-yellow-400 select-all break-all">
                Read the one-time setup token from the EasyPi installer console.
              </div>
            </div>

            {/* Copy Button */}
            <button
              onClick={() => setShowSetupInstructions(false)}
              className="w-full py-3 px-4 bg-gradient-to-r from-yellow-500 to-orange-600 hover:from-yellow-600 hover:to-orange-700 text-white font-medium rounded-xl shadow-lg transition-all flex items-center justify-center gap-2"
            >
              <ArrowRight className="h-5 w-5" />
              <span>Continue</span>
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex flex-col items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-[#0c1445] via-[#0c1445] to-red-500 mb-4">
            <span className="text-base font-bold text-white leading-none tracking-wide">Easy</span>
            <span className="text-3xl font-serif text-red-500 leading-none -mt-1">π</span>
          </div>
          <h1 className="text-3xl font-bold text-white">EasyPi</h1>
          <p className="text-gray-400 mt-2">Raspberry Pi Management Platform</p>
        </div>

        {/* Card */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl border border-gray-700/50 p-8 shadow-2xl">
          <h2 className="text-xl font-semibold text-white mb-6 text-center">
            {isFirstTimeSetup ? 'Create Admin Account' : 'Welcome Back'}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="block w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="Enter username"
                  required
                  minLength={3}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="block w-full pl-10 pr-12 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder={isFirstTimeSetup ? "Create a strong password" : "Enter password"}
                  required
                  minLength={8}
                  autoComplete={isFirstTimeSetup ? 'new-password' : 'current-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
              {isFirstTimeSetup && (
                <p className="mt-1 text-xs text-gray-500">
                  Min 8 chars, uppercase, lowercase, and digit required
                </p>
              )}
            </div>

            {/* Setup Token (shown for first time setup) */}
            {isFirstTimeSetup && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Setup Token
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Key className="h-5 w-5 text-yellow-500" />
                  </div>
                  <input
                    type="text"
                    value={setupToken}
                    onChange={(e) => setSetupToken(e.target.value)}
                    className="block w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-yellow-600/50 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-yellow-500 focus:border-transparent transition-all font-mono tracking-wider"
                    placeholder="Paste token here"
                    required
                    autoComplete="off"
                  />
                </div>
                <p className="mt-2 text-xs text-gray-400">
                  This one-time token is printed in the EasyPi installer console.
                </p>
              </div>
            )}

            {/* 2FA Code (shown when required) */}
            {requires2FA && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Two-Factor Code
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Shield className="h-5 w-5 text-gray-500" />
                  </div>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="block w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all text-center tracking-widest font-mono text-lg"
                    placeholder="000000"
                    maxLength={6}
                    autoFocus
                    autoComplete="one-time-code"
                  />
                </div>
                <p className="mt-2 text-xs text-gray-400 text-center">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            )}

            {/* Error message */}
            {error && (
              <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 px-4 bg-gradient-to-r from-[#0c1445] via-[#0c1445] to-red-500 hover:from-[#101a52] hover:via-[#101a52] hover:to-red-600 text-white font-medium rounded-xl shadow-lg shadow-red-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span>{isFirstTimeSetup ? 'Creating admin...' : 'Signing in...'}</span>
                </>
              ) : (
                <span>{isFirstTimeSetup ? 'Create Admin Account' : 'Sign In'}</span>
              )}
            </button>

            {/* Forgot Password */}
            {!isFirstTimeSetup && (
              <button
                type="button"
                onClick={() => setShowRecoveryModal(true)}
                className="w-full text-sm text-gray-400 hover:text-white transition-colors mt-3"
              >
                Forgot password?
              </button>
            )}
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-gray-500 text-sm mt-6">
          EasyPi v{__APP_VERSION__} • Secure Home Server Management
        </p>
      </div>

      {/* Recovery Modal */}
      {showRecoveryModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-2xl border border-gray-700 p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-xl font-semibold text-white mb-4 text-center">
              🔐 Password Recovery
            </h3>

            <p className="text-gray-400 text-sm text-center mb-6">
              The master recovery token is always required. Enter a two-factor code if it is enabled.
            </p>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Recovery Token
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Key className="h-5 w-5 text-yellow-500" />
                </div>
                <input
                  type="password"
                  value={recoveryToken}
                  onChange={(e) => setRecoveryToken(e.target.value)}
                  className="block w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-yellow-500 focus:border-transparent transition-all font-mono"
                  placeholder="Enter your recovery token"
                  autoComplete="off"
                  autoFocus
                />
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Two-Factor Code
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Shield className="h-5 w-5 text-blue-500" />
                </div>
                <input
                  type="text"
                  value={recoveryTotpCode}
                  onChange={(e) => setRecoveryTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="block w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all text-center tracking-widest font-mono text-lg"
                  placeholder="Optional"
                  maxLength={6}
                  autoComplete="one-time-code"
                />
              </div>
            </div>

            {recoveryError && (
              <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm mb-4">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{recoveryError}</span>
              </div>
            )}

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => {
                  setShowRecoveryModal(false)
                  setRecoveryToken('')
                  setRecoveryTotpCode('')
                  setRecoveryError('')
                }}
                className="flex-1 py-3 px-4 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-xl transition-all"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRecoveryLogin}
                disabled={recoveryLoading || !recoveryToken}
                className="flex-1 py-3 px-4 bg-gradient-to-r from-yellow-500 to-orange-600 hover:from-yellow-600 hover:to-orange-700 text-white font-medium rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {recoveryLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Login'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
