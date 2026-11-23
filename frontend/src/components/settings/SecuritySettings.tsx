import { useCallback, useState, useEffect } from 'react'
import { Lock, Shield, Key, RefreshCw, Smartphone, Copy, Check, AlertTriangle, Monitor, Globe, Clock, Trash2 } from 'lucide-react'
import Card from '../common/Card'
import Input from '../common/Input'
import Button from '../common/Button'
import { toast } from 'react-hot-toast'
import { useAuthStore } from '../../stores/authStore'
import { getCsrfHeaders } from '../../utils/csrf'

interface TwoFAStatus {
  enabled: boolean
  backup_codes_remaining: number
}

interface TwoFASetup {
  secret: string
  qr_code: string
  uri: string
}

interface Session {
  id: string
  ip_address: string
  device_name: string
  location: string
  created_at: string
  last_active: string
  is_current: boolean
  is_active: boolean
}

const authFetch = async (url: string, options: RequestInit = {}) => {
  const csrfHeaders = await getCsrfHeaders()
  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      ...csrfHeaders,
    },
  })
}

const SecuritySettings = () => {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changing, setChanging] = useState(false)
  
  // 2FA state
  const [twoFAStatus, setTwoFAStatus] = useState<TwoFAStatus | null>(null)
  const [twoFASetup, setTwoFASetup] = useState<TwoFASetup | null>(null)
  const [verificationCode, setVerificationCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [loading2FA, setLoading2FA] = useState(false)
  const [copiedSecret, setCopiedSecret] = useState(false)
  
  // Sessions state
  const [sessions, setSessions] = useState<Session[]>([])
  const [loadingSessions, setLoadingSessions] = useState(false)
  
  // Auth store for logout
  const { logout, isAuthenticated } = useAuthStore()

  const getErrorMessage = (data: unknown, fallback: string): string => {
    if (!data || typeof data !== 'object') return fallback
    const d = data as Record<string, unknown>
    if (typeof d.detail === 'string') return d.detail
    if (Array.isArray(d.detail) && d.detail.length > 0) {
      const messages = d.detail
        .map((item) => {
          if (typeof item === 'string') return item
          if (item && typeof item === 'object' && 'msg' in item) {
            return String((item as Record<string, unknown>).msg)
          }
          return null
        })
        .filter((msg): msg is string => Boolean(msg))
      if (messages.length > 0) {
        return Array.from(new Set(messages)).join('; ')
      }
    }
    if (typeof d.message === 'string') return d.message
    return fallback
  }

  const fetchSessions = useCallback(async () => {
    setLoadingSessions(true)
    try {
      const res = await authFetch('/api/v1/auth/sessions')
      if (res.ok) {
        setSessions(await res.json())
      }
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
    } finally {
      setLoadingSessions(false)
    }
  }, [])

  const fetch2FAStatus = useCallback(async () => {
    try {
      const res = await authFetch('/api/v1/auth/2fa/status')
      if (res.ok) {
        setTwoFAStatus(await res.json())
      }
    } catch (error) {
      console.error('Failed to fetch 2FA status:', error)
    }
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      void fetch2FAStatus()
      void fetchSessions()
    }
  }, [isAuthenticated, fetch2FAStatus, fetchSessions])

  const handleRevokeSession = async (sessionId: string) => {
    try {
      const res = await authFetch(`/api/v1/auth/sessions/${sessionId}`, {
        method: 'DELETE',
      })
      
      if (res.ok) {
        toast.success('Session revoked')
        fetchSessions()
      } else {
        toast.error('Failed to revoke session')
      }
    } catch (error) {
      toast.error('Failed to revoke session')
    }
  }

  const handleRevokeAllSessions = async () => {
    if (!confirm('This will log you out of all devices. Continue?')) return
    
    try {
      const res = await authFetch('/api/v1/auth/sessions', {
        method: 'DELETE',
      })
      
      if (res.ok) {
        toast.success('All sessions revoked')
        // Log out current user using authStore
        logout()
        window.location.href = '/login'
      } else {
        toast.error('Failed to revoke sessions')
      }
    } catch (error) {
      toast.error('Failed to revoke sessions')
    }
  }

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Unknown'
    const date = new Date(dateString)
    return date.toLocaleString()
  }

  const handleChangePassword = async () => {
    if (!currentPassword || !newPassword || !confirmPassword) {
      toast.error('Please fill in all password fields')
      return
    }
    
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match')
      return
    }
    
    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters')
      return
    }

    setChanging(true)
    try {
      const response = await authFetch('/api/v1/auth/change-password', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      })
      
      if (response.ok) {
        toast.success('Password changed successfully')
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
      } else if (response.status === 429) {
        const data = await response.json()
        toast.error(getErrorMessage(data, 'Too many attempts. Please try again later.'))
      } else {
        const data = await response.json()
        toast.error(getErrorMessage(data, 'Failed to change password'))
      }
    } catch (error) {
      toast.error('Failed to change password')
    } finally {
      setChanging(false)
    }
  }

  const handleSetup2FA = async () => {
    setLoading2FA(true)
    try {
      const res = await authFetch('/api/v1/auth/2fa/setup', {
        method: 'POST',
      })
      
      if (res.ok) {
        setTwoFASetup(await res.json())
      } else {
        const data = await res.json()
        toast.error(data.detail || 'Failed to setup 2FA')
      }
    } catch (error) {
      toast.error('Failed to setup 2FA')
    } finally {
      setLoading2FA(false)
    }
  }

  const handleEnable2FA = async () => {
    if (!verificationCode) return
    
    setLoading2FA(true)
    try {
      const res = await authFetch('/api/v1/auth/2fa/enable', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code: verificationCode })
      })
      
      if (res.ok) {
        const data = await res.json()
        setBackupCodes(data.backup_codes)
        setShowBackupCodes(true)
        setTwoFASetup(null)
        setVerificationCode('')
        fetch2FAStatus()
        toast.success('Two-factor authentication enabled!')
      } else {
        const data = await res.json()
        toast.error(data.detail || 'Invalid verification code')
      }
    } catch (error) {
      toast.error('Failed to enable 2FA')
    } finally {
      setLoading2FA(false)
    }
  }

  const handleDisable2FA = async () => {
    const code = prompt('Enter your 2FA code to disable:')
    if (!code) return
    
    setLoading2FA(true)
    try {
      const res = await authFetch('/api/v1/auth/2fa/disable', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code })
      })
      
      if (res.ok) {
        fetch2FAStatus()
        toast.success('Two-factor authentication disabled')
      } else {
        const data = await res.json()
        toast.error(data.detail || 'Failed to disable 2FA')
      }
    } catch (error) {
      toast.error('Failed to disable 2FA')
    } finally {
      setLoading2FA(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedSecret(true)
    setTimeout(() => setCopiedSecret(false), 2000)
    toast.success('Copied to clipboard')
  }

  return (
    <div className="space-y-6">
      {/* Change Password */}
      <Card title="Change Password">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Change your EasyPi account password. You'll need to enter your current password to confirm.
          </p>
          
          <Input 
            label="Current Password" 
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Enter current password"
          />
          <Input 
            label="New Password" 
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Enter new password (min 8 characters)"
          />
          <Input 
            label="Confirm New Password" 
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm new password"
          />

          <div className="flex justify-end pt-2">
            <Button 
              variant="primary" 
              onClick={handleChangePassword}
              disabled={changing}
              icon={<Key className="h-4 w-4" />}
            >
              {changing ? 'Changing...' : 'Change Password'}
            </Button>
          </div>
        </div>
      </Card>

      {/* Two-Factor Authentication */}
      <Card title="Two-Factor Authentication">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Add an extra layer of security to your account using an authenticator app.
          </p>
          
          {/* 2FA Status */}
          <div className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800">
            <div className="flex items-center gap-4">
              <div className={`p-2 rounded-lg ${twoFAStatus?.enabled ? 'bg-green-100 dark:bg-green-900/30' : 'bg-gray-100 dark:bg-gray-800'}`}>
                <Shield className={`h-5 w-5 ${twoFAStatus?.enabled ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`} />
              </div>
              <div>
                <div className="font-medium text-gray-900 dark:text-white">
                  {twoFAStatus?.enabled ? '2FA Enabled' : '2FA Disabled'}
                </div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  {twoFAStatus?.enabled 
                    ? `${twoFAStatus.backup_codes_remaining} backup codes remaining`
                    : 'Protect your account with 2FA'
                  }
                </div>
              </div>
            </div>
            {twoFAStatus?.enabled ? (
              <Button 
                variant="danger" 
                size="sm"
                onClick={handleDisable2FA}
                disabled={loading2FA}
              >
                Disable
              </Button>
            ) : (
              <Button 
                variant="primary" 
                size="sm"
                onClick={handleSetup2FA}
                disabled={loading2FA}
              >
                {loading2FA ? 'Loading...' : 'Enable'}
              </Button>
            )}
          </div>

          {/* 2FA Setup Flow */}
          {twoFASetup && (
            <div className="p-4 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20 space-y-4">
              <div className="flex items-start gap-3">
                <Smartphone className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Scan QR Code</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    Use an authenticator app like Google Authenticator or Authy
                  </div>
                </div>
              </div>
              
              {/* QR Code */}
              <div className="flex justify-center">
                <img 
                  src={`data:image/png;base64,${twoFASetup.qr_code}`} 
                  alt="2FA QR Code" 
                  className="w-48 h-48 border border-gray-200 dark:border-dark-600 rounded-lg"
                />
              </div>
              
              {/* Manual Entry */}
              <div className="text-center">
                <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">Or enter this code manually:</div>
                <div className="flex items-center justify-center gap-2">
                  <code className="px-3 py-2 bg-gray-100 dark:bg-dark-700 rounded font-mono text-sm">
                    {twoFASetup.secret}
                  </code>
                  <button 
                    onClick={() => copyToClipboard(twoFASetup.secret)}
                    className="p-2 hover:bg-gray-200 dark:hover:bg-dark-600 rounded"
                  >
                    {copiedSecret ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4 text-gray-400" />}
                  </button>
                </div>
              </div>
              
              {/* Verification */}
              <div className="space-y-3">
                <Input
                  label="Enter 6-digit code from your app"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                />
                <div className="flex gap-2">
                  <Button 
                    variant="ghost" 
                    onClick={() => setTwoFASetup(null)}
                    className="flex-1"
                  >
                    Cancel
                  </Button>
                  <Button 
                    variant="primary" 
                    onClick={handleEnable2FA}
                    disabled={verificationCode.length !== 6 || loading2FA}
                    className="flex-1"
                  >
                    {loading2FA ? 'Verifying...' : 'Verify & Enable'}
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Backup Codes Modal */}
          {showBackupCodes && backupCodes.length > 0 && (
            <div className="p-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 space-y-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5" />
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Save Your Backup Codes</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    Store these codes in a safe place. Each code can only be used once.
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-2">
                {backupCodes.map((code, i) => (
                  <code key={i} className="px-3 py-2 bg-white dark:bg-dark-700 rounded text-center font-mono text-sm border border-gray-200 dark:border-dark-600">
                    {code}
                  </code>
                ))}
              </div>
              
              <div className="flex gap-2">
                <Button 
                  variant="ghost" 
                  onClick={() => copyToClipboard(backupCodes.join('\n'))}
                  icon={<Copy className="h-4 w-4" />}
                  className="flex-1"
                >
                  Copy All
                </Button>
                <Button 
                  variant="primary" 
                  onClick={() => {
                    setShowBackupCodes(false)
                    setBackupCodes([])
                  }}
                  className="flex-1"
                >
                  I've Saved These Codes
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Active Sessions */}
      <Card title="Active Sessions">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Devices where you're currently logged in.
            </p>
            {sessions.length > 1 && (
              <Button
                variant="danger"
                size="sm"
                onClick={handleRevokeAllSessions}
                icon={<Trash2 className="h-4 w-4" />}
              >
                Revoke All
              </Button>
            )}
          </div>
          
          {loadingSessions ? (
            <div className="text-center py-8 text-gray-500">Loading sessions...</div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-8 text-gray-500">No active sessions</div>
          ) : (
            <div className="space-y-3">
              {sessions.map((session) => (
                <div
                  key={session.id}
                  className={`flex items-center justify-between p-4 rounded-lg border ${
                    session.is_current
                      ? 'border-green-500 bg-green-50 dark:bg-green-900/20'
                      : 'border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800'
                  }`}
                >
                  <div className="flex items-center gap-4">
                    <div className={`p-2 rounded-lg ${session.is_current ? 'bg-green-100 dark:bg-green-900/30' : 'bg-gray-100 dark:bg-gray-800'}`}>
                      <Monitor className={`h-5 w-5 ${session.is_current ? 'text-green-600 dark:text-green-400' : 'text-gray-500'}`} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900 dark:text-white">
                          {session.device_name}
                        </span>
                        {session.is_current && (
                          <span className="px-2 py-0.5 text-xs font-medium bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-400 rounded-full">
                            Current
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400 mt-1">
                        <span className="flex items-center gap-1">
                          <Globe className="h-3 w-3" />
                          {session.ip_address}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {formatDate(session.last_active)}
                        </span>
                      </div>
                    </div>
                  </div>
                  {!session.is_current && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRevokeSession(session.id)}
                      className="text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                    >
                      Revoke
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* Other Security Features */}
      <Card title="Additional Security">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            More security features to protect your EasyPi installation.
          </p>
          
          {/* Password for Sensitive Operations */}
          <div className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800">
            <div className="flex items-center gap-4">
              <div className="p-2 rounded-lg bg-amber-100 dark:bg-amber-900/30">
                <Lock className="h-5 w-5 text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <div className="font-medium text-gray-900 dark:text-white">Password for Sensitive Operations</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Require password confirmation for critical actions
                </div>
              </div>
            </div>
            <span className="px-3 py-1 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
              Coming soon
            </span>
          </div>
          
          {/* Automatic Security Updates */}
          <div className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800">
            <div className="flex items-center gap-4">
              <div className="p-2 rounded-lg bg-green-100 dark:bg-green-900/30">
                <RefreshCw className="h-5 w-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <div className="font-medium text-gray-900 dark:text-white">Automatic Security Updates</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">
                  Keep your system secure with automatic updates
                </div>
              </div>
            </div>
            <span className="px-3 py-1 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
              Coming soon
            </span>
          </div>
        </div>
      </Card>
    </div>
  )
}

export default SecuritySettings
