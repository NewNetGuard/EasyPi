/**
 * Users Management Page
 * 
 * Admin-only page for managing users:
 * - List all users
 * - Create new user
 * - Edit user (role, status)
 * - Delete user
 * - Reset password
 * - Revoke sessions
 * - Disable 2FA
 */

import { useCallback, useState, useEffect } from 'react'
import { 
  Users as UsersIcon, 
  Plus, 
  Edit, 
  Trash2, 
  Key, 
  Shield, 
  ShieldOff,
  UserCheck,
  UserX,
  RefreshCw,
  LogOut,
  Clock,
  Mail,
  AlertTriangle,
  X,
  Check,
  Smartphone
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { useAuthStore } from '../stores/authStore'
import { getCsrfHeaders } from '../utils/csrf'
import Button from '../components/common/Button'
import OverviewStat from '../components/common/OverviewStat'

interface User {
  id: number
  username: string
  email: string | null
  role: 'admin' | 'user'
  is_active: boolean
  created_at: string
  last_login: string | null
  totp_enabled: boolean
  sessions_count: number
}

const authFetch = async (url: string, options: RequestInit = {}) => {
  const method = options.method?.toUpperCase() || 'GET'
  const csrfHeaders = ['GET', 'HEAD', 'OPTIONS'].includes(method)
    ? {}
    : await getCsrfHeaders()
  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      ...csrfHeaders,
    },
  })
}

const Users = () => {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [currentUserId, setCurrentUserId] = useState<number | null>(null)
  
  // Get current user from auth store
  const { user: authUser, logout } = useAuthStore()
  
  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [showResetPasswordModal, setShowResetPasswordModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  
  // Form state
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    role: 'user' as 'admin' | 'user'
  })
  const [newPassword, setNewPassword] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const [formError, setFormError] = useState('')

  // Helper to extract error message from API response
  const getErrorMessage = (data: unknown, fallback: string): string => {
    if (!data || typeof data !== 'object') return fallback
    const d = data as Record<string, unknown>
    if (typeof d.detail === 'string') return d.detail
    if (Array.isArray(d.detail) && d.detail.length > 0) {
      const first = d.detail[0]
      if (typeof first === 'string') return first
      if (first && typeof first === 'object' && 'msg' in first) {
        return String((first as Record<string, unknown>).msg)
      }
    }
    if (typeof d.message === 'string') return d.message
    return fallback
  }

  const fetchUsers = useCallback(async () => {
    setLoading(true)
    try {
      if (!authUser) {
        setLoading(false)
        return
      }
      const res = await authFetch('/api/v1/users')
      
      if (res.status === 401) {
        toast.error('Session expired. Please log in again.')
        logout()
        window.location.href = '/login'
        return
      }
      if (res.status === 403) {
        toast.error('Admin access required')
        return
      }
      
      if (res.ok) {
        setUsers(await res.json())
      } else {
        toast.error('Failed to fetch users')
      }
    } catch (error) {
      console.error('Failed to fetch users:', error)
      toast.error('Failed to fetch users')
    } finally {
      setLoading(false)
    }
  }, [authUser, logout])

  useEffect(() => {
    if (authUser?.id) {
      setCurrentUserId(authUser.id)
    }
    void fetchUsers()
  }, [authUser?.id, fetchUsers])

  const handleCreateUser = async () => {
    setFormError('')
    
    if (!formData.username || !formData.password) {
      setFormError('Username and password are required')
      return
    }
    
    setActionLoading(true)
    try {
      const res = await authFetch('/api/v1/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email || null,
          password: formData.password,
          role: formData.role
        })
      })
      
      if (res.ok) {
        toast.success('User created successfully')
        setShowCreateModal(false)
        setFormData({ username: '', email: '', password: '', role: 'user' })
        setFormError('')
        fetchUsers()
      } else {
        const data = await res.json()
        setFormError(getErrorMessage(data, 'Failed to create user'))
      }
    } catch (error) {
      setFormError('Failed to create user')
    } finally {
      setActionLoading(false)
    }
  }

  const handleUpdateUser = async () => {
    if (!selectedUser) return
    
    setActionLoading(true)
    try {
      const res = await authFetch(`/api/v1/users/${selectedUser.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: formData.email || null,
          role: formData.role,
          is_active: selectedUser.is_active
        })
      })
      
      if (res.ok) {
        toast.success('User updated successfully')
        setShowEditModal(false)
        setSelectedUser(null)
        fetchUsers()
      } else {
        const data = await res.json()
        toast.error(getErrorMessage(data, 'Failed to update user'))
      }
    } catch (error) {
      toast.error('Failed to update user')
    } finally {
      setActionLoading(false)
    }
  }

  const handleDeleteUser = async () => {
    if (!selectedUser) return
    
    setActionLoading(true)
    try {
      const res = await authFetch(`/api/v1/users/${selectedUser.id}`, {
        method: 'DELETE',
      })
      
      if (res.ok) {
        toast.success('User deleted successfully')
        setShowDeleteModal(false)
        setSelectedUser(null)
        fetchUsers()
      } else {
        const data = await res.json()
        toast.error(getErrorMessage(data, 'Failed to delete user'))
      }
    } catch (error) {
      toast.error('Failed to delete user')
    } finally {
      setActionLoading(false)
    }
  }

  const handleResetPassword = async () => {
    if (!selectedUser || !newPassword) {
      toast.error('New password is required')
      return
    }
    
    setFormError('')
    
    if (newPassword.length < 8) {
      setFormError('Password must be at least 8 characters')
      return
    }
    
    setActionLoading(true)
    try {
      const res = await authFetch(`/api/v1/users/${selectedUser.id}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_password: newPassword })
      })
      
      if (res.ok) {
        toast.success('Password reset successfully')
        setShowResetPasswordModal(false)
        setSelectedUser(null)
        setNewPassword('')
        setFormError('')
        if (selectedUser.id === currentUserId) {
          toast.error('Your session was reset. Please log in again.')
          logout()
          window.location.href = '/login'
          return
        }
        fetchUsers()
      } else {
        const data = await res.json()
        setFormError(getErrorMessage(data, 'Failed to reset password'))
      }
    } catch (error) {
      setFormError('Failed to reset password')
    } finally {
      setActionLoading(false)
    }
  }

  const handleToggleActive = async (user: User) => {
    try {
      const res = await authFetch(`/api/v1/users/${user.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ is_active: !user.is_active })
      })
      
      if (res.ok) {
        toast.success(user.is_active ? 'User deactivated' : 'User activated')
        fetchUsers()
      } else {
        const data = await res.json()
        toast.error(getErrorMessage(data, 'Failed to update user'))
      }
    } catch (error) {
      toast.error('Failed to update user')
    }
  }

  const handleDisable2FA = async (user: User) => {
    if (!confirm(`Disable 2FA for ${user.username}?`)) return
    
    try {
      const res = await authFetch(`/api/v1/users/${user.id}/disable-2fa`, {
        method: 'POST',
      })
      
      if (res.ok) {
        toast.success('2FA disabled')
        fetchUsers()
      } else {
        const data = await res.json()
        toast.error(getErrorMessage(data, 'Failed to disable 2FA'))
      }
    } catch (error) {
      toast.error('Failed to disable 2FA')
    }
  }

  const handleRevokeSessions = async (user: User) => {
    if (!confirm(`Revoke all sessions for ${user.username}?`)) return
    
    try {
      const res = await authFetch(`/api/v1/users/${user.id}/revoke-sessions`, {
        method: 'POST',
      })
      
      if (res.ok) {
        toast.success('Sessions revoked')
        fetchUsers()
      } else {
        const data = await res.json()
        toast.error(getErrorMessage(data, 'Failed to revoke sessions'))
      }
    } catch (error) {
      toast.error('Failed to revoke sessions')
    }
  }

  const openEditModal = (user: User) => {
    setSelectedUser(user)
    setFormData({
      username: user.username,
      email: user.email || '',
      password: '',
      role: user.role
    })
    setShowEditModal(true)
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never'
    return new Date(dateString).toLocaleString()
  }

  const adminCount = users.filter((user) => user.role === 'admin').length
  const activeCount = users.filter((user) => user.is_active).length
  const twoFactorCount = users.filter((user) => user.totp_enabled).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
            <UsersIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">User Management</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Manage users, roles, and permissions
            </p>
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchUsers}
            loading={loading}
            icon={<RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />}
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </Button>
          <Button
            onClick={() => {
              setFormData({ username: '', email: '', password: '', role: 'user' })
              setShowCreateModal(true)
            }}
            icon={<Plus className="h-4 w-4" />}
          >
            Add User
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <OverviewStat label="Total users" value={users.length} hint="Accounts known to EasyPi" tone="primary" icon={UsersIcon} />
        <OverviewStat label="Admins" value={adminCount} hint="Users with elevated access" tone="warning" icon={Shield} />
        <OverviewStat label="Active" value={activeCount} hint="Currently allowed to sign in" tone="success" icon={UserCheck} />
        <OverviewStat label="2FA enabled" value={twoFactorCount} hint="Protected with a second factor" tone="gray" icon={Smartphone} />
      </div>

      {/* Users List */}
      <div className="bg-white dark:bg-dark-800 rounded-xl shadow-sm border border-gray-200 dark:border-dark-700 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-primary-500 animate-spin" />
          </div>
        ) : users.length === 0 ? (
          <div className="py-12 text-center text-gray-500 dark:text-gray-400">
            <UsersIcon className="mx-auto mb-3 h-12 w-12 opacity-40" />
            <div className="text-lg font-medium text-gray-900 dark:text-white">No users found</div>
            <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Create the first additional account when you are ready to share access.
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-dark-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Security
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Last Login
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-dark-700">
                {users.map((user) => (
                  <tr 
                    key={user.id} 
                    className={`hover:bg-gray-50 dark:hover:bg-dark-700/50 ${
                      user.id === currentUserId ? 'bg-primary-50 dark:bg-primary-900/10' : ''
                    }`}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                          user.role === 'admin' 
                            ? 'bg-amber-100 dark:bg-amber-900/30' 
                            : 'bg-gray-100 dark:bg-dark-600'
                        }`}>
                          {user.role === 'admin' ? (
                            <Shield className="h-5 w-5 text-amber-600 dark:text-amber-400" />
                          ) : (
                            <UsersIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
                          )}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-gray-900 dark:text-white">
                              {user.username}
                            </span>
                            {user.id === currentUserId && (
                              <span className="px-2 py-0.5 text-xs font-medium bg-primary-100 dark:bg-primary-900/50 text-primary-700 dark:text-primary-400 rounded-full">
                                You
                              </span>
                            )}
                          </div>
                          {user.email && (
                            <div className="flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400">
                              <Mail className="h-3 w-3" />
                              {user.email}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        user.role === 'admin'
                          ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-400'
                          : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400'
                      }`}>
                        {user.role === 'admin' ? 'Admin' : 'User'}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => user.id !== currentUserId && handleToggleActive(user)}
                        disabled={user.id === currentUserId}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium transition-colors ${
                          user.is_active
                            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50'
                            : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-900/50'
                        } ${user.id === currentUserId ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}
                      >
                        {user.is_active ? (
                          <>
                            <UserCheck className="h-3 w-3" />
                            Active
                          </>
                        ) : (
                          <>
                            <UserX className="h-3 w-3" />
                            Inactive
                          </>
                        )}
                      </button>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        {user.totp_enabled ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400">
                            <Smartphone className="h-3 w-3" />
                            2FA
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-dark-600 text-gray-600 dark:text-gray-400">
                            <ShieldOff className="h-3 w-3" />
                            No 2FA
                          </span>
                        )}
                        {user.sessions_count > 0 && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400">
                            <LogOut className="h-3 w-3" />
                            {user.sessions_count}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400">
                        <Clock className="h-4 w-4" />
                        {formatDate(user.last_login)}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEditModal(user)}
                          className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-600 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
                          title="Edit"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        {user.id !== currentUserId && (
                          <>
                            <button
                              onClick={() => {
                                setSelectedUser(user)
                                setNewPassword('')
                                setShowResetPasswordModal(true)
                              }}
                              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-600 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
                              title="Reset Password"
                            >
                              <Key className="h-4 w-4" />
                            </button>
                            {user.totp_enabled && (
                              <button
                                onClick={() => handleDisable2FA(user)}
                                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-600 text-gray-500 hover:text-amber-600 dark:hover:text-amber-400 transition-colors"
                                title="Disable 2FA"
                              >
                                <ShieldOff className="h-4 w-4" />
                              </button>
                            )}
                          </>
                        )}
                        {user.sessions_count > 0 && (
                          <button
                            onClick={() => handleRevokeSessions(user)}
                            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-600 text-gray-500 hover:text-orange-600 dark:hover:text-orange-400 transition-colors"
                            title="Revoke Sessions"
                          >
                            <LogOut className="h-4 w-4" />
                          </button>
                        )}
                        {user.id !== currentUserId && (
                          <button
                            onClick={() => {
                              setSelectedUser(user)
                              setShowDeleteModal(true)
                            }}
                            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-600 text-gray-500 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-dark-800 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Create User</h2>
              <button
                onClick={() => { setShowCreateModal(false); setFormError(''); }}
                className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-700"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>
            
            {/* Error Message */}
            {formError && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{formError}</p>
              </div>
            )}
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Username *
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="Enter username"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="Enter email (optional)"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Password *
                </label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="Enter password"
                />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Min 8 characters, uppercase, lowercase, number, special character
                </p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Role
                </label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as 'admin' | 'user' })}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => { setShowCreateModal(false); setFormError(''); }}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-dark-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateUser}
                disabled={actionLoading}
                className="flex-1 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actionLoading ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Plus className="h-5 w-5" />
                    Create
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {showEditModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-dark-800 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Edit User: {selectedUser.username}
              </h2>
              <button
                onClick={() => setShowEditModal(false)}
                className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-700"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="Enter email (optional)"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Role
                </label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as 'admin' | 'user' })}
                  disabled={selectedUser.id === currentUserId}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent disabled:opacity-50"
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
                {selectedUser.id === currentUserId && (
                  <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
                    You cannot change your own role
                  </p>
                )}
              </div>
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowEditModal(false)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-dark-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdateUser}
                disabled={actionLoading}
                className="flex-1 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actionLoading ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Check className="h-5 w-5" />
                    Save
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete User Modal */}
      {showDeleteModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-dark-800 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-full bg-red-100 dark:bg-red-900/30">
                <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Delete User</h2>
            </div>
            
            <p className="text-gray-600 dark:text-gray-400 mb-6">
              Are you sure you want to delete user <strong>{selectedUser.username}</strong>? 
              This action cannot be undone.
            </p>
            
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-dark-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteUser}
                disabled={actionLoading}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actionLoading ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Trash2 className="h-5 w-5" />
                    Delete
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {showResetPasswordModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-dark-800 rounded-xl shadow-xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Reset Password: {selectedUser.username}
              </h2>
              <button
                onClick={() => { setShowResetPasswordModal(false); setFormError(''); }}
                className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-700"
              >
                <X className="h-5 w-5 text-gray-500" />
              </button>
            </div>
            
            {/* Error Message */}
            {formError && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{formError}</p>
              </div>
            )}
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                New Password *
              </label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-dark-600 bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="Enter new password"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Min 8 characters, uppercase, lowercase, number, special character
              </p>
              <p className="mt-2 text-sm text-amber-600 dark:text-amber-400">
                This will log out the user from all devices.
              </p>
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => { setShowResetPasswordModal(false); setFormError(''); }}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-dark-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleResetPassword}
                disabled={actionLoading || !newPassword}
                className="flex-1 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {actionLoading ? (
                  <RefreshCw className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Key className="h-5 w-5" />
                    Reset
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Users
