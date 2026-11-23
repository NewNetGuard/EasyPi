/**
 * Push Notification Settings Component
 * 
 * Allows users to enable/disable browser push notifications
 * and manage notification preferences.
 */

import { useEffect } from 'react'
import { Bell, BellOff, Check, AlertCircle, Loader2, Send } from 'lucide-react'
import { usePushNotificationStore } from '../../stores/pushNotificationStore'
import Button from '../common/Button'
import { toast } from 'react-hot-toast'

export default function PushNotificationSettings() {
  const {
    isSupported,
    permission,
    isSubscribed,
    isLoading,
    error,
    initialize,
    requestPermission,
    subscribe,
    unsubscribe,
    sendTestNotification,
    clearError
  } = usePushNotificationStore()
  
  // Initialize on mount
  useEffect(() => {
    initialize()
  }, [initialize])
  
  // Show error toast
  useEffect(() => {
    if (error) {
      toast.error(error)
      clearError()
    }
  }, [error, clearError])
  
  const handleToggle = async () => {
    if (isSubscribed) {
      const success = await unsubscribe()
      if (success) {
        toast.success('Push notifications disabled')
      }
    } else {
      if (permission !== 'granted') {
        const granted = await requestPermission()
        if (granted) {
          toast.success('Push notifications enabled!')
        }
      } else {
        const success = await subscribe()
        if (success) {
          toast.success('Push notifications enabled!')
        }
      }
    }
  }
  
  const handleTestNotification = async () => {
    const success = await sendTestNotification()
    if (success) {
      toast.success('Test notification sent!')
    }
  }
  
  // Browser doesn't support push
  if (!isSupported) {
    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-4 border border-yellow-200 dark:border-yellow-800">
        <div className="flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 mt-0.5" />
          <div>
            <h4 className="font-medium text-yellow-800 dark:text-yellow-200">
              Push Notifications Not Supported
            </h4>
            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
              Your browser doesn't support push notifications. Try using a modern browser like Chrome, Firefox, or Edge.
            </p>
          </div>
        </div>
      </div>
    )
  }
  
  // Permission denied
  if (permission === 'denied') {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4 border border-red-200 dark:border-red-800">
        <div className="flex items-start gap-3">
          <BellOff className="h-5 w-5 text-red-600 dark:text-red-400 mt-0.5" />
          <div>
            <h4 className="font-medium text-red-800 dark:text-red-200">
              Notifications Blocked
            </h4>
            <p className="text-sm text-red-700 dark:text-red-300 mt-1">
              Push notifications are blocked in your browser settings. To enable them, click the lock icon in your browser's address bar and allow notifications.
            </p>
          </div>
        </div>
      </div>
    )
  }
  
  return (
    <div className="space-y-4">
      {/* Main toggle card */}
      <div className="bg-white dark:bg-dark-800 rounded-lg border border-gray-200 dark:border-dark-700 p-4 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-full ${
              isSubscribed 
                ? 'bg-green-100 dark:bg-green-900/30' 
                : 'bg-gray-100 dark:bg-dark-700'
            }`}>
              {isSubscribed ? (
                <Bell className="h-6 w-6 text-green-600 dark:text-green-400" />
              ) : (
                <BellOff className="h-6 w-6 text-gray-500 dark:text-gray-400" />
              )}
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                Browser Push Notifications
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                {isSubscribed 
                  ? 'You will receive push notifications for important system events'
                  : 'Enable to receive real-time alerts even when EasyPi is not open'
                }
              </p>
              {isSubscribed && (
                <div className="flex items-center gap-1.5 mt-2 text-sm text-green-600 dark:text-green-400">
                  <Check className="h-4 w-4" />
                  <span>Notifications enabled</span>
                </div>
              )}
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {isSubscribed && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleTestNotification}
                disabled={isLoading}
                icon={<Send className="h-4 w-4" />}
              >
                Test
              </Button>
            )}
            <Button
              variant={isSubscribed ? 'outline' : 'primary'}
              onClick={handleToggle}
              disabled={isLoading}
              icon={isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : undefined}
            >
              {isLoading 
                ? 'Processing...' 
                : isSubscribed 
                  ? 'Disable' 
                  : 'Enable Notifications'
              }
            </Button>
          </div>
        </div>
      </div>
      
      {/* Notification types info */}
      {isSubscribed && (
        <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-4 border border-gray-200 dark:border-dark-700">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
            You'll be notified about:
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <NotificationTypeItem 
              icon="🔒" 
              title="Security Alerts" 
              description="Login attempts, suspicious activity"
            />
            <NotificationTypeItem 
              icon="💾" 
              title="Backup Status" 
              description="Backup completion and failures"
            />
            <NotificationTypeItem 
              icon="🔧" 
              title="Service Status" 
              description="Service starts, stops, and errors"
            />
            <NotificationTypeItem 
              icon="🆕" 
              title="Updates" 
              description="New EasyPi versions available"
            />
          </div>
        </div>
      )}
    </div>
  )
}

function NotificationTypeItem({ 
  icon, 
  title, 
  description 
}: { 
  icon: string
  title: string
  description: string 
}) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-lg">{icon}</span>
      <div>
        <p className="text-sm font-medium text-gray-700 dark:text-gray-300">{title}</p>
        <p className="text-xs text-gray-500 dark:text-gray-400">{description}</p>
      </div>
    </div>
  )
}
