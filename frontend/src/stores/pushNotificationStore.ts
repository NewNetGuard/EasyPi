/**
 * Push Notification Store
 * 
 * Manages browser push notification subscriptions and state.
 * Uses Zustand for state management.
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { getCsrfHeaders } from '../utils/csrf'

interface PushNotificationState {
  // State
  isSupported: boolean
  permission: NotificationPermission | 'default'
  isSubscribed: boolean
  isLoading: boolean
  subscription: PushSubscription | null
  vapidPublicKey: string | null
  error: string | null
  
  // Actions
  initialize: () => Promise<void>
  requestPermission: () => Promise<boolean>
  subscribe: () => Promise<boolean>
  unsubscribe: () => Promise<boolean>
  sendTestNotification: () => Promise<boolean>
  checkSubscription: () => Promise<void>
  clearError: () => void
}

// Helper to convert base64 to Uint8Array for VAPID key
function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
  const base64 = (base64String + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  
  const rawData = window.atob(base64)
  const outputArray = new Uint8Array(rawData.length)
  
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i)
  }
  return outputArray
}

// Helper to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return window.btoa(binary)
}

function applicationServerKeysMatch(left: ArrayBuffer | null, right: Uint8Array): boolean {
  if (!left) return false
  const existing = new Uint8Array(left)
  return existing.length === right.length && existing.every((value, index) => value === right[index])
}

const API_BASE = '/api/v1'

export const usePushNotificationStore = create<PushNotificationState>()(
  persist(
    (set, get) => ({
      // Initial state
      isSupported: false,
      permission: 'default',
      isSubscribed: false,
      isLoading: false,
      subscription: null,
      vapidPublicKey: null,
      error: null,
      
      // Initialize the push notification system
      initialize: async () => {
        // Check browser support
        const isSupported = 'serviceWorker' in navigator && 
                           'PushManager' in window && 
                           'Notification' in window
        
        set({ isSupported })
        
        if (!isSupported) {
          set({ error: 'Push notifications are not supported in this browser' })
          return
        }
        
        // Get current permission
        const permission = Notification.permission
        set({ permission })
        
        try {
          // Register service worker
          await navigator.serviceWorker.register('/sw.js', {
            scope: '/'
          })
          
          // Wait for service worker to be ready
          await navigator.serviceWorker.ready
          
          // Get VAPID public key from server
          const response = await fetch(`${API_BASE}/notifications/push/vapid-key`, {
            credentials: 'include'  // Use httpOnly cookies
          })
          
          if (response.ok) {
            const data = await response.json()
            set({ vapidPublicKey: data.public_key })
          }
          
          // Check existing subscription
          await get().checkSubscription()
          
        } catch (error) {
          console.error('[Push] Initialization error:', error)
          set({ error: 'Failed to initialize push notifications' })
        }
      },
      
      // Request notification permission
      requestPermission: async () => {
        set({ isLoading: true, error: null })
        
        try {
          const permission = await Notification.requestPermission()
          set({ permission })
          
          if (permission === 'granted') {
            // Auto-subscribe after permission granted
            return await get().subscribe()
          }
          
          if (permission === 'denied') {
            set({ error: 'Notification permission was denied' })
          }
          
          return false
        } catch (error) {
          console.error('[Push] Permission request error:', error)
          set({ error: 'Failed to request notification permission' })
          return false
        } finally {
          set({ isLoading: false })
        }
      },
      
      // Subscribe to push notifications
      subscribe: async () => {
        const { vapidPublicKey, permission } = get()
        
        if (permission !== 'granted') {
          set({ error: 'Notification permission not granted' })
          return false
        }
        
        if (!vapidPublicKey) {
          set({ error: 'VAPID key not available' })
          return false
        }
        
        set({ isLoading: true, error: null })
        
        try {
          const registration = await navigator.serviceWorker.ready
          
          // Subscribe to push manager
          const applicationServerKey = urlBase64ToUint8Array(vapidPublicKey)
          const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: applicationServerKey as BufferSource
          })
          
          // Send subscription to server
          const csrfHeaders = await getCsrfHeaders()
          const response = await fetch(`${API_BASE}/notifications/push/subscribe`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...csrfHeaders,
            },
            credentials: 'include',  // Use httpOnly cookies
            body: JSON.stringify({
              endpoint: subscription.endpoint,
              keys: {
                p256dh: arrayBufferToBase64(subscription.getKey('p256dh')!),
                auth: arrayBufferToBase64(subscription.getKey('auth')!)
              },
              user_agent: navigator.userAgent
            })
          })
          
          if (!response.ok) {
            throw new Error('Failed to register subscription with server')
          }
          
          set({ 
            isSubscribed: true, 
            subscription,
            error: null 
          })
          return true
          
        } catch (error) {
          console.error('[Push] Subscription error:', error)
          set({ error: 'Failed to subscribe to push notifications' })
          return false
        } finally {
          set({ isLoading: false })
        }
      },
      
      // Unsubscribe from push notifications
      unsubscribe: async () => {
        const { subscription } = get()
        
        set({ isLoading: true, error: null })
        
        try {
          if (subscription) {
            // Remove the server record before invalidating the browser object.
            const csrfHeaders = await getCsrfHeaders()
            const response = await fetch(`${API_BASE}/notifications/push/unsubscribe`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...csrfHeaders,
              },
              credentials: 'include',  // Use httpOnly cookies
              body: JSON.stringify({
                endpoint: subscription.endpoint,
                keys: {
                  p256dh: arrayBufferToBase64(subscription.getKey('p256dh')!),
                  auth: arrayBufferToBase64(subscription.getKey('auth')!)
                }
              })
            })
            if (!response.ok) {
              throw new Error('Failed to remove subscription from server')
            }
            await subscription.unsubscribe()
          }
          
          set({ 
            isSubscribed: false, 
            subscription: null,
            error: null 
          })
          return true
          
        } catch (error) {
          console.error('[Push] Unsubscribe error:', error)
          set({ error: 'Failed to unsubscribe from push notifications' })
          return false
        } finally {
          set({ isLoading: false })
        }
      },
      
      // Send test notification
      sendTestNotification: async () => {
        set({ isLoading: true, error: null })
        
        try {
          const csrfHeaders = await getCsrfHeaders()
          const response = await fetch(`${API_BASE}/notifications/push/test`, {
            method: 'POST',
            credentials: 'include',  // Use httpOnly cookies
            headers: csrfHeaders,
          })
          
          if (!response.ok) {
            const data = await response.json()
            throw new Error(data.detail || 'Failed to send test notification')
          }
          const data = await response.json()
          if (!data.success) {
            throw new Error(data.message || 'Test notification was not delivered')
          }
          return true
        } catch (error: any) {
          console.error('[Push] Test notification error:', error)
          set({ error: error.message || 'Failed to send test notification' })
          return false
        } finally {
          set({ isLoading: false })
        }
      },
      
      // Check current subscription status
      checkSubscription: async () => {
        try {
          const registration = await navigator.serviceWorker.ready
          let subscription = await registration.pushManager.getSubscription()
          const { vapidPublicKey, isSubscribed: wantedSubscription, permission } = get()

          if (subscription && vapidPublicKey) {
            const expectedKey = urlBase64ToUint8Array(vapidPublicKey)
            if (!applicationServerKeysMatch(subscription.options.applicationServerKey, expectedKey)) {
              await subscription.unsubscribe()
              subscription = null
            }
          }

          if (!subscription && wantedSubscription && permission === 'granted' && vapidPublicKey) {
            await get().subscribe()
            return
          }

          if (subscription) {
            const csrfHeaders = await getCsrfHeaders()
            const response = await fetch(`${API_BASE}/notifications/push/subscribe`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', ...csrfHeaders },
              credentials: 'include',
              body: JSON.stringify({
                endpoint: subscription.endpoint,
                keys: {
                  p256dh: arrayBufferToBase64(subscription.getKey('p256dh')!),
                  auth: arrayBufferToBase64(subscription.getKey('auth')!),
                },
                user_agent: navigator.userAgent,
              }),
            })
            if (!response.ok && response.status !== 409) {
              throw new Error('Failed to synchronize push subscription')
            }
          }
          
          set({ 
            isSubscribed: subscription !== null,
            subscription 
          })
        } catch (error) {
          console.error('[Push] Check subscription error:', error)
        }
      },
      
      // Clear error
      clearError: () => set({ error: null })
    }),
    {
      name: 'push-notification-storage',
      partialize: (state) => ({
        isSubscribed: state.isSubscribed
      })
    }
  )
)

// Hook to initialize push notifications on app load
export function initializePushNotifications() {
  const store = usePushNotificationStore.getState()
  if (store.isSupported === false) {
    store.initialize()
  }
}
