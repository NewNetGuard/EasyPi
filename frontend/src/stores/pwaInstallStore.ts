/**
 * PWA Install Store
 * 
 * Manages the PWA installation prompt and state.
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>
}

interface PWAInstallState {
  // State
  isInstallable: boolean
  isInstalled: boolean
  isIOS: boolean
  deferredPrompt: BeforeInstallPromptEvent | null
  installDismissed: boolean
  lastDismissed: number | null
  
  // Actions
  setDeferredPrompt: (prompt: BeforeInstallPromptEvent | null) => void
  install: () => Promise<boolean>
  dismiss: () => void
  resetDismiss: () => void
  checkInstalled: () => void
}

// Check if running as standalone PWA
function isRunningStandalone(): boolean {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    (window.navigator as any).standalone === true ||
    document.referrer.includes('android-app://')
  )
}

// Check if iOS
function isIOS(): boolean {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !(window as any).MSStream
}

export const usePWAInstallStore = create<PWAInstallState>()(
  persist(
    (set, get) => ({
      isInstallable: false,
      isInstalled: false,
      isIOS: isIOS(),
      deferredPrompt: null,
      installDismissed: false,
      lastDismissed: null,
      
      setDeferredPrompt: (prompt) => {
        set({ 
          deferredPrompt: prompt,
          isInstallable: prompt !== null
        })
      },
      
      install: async () => {
        const { deferredPrompt } = get()
        
        if (!deferredPrompt) {
          return false
        }
        
        try {
          // Show the install prompt
          await deferredPrompt.prompt()
          
          // Wait for user choice
          const { outcome } = await deferredPrompt.userChoice
          
          if (outcome === 'accepted') {
            set({ 
              isInstalled: true,
              isInstallable: false,
              deferredPrompt: null
            })
            return true
          }
          
          return false
        } catch (error) {
          console.error('[PWA] Install error:', error)
          return false
        }
      },
      
      dismiss: () => {
        set({ 
          installDismissed: true,
          lastDismissed: Date.now()
        })
      },
      
      resetDismiss: () => {
        set({ 
          installDismissed: false,
          lastDismissed: null
        })
      },
      
      checkInstalled: () => {
        const installed = isRunningStandalone()
        set({ isInstalled: installed })
      }
    }),
    {
      name: 'pwa-install-storage',
      partialize: (state) => ({
        installDismissed: state.installDismissed,
        lastDismissed: state.lastDismissed
      })
    }
  )
)

// Initialize PWA install prompt listener
export function initPWAInstall() {
  const store = usePWAInstallStore.getState()
  
  // Check if already installed
  store.checkInstalled()
  
  // Listen for beforeinstallprompt event
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault()
    store.setDeferredPrompt(e as BeforeInstallPromptEvent)
  })
  
  // Listen for app installed event
  window.addEventListener('appinstalled', () => {
    store.setDeferredPrompt(null)
    usePWAInstallStore.setState({ isInstalled: true })
  })
  
  // Check display mode changes
  window.matchMedia('(display-mode: standalone)').addEventListener('change', (e) => {
    if (e.matches) {
      usePWAInstallStore.setState({ isInstalled: true })
    }
  })
}
