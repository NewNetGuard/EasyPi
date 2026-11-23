/**
 * PWA Install Prompt Component
 * 
 * Shows a banner prompting users to install the app.
 * Handles iOS Safari (manual instructions) and other browsers (native prompt).
 */

import { useEffect, useState } from 'react'
import { X, Download, Share, Plus } from 'lucide-react'
import { usePWAInstallStore, initPWAInstall } from '../../stores/pwaInstallStore'

export default function PWAInstallPrompt() {
  const {
    isInstallable,
    isInstalled,
    isIOS,
    installDismissed,
    lastDismissed,
    install,
    dismiss
  } = usePWAInstallStore()
  
  const [showIOSInstructions, setShowIOSInstructions] = useState(false)
  
  // Initialize on mount
  useEffect(() => {
    initPWAInstall()
  }, [])
  
  // Don't show if already installed
  if (isInstalled) {
    return null
  }
  
  // Don't show if recently dismissed (show again after 7 days)
  if (installDismissed && lastDismissed) {
    const daysSinceDismiss = (Date.now() - lastDismissed) / (1000 * 60 * 60 * 24)
    if (daysSinceDismiss < 7) {
      return null
    }
  }
  
  // iOS - show instructions to add to home screen
  if (isIOS) {
    return (
      <>
        <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-4 sm:w-80 bg-white dark:bg-dark-800 rounded-xl shadow-lg border border-gray-200 dark:border-dark-700 p-4 z-50 animate-slide-up">
          <button
            onClick={dismiss}
            className="absolute top-2 right-2 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
          
          <div className="flex items-start gap-3">
            <div className="p-2 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
              <Download className="h-6 w-6 text-primary-600 dark:text-primary-400" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-gray-900 dark:text-white text-sm">
                Install EasyPi
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Add to your home screen for quick access
              </p>
              <button
                onClick={() => setShowIOSInstructions(true)}
                className="mt-2 text-xs font-medium text-primary-600 dark:text-primary-400 hover:underline"
              >
                Show me how →
              </button>
            </div>
          </div>
        </div>
        
        {/* iOS Instructions Modal */}
        {showIOSInstructions && (
          <div className="fixed inset-0 bg-black/50 flex items-end sm:items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-dark-800 rounded-xl w-full max-w-sm overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-dark-700 flex items-center justify-between">
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  Install on iOS
                </h3>
                <button
                  onClick={() => setShowIOSInstructions(false)}
                  className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              
              <div className="p-4 space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center text-primary-600 dark:text-primary-400 font-bold text-sm">
                    1
                  </div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white font-medium">
                      Tap the Share button
                    </p>
                    <div className="mt-1 flex items-center gap-1 text-xs text-gray-500">
                      <Share className="h-4 w-4" />
                      <span>at the bottom of your browser</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center text-primary-600 dark:text-primary-400 font-bold text-sm">
                    2
                  </div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white font-medium">
                      Scroll and tap "Add to Home Screen"
                    </p>
                    <div className="mt-1 flex items-center gap-1 text-xs text-gray-500">
                      <Plus className="h-4 w-4" />
                      <span>in the share menu</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center text-primary-600 dark:text-primary-400 font-bold text-sm">
                    3
                  </div>
                  <div>
                    <p className="text-sm text-gray-900 dark:text-white font-medium">
                      Tap "Add" to confirm
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      EasyPi will appear on your home screen
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="p-4 bg-gray-50 dark:bg-dark-900">
                <button
                  onClick={() => {
                    setShowIOSInstructions(false)
                    dismiss()
                  }}
                  className="w-full py-2 px-4 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
                >
                  Got it!
                </button>
              </div>
            </div>
          </div>
        )}
      </>
    )
  }
  
  // Other browsers - show install prompt if available
  if (!isInstallable) {
    return null
  }
  
  const handleInstall = async () => {
    const success = await install()
    if (!success) {
      dismiss()
    }
  }
  
  return (
    <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-4 sm:w-80 bg-white dark:bg-dark-800 rounded-xl shadow-lg border border-gray-200 dark:border-dark-700 p-4 z-50 animate-slide-up">
      <button
        onClick={dismiss}
        className="absolute top-2 right-2 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        aria-label="Close"
      >
        <X className="h-4 w-4" />
      </button>
      
      <div className="flex items-start gap-3">
        <div className="p-2 bg-gradient-to-br from-primary-500 to-purple-500 rounded-lg">
          <Download className="h-6 w-6 text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="font-semibold text-gray-900 dark:text-white text-sm">
            Install EasyPi
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Install for faster access and offline use
          </p>
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleInstall}
              className="flex-1 py-1.5 px-3 bg-primary-600 text-white text-xs font-medium rounded-lg hover:bg-primary-700 transition-colors"
            >
              Install
            </button>
            <button
              onClick={dismiss}
              className="py-1.5 px-3 text-gray-600 dark:text-gray-400 text-xs font-medium rounded-lg hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors"
            >
              Not now
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
