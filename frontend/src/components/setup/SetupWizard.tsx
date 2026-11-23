import { useState } from 'react'
import { 
  Shield, 
  CheckCircle, 
  XCircle,
  RefreshCw,
  Rocket,
  Lock,
  Server,
  ArrowRight,
  X
} from 'lucide-react'
import { setupPermissions, getPermissionsStatus, PermissionStatus } from '../../api/system'

interface SetupWizardProps {
  onComplete: () => void
  onSkip: () => void
}

const SetupWizard = ({ onComplete, onSkip }: SetupWizardProps) => {
  const [step, setStep] = useState<'welcome' | 'permissions' | 'setting-up' | 'complete' | 'error'>('welcome')
  const [error, setError] = useState<string | null>(null)
  // const [permissionStatus, setPermissionStatus] = useState<PermissionStatus | null>(null)
  const [, setPermissionStatus] = useState<PermissionStatus | null>(null)

  const handleSetupPermissions = async () => {
    setStep('setting-up')
    setError(null)
    
    try {
      const result = await setupPermissions()
      
      // Check if this is development mode (Windows)
      if (result.message.includes('Development mode') || result.message.includes('Windows')) {
        // Development mode - just complete
        setStep('complete')
        return
      }
      
      if (result.message.includes('restarting')) {
        // Wait for backend to restart
        await new Promise(resolve => setTimeout(resolve, 3000))
        
        // Poll for backend to come back
        let attempts = 0
        const maxAttempts = 15
        
        while (attempts < maxAttempts) {
          try {
            const status = await getPermissionsStatus()
            setPermissionStatus(status)
            if (status.permissions_ok) {
              setStep('complete')
              return
            }
            break
          } catch {
            attempts++
            await new Promise(resolve => setTimeout(resolve, 2000))
          }
        }
        
        // If we got here, check status one more time
        try {
          const status = await getPermissionsStatus()
          setPermissionStatus(status)
          setStep(status.permissions_ok ? 'complete' : 'error')
        } catch {
          setError('Backend restart timed out. Please refresh the page.')
          setStep('error')
        }
      } else {
        // No restart needed - could be already configured or development mode
        setStep('complete')
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to setup permissions')
      setStep('error')
    }
  }

  const features = [
    { icon: Shield, title: 'Firewall Management', desc: 'Configure UFW firewall rules' },
    { icon: Server, title: 'System Backups', desc: 'Create and restore backups' },
    { icon: Lock, title: 'Security Settings', desc: 'Manage SSH and users' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="relative w-full max-w-lg mx-4 bg-white dark:bg-dark-900 rounded-2xl shadow-2xl overflow-hidden">
        {/* Close button */}
        <button 
          onClick={onSkip}
          className="absolute top-4 right-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Welcome Step */}
        {step === 'welcome' && (
          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center">
                <Rocket className="w-10 h-10 text-white" />
              </div>
            </div>
            
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              Welcome to EasyPi!
            </h2>
            <p className="text-center text-gray-500 dark:text-gray-400 mb-8">
              Let's set up your system for the best experience
            </p>

            <div className="space-y-3 mb-8">
              {features.map((feature, i) => (
                <div key={i} className="flex items-center gap-4 p-3 bg-gray-50 dark:bg-dark-800 rounded-lg">
                  <div className="w-10 h-10 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
                    <feature.icon className="w-5 h-5 text-primary-600 dark:text-primary-400" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{feature.title}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{feature.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <button
              onClick={() => setStep('permissions')}
              className="w-full py-3 px-4 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg flex items-center justify-center gap-2 transition-colors"
            >
              Get Started
              <ArrowRight className="w-5 h-5" />
            </button>
            
            <button
              onClick={onSkip}
              className="w-full mt-3 py-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 text-sm transition-colors"
            >
              Skip for now
            </button>
          </div>
        )}

        {/* Permissions Step */}
        {step === 'permissions' && (
          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center">
                <Shield className="w-10 h-10 text-white" />
              </div>
            </div>
            
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              System Permissions
            </h2>
            <p className="text-center text-gray-500 dark:text-gray-400 mb-6">
              EasyPi needs elevated permissions for some features
            </p>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
              <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">
                What this does:
              </h4>
              <ul className="text-sm text-blue-700 dark:text-blue-300 space-y-1">
                <li>• Creates an <code className="bg-blue-200 dark:bg-blue-800 px-1 rounded">easypi</code> group</li>
                <li>• Adds your user to this group</li>
                <li>• Grants limited sudo access for EasyPi commands only</li>
              </ul>
            </div>

            <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 mb-6">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                <strong className="text-gray-900 dark:text-white">Note:</strong> This is not full root access. 
                Only specific commands needed by EasyPi will be allowed.
              </p>
            </div>

            <button
              onClick={handleSetupPermissions}
              className="w-full py-3 px-4 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg flex items-center justify-center gap-2 transition-colors"
            >
              <Shield className="w-5 h-5" />
              Grant Permissions
            </button>
            
            <button
              onClick={onSkip}
              className="w-full mt-3 py-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 text-sm transition-colors"
            >
              Skip (some features won't work)
            </button>
          </div>
        )}

        {/* Setting Up Step */}
        {step === 'setting-up' && (
          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center">
                <RefreshCw className="w-10 h-10 text-white animate-spin" />
              </div>
            </div>
            
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              Setting Up...
            </h2>
            <p className="text-center text-gray-500 dark:text-gray-400 mb-4">
              Configuring system permissions
            </p>
            
            <div className="flex justify-center">
              <div className="flex gap-1">
                <div className="w-2 h-2 rounded-full bg-primary-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 rounded-full bg-primary-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 rounded-full bg-primary-500 animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}

        {/* Complete Step */}
        {step === 'complete' && (
          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
                <CheckCircle className="w-10 h-10 text-white" />
              </div>
            </div>
            
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              All Set!
            </h2>
            <p className="text-center text-gray-500 dark:text-gray-400 mb-8">
              EasyPi is ready to use with full functionality
            </p>

            <div className="grid grid-cols-2 gap-3 mb-8">
              <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <span className="text-sm text-green-700 dark:text-green-300">Group created</span>
              </div>
              <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <span className="text-sm text-green-700 dark:text-green-300">User added</span>
              </div>
              <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <span className="text-sm text-green-700 dark:text-green-300">Sudo configured</span>
              </div>
              <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <span className="text-sm text-green-700 dark:text-green-300">Ready to go!</span>
              </div>
            </div>

            <button
              onClick={onComplete}
              className="w-full py-3 px-4 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg flex items-center justify-center gap-2 transition-colors"
            >
              Start Using EasyPi
              <ArrowRight className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Error Step */}
        {step === 'error' && (
          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-red-500 to-rose-600 flex items-center justify-center">
                <XCircle className="w-10 h-10 text-white" />
              </div>
            </div>
            
            <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-2">
              Setup Failed
            </h2>
            <p className="text-center text-gray-500 dark:text-gray-400 mb-4">
              {error || 'Something went wrong during setup'}
            </p>

            <div className="flex gap-3">
              <button
                onClick={() => setStep('permissions')}
                className="flex-1 py-3 px-4 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
              >
                Try Again
              </button>
              <button
                onClick={onSkip}
                className="flex-1 py-3 px-4 border border-gray-300 dark:border-dark-700 text-gray-700 dark:text-gray-300 font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-dark-800 transition-colors"
              >
                Skip
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default SetupWizard
