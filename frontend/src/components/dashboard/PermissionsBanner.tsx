import { useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, X, Settings, ArrowRight } from 'lucide-react'
import { useSystemSetup } from '../../hooks/useSystemSetup'

const PermissionsBanner = () => {
  const { needsSetup, loading, setShowWizard } = useSystemSetup()
  const [dismissed, setDismissed] = useState(false)

  if (loading || !needsSetup || dismissed) {
    return null
  }

  return (
    <div className="mb-6 relative overflow-hidden rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 p-4 shadow-lg">
      {/* Background pattern */}
      <div className="absolute inset-0 opacity-10">
        <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
            <path d="M 10 0 L 0 0 0 10" fill="none" stroke="currentColor" strokeWidth="0.5"/>
          </pattern>
          <rect width="100" height="100" fill="url(#grid)" />
        </svg>
      </div>

      <div className="relative flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex-shrink-0 w-12 h-12 rounded-full bg-white/20 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="font-semibold text-white">
              Limited Functionality
            </h3>
            <p className="text-sm text-white/80">
              Some features like firewall and backups require additional permissions
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 px-4 py-2 bg-white text-orange-600 font-medium rounded-lg hover:bg-white/90 transition-colors"
          >
            <Settings className="w-4 h-4" />
            Setup Now
          </button>
          
          <Link
            to="/settings"
            className="hidden sm:flex items-center gap-1 text-white/80 hover:text-white text-sm transition-colors"
          >
            Settings
            <ArrowRight className="w-4 h-4" />
          </Link>
          
          <button
            onClick={() => setDismissed(true)}
            className="p-1 text-white/60 hover:text-white transition-colors"
            title="Dismiss"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default PermissionsBanner
