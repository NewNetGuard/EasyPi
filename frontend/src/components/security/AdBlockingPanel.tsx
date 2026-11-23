/**
 * Ad Blocking Panel
 * 
 * Beautiful, user-friendly blocklist management interface.
 * Two-layer system: Verified (CC0/MIT) + Custom sources
 */
import React, { useState, useRef } from 'react'
import { toast } from 'react-hot-toast'
import {
  Shield,
  ShieldCheck,
  Download,
  RefreshCw,
  Globe,
  Lock,
  Unlock,
  Clock,
  FileText,
  Plus,
  Trash2,
  AlertTriangle,
  Upload,
  Zap,
  Sparkles,
  Info,
} from 'lucide-react'
import {
  useBlocklistStatus,
  useCustomSources,
  useGenerateBlocklists,
  useGenerationProgress,
  useAddCustomSource,
  useUploadCustomBlocklistFile,
  useRemoveCustomSource,
  useGetUseCustomBlocklist,
  useSetUseCustomBlocklist,
} from '../../hooks/useNetProtection'
import { setVerifiedSourceEnabled, type BlocklistSource } from '../../api/netProtectionBlocklistsApi'

export default function AdBlockingPanel() {
  const { data: blocklistStatus, refetch: refetchStatus } = useBlocklistStatus()
  const { data: customSources } = useCustomSources()
  const { data: generationProgress } = useGenerationProgress()
  const { data: useCustomStatus } = useGetUseCustomBlocklist()
  
  const generateBlocklists = useGenerateBlocklists()
  const addCustomSource = useAddCustomSource()
  const uploadCustomFile = useUploadCustomBlocklistFile()
  const removeCustomSource = useRemoveCustomSource()
  const setUseCustomBlocklist = useSetUseCustomBlocklist()
  
  const [showAddModal, setShowAddModal] = useState(false)
  // Source pending a license-consent tick (GPL / NonCommercial sources are opt-in).
  const [consentSource, setConsentSource] = useState<BlocklistSource | null>(null)
  const [consentChecked, setConsentChecked] = useState(false)

  const handleToggleVerified = async (source: BlocklistSource, enabled: boolean) => {
    // Enabling a non-permissive (GPL/NC) source requires an explicit license tick first.
    if (enabled && source.requires_consent) {
      setConsentChecked(false)
      setConsentSource(source)
      return
    }
    try {
      await setVerifiedSourceEnabled(source.id, enabled)
      toast.success(enabled ? `Enabled ${source.name}` : `Disabled ${source.name}`)
      refetchStatus()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to update source')
    }
  }

  const confirmConsentEnable = async () => {
    if (!consentSource || !consentChecked) return
    try {
      await setVerifiedSourceEnabled(consentSource.id, true, true)
      toast.success(`Enabled ${consentSource.name}`)
      setConsentSource(null)
      refetchStatus()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to enable source')
    }
  }

  const isGenerating = generateBlocklists.isPending || 
    !!(generationProgress && generationProgress.phase !== 'done')
  const handleGenerateBlocklists = async () => {
    try {
      const result = await generateBlocklists.mutateAsync()
      if (result.error) {
        toast.error(result.error)
        return
      }
      const total = result.effective?.total_domains || 0
      toast.success(`Protection updated! ${total.toLocaleString()} domains blocked.`)
      refetchStatus()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to update blocklist')
    }
  }

  const totalDomains = blocklistStatus?.effective?.total_domains || 0
  const verifiedDomains = blocklistStatus?.effective?.verified_domains || 0
  const customSourcesCount =
    customSources?.length ?? blocklistStatus?.custom_sources?.length ?? 0
  const customDomainsFromSources = (customSources || blocklistStatus?.custom_sources || [])
    .reduce((sum, source) => sum + (source.domain_count || 0), 0)
  const customDomains = blocklistStatus?.effective?.custom_domains || 0
  const isUsingCustom = !!useCustomStatus?.use_custom
  const customDomainsTotal = customDomainsFromSources || customDomains
  const displayTotalDomains = isUsingCustom ? customDomainsTotal : totalDomains
  const displayVerifiedDomains = isUsingCustom ? customDomainsTotal : verifiedDomains
  const lastUpdate = blocklistStatus?.effective?.generated_at
  const isActive = displayTotalDomains > 0
  const verifiedCardLabel = isUsingCustom ? 'Active List' : 'Verified Sources'
  const verifiedCardBadge = isUsingCustom ? 'Custom' : 'Sources'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            <Shield className="w-10 h-10 sm:w-16 sm:h-16 text-indigo-600 dark:text-indigo-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                Ad &amp; Tracker Blocking
              </h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Protect your network from ads, trackers, and malicious domains
              </p>
            </div>
          </div>
          <button
            onClick={handleGenerateBlocklists}
            disabled={isGenerating}
            className="px-3 sm:px-4 py-2 sm:py-2.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:opacity-50 text-white rounded-xl transition-all shadow-lg shadow-indigo-500/25 flex items-center justify-center gap-2 font-medium text-sm sm:text-base w-full sm:w-auto"
          >
            {isGenerating ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            {isGenerating ? 'Updating...' : 'Update Blocklists'}
          </button>
        </div>
      </div>

      {/* Generation Progress */}
      {isGenerating && generationProgress && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-indigo-50 to-purple-50 dark:from-indigo-900/20 dark:to-purple-900/20 border border-indigo-200 dark:border-indigo-800">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-indigo-500 animate-pulse" />
              <span className="font-medium text-indigo-700 dark:text-indigo-300">
                {generationProgress.message || 'Downloading blocklists...'}
              </span>
            </div>
            <span className="text-sm font-bold text-indigo-600 dark:text-indigo-400">
              {generationProgress.progress_percent || 0}%
            </span>
          </div>
          <div className="w-full bg-indigo-200 dark:bg-indigo-900/50 rounded-full h-3 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-indigo-500 to-purple-500 h-3 rounded-full transition-all duration-300 relative"
              style={{ width: `${generationProgress.progress_percent || 0}%` }}
            >
              <div className="absolute inset-0 bg-white/20 animate-pulse" />
            </div>
          </div>
          {generationProgress.domains_collected > 0 && (
            <div className="mt-2 text-sm text-indigo-600 dark:text-indigo-400 flex items-center gap-2">
              <Sparkles className="w-4 h-4" />
              {generationProgress.domains_collected.toLocaleString()} domains collected
            </div>
          )}
        </div>
      )}

      {/* Status Overview Card */}
      <div className={`rounded-2xl p-4 sm:p-6 ${
        isActive 
          ? 'bg-gradient-to-br from-green-500 to-emerald-600' 
          : 'bg-gradient-to-br from-gray-400 to-gray-500'
      } text-white shadow-xl`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="p-3 sm:p-4 rounded-2xl bg-white/20 backdrop-blur-sm">
              {isActive ? (
                <ShieldCheck className="w-8 h-8 sm:w-10 sm:h-10" />
              ) : (
                <Shield className="w-8 h-8 sm:w-10 sm:h-10" />
              )}
            </div>
            <div>
              <h3 className="text-lg sm:text-xl font-bold">
                {isActive ? 'Protection Active' : 'No Protection'}
              </h3>
              <p className="text-white/80 text-xs sm:text-sm mt-1">
                {isActive 
                  ? isUsingCustom
                    ? `Blocking ${displayTotalDomains.toLocaleString()} domains from custom list`
                    : `Blocking ${displayTotalDomains.toLocaleString()} malicious domains`
                  : 'Click "Update Blocklists" to enable protection'
                }
              </p>
            </div>
          </div>
          <div className="text-left sm:text-right">
            <div className="text-3xl sm:text-4xl font-bold">
              {displayTotalDomains.toLocaleString()}
            </div>
            <div className="text-white/70 text-xs sm:text-sm">domains blocked</div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <StatCard
          icon={<Globe className="w-5 h-5 text-indigo-500" />}
          label="Total Domains"
          value={displayTotalDomains.toLocaleString()}
          color="indigo"
        />
        <StatCard
          icon={<Lock className="w-5 h-5 text-green-500" />}
          label={verifiedCardLabel}
          value={displayVerifiedDomains.toLocaleString()}
          color="green"
          badge={verifiedCardBadge}
        />
        <StatCard
          icon={<Unlock className="w-5 h-5 text-amber-500" />}
          label="Custom Sources"
          value={customSourcesCount.toLocaleString()}
          color="amber"
        />
        <StatCard
          icon={<Clock className="w-5 h-5 text-blue-500" />}
          label="Last Update"
          value={lastUpdate ? formatDate(lastUpdate) : 'Never'}
          color="blue"
        />
      </div>

      {/* Two Sections: Verified + Custom */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Verified Sources */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm border border-gray-100 dark:border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-green-100 dark:bg-green-900/30">
                <Lock className="w-4 h-4 text-green-600 dark:text-green-400" />
              </div>
              Verified Sources
            </h3>
            <span className="px-2.5 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
              {!useCustomStatus?.use_custom ? 'ACTIVE' : 'Available'}
            </span>
          </div>
          
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Third-party lists are downloaded directly to this device and are never bundled with EasyPi.
            Some sources require one-time acknowledgement before enabling.
          </p>
          
          <div className="space-y-2">
            {(blocklistStatus?.verified_sources || []).map((source) => (
              <div
                key={source.id}
                className="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="min-w-0">
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {source.name}
                    </span>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate cursor-help" title={source.description}>{source.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2.5 flex-shrink-0">
                  <a
                    href={source.info_url || source.url}
                    target="_blank"
                    rel="noreferrer"
                    className={`text-[10px] px-1.5 py-0.5 rounded font-medium hover:underline ${
                      source.requires_consent
                        ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                    }`}
                    title="View source & license"
                  >
                    {source.license}
                  </a>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={source.enabled}
                      onChange={(e) => handleToggleVerified(source, e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-gray-200 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-green-500"></div>
                  </label>
                </div>
              </div>
            ))}
          </div>
          
          {/* Status bar */}
          <div className={`mt-4 p-3 rounded-xl flex items-center justify-between ${
            !useCustomStatus?.use_custom 
              ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800'
              : 'bg-gray-50 dark:bg-gray-700/30'
          }`}>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${!useCustomStatus?.use_custom ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
              <span className={`text-sm ${!useCustomStatus?.use_custom ? 'text-green-700 dark:text-green-400 font-medium' : 'text-gray-500'}`}>
                {displayVerifiedDomains.toLocaleString()} {isUsingCustom ? 'unique rules from your custom list' : 'unique rules from selected sources'}
              </span>
            </div>
          </div>
        </div>

        {/* License consent modal — opt-in for GPL / NonCommercial verified sources */}
        {consentSource && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setConsentSource(null)}>
            <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 max-w-md w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Enable {consentSource.name}?</h3>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                <strong>{consentSource.name}</strong> is a third-party list (<strong>{consentSource.license}</strong>),
                maintained by others. EasyPi does not include or redistribute it — it is downloaded
                directly to <strong>this device</strong> from the maintainer when you update your lists.
                It is provided as-is, without warranty, and may occasionally block legitimate domains.
              </p>
              <a href={consentSource.info_url || consentSource.url} target="_blank" rel="noreferrer"
                 className="text-xs text-indigo-500 hover:underline break-all block mb-4">
                {consentSource.info_url || consentSource.url} ↗
              </a>
              <label className="flex items-start gap-3 cursor-pointer p-3 rounded-xl bg-gray-50 dark:bg-gray-700/50 mb-4">
                <input type="checkbox" checked={consentChecked}
                       onChange={(e) => setConsentChecked(e.target.checked)}
                       className="mt-0.5 rounded border-gray-300 text-indigo-500 focus:ring-indigo-500" />
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  I understand that this is a third-party list, downloaded directly from its maintainer
                  and provided without warranty.
                </span>
              </label>
              <div className="flex justify-end gap-2">
                <button onClick={() => setConsentSource(null)}
                        className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-xl transition-colors">
                  Cancel
                </button>
                <button onClick={confirmConsentEnable} disabled={!consentChecked}
                        className="px-4 py-2 bg-green-500 hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-colors">
                  Enable
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Custom Sources */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm border border-gray-100 dark:border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-amber-100 dark:bg-amber-900/30">
                <Unlock className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              </div>
              Custom Sources
            </h3>
            <div className="flex items-center gap-2">
              {useCustomStatus?.custom_available && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <span className={`text-xs ${useCustomStatus?.use_custom ? 'text-amber-600 dark:text-amber-400 font-medium' : 'text-gray-500'}`}>
                    {useCustomStatus?.use_custom ? 'Active' : 'Off'}
                  </span>
                  <div className="relative">
                    <input
                      type="checkbox"
                      checked={useCustomStatus?.use_custom || false}
                      onChange={async (e) => {
                        try {
                          const result = await setUseCustomBlocklist.mutateAsync(e.target.checked)
                          toast.success(
                            result.use_custom 
                              ? `Switched to custom blocklist (${result.domains_loaded.toLocaleString()} domains)`
                              : `Switched to verified blocklist (${result.domains_loaded.toLocaleString()} domains)`
                          )
                        } catch (error: any) {
                          toast.error(error.response?.data?.detail || 'Failed to switch')
                        }
                      }}
                      disabled={setUseCustomBlocklist.isPending}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-amber-300 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-amber-500"></div>
                  </div>
                </label>
              )}
              <button
                onClick={() => setShowAddModal(true)}
                className="px-3 py-1.5 text-sm bg-amber-100 hover:bg-amber-200 dark:bg-amber-900/30 dark:hover:bg-amber-900/50 text-amber-700 dark:text-amber-400 rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                Add
              </button>
            </div>
          </div>
          
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            Add your own blocklists from URLs or files. Check licenses before adding.
          </p>
          
          {/* Custom Sources List */}
          {customSources && customSources.length > 0 ? (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {customSources.map((source) => (
                <div 
                  key={source.id}
                  className={`flex items-center justify-between p-3 rounded-xl ${
                    source.last_error 
                      ? 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
                      : 'bg-gray-50 dark:bg-gray-700/50'
                  }`}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${source.last_error ? 'bg-red-500' : 'bg-amber-500'}`} />
                    <div className="flex-1 min-w-0">
                      <span className="text-sm font-medium text-gray-900 dark:text-white truncate block">
                        {source.name}
                      </span>
                      {source.last_error ? (
                        <span className="text-xs text-red-500 truncate block">{source.last_error}</span>
                      ) : source.domain_count ? (
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          {source.domain_count.toLocaleString()} domains
                        </span>
                      ) : null}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="px-2 py-0.5 text-xs rounded bg-amber-200 dark:bg-amber-800 text-amber-700 dark:text-amber-300">
                      {source.format}
                    </span>
                    <button
                      onClick={() => {
                        if (confirm(`Delete "${source.name}"?`)) {
                          removeCustomSource.mutate(source.id)
                        }
                      }}
                      className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <Unlock className="w-10 h-10 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
              <p className="text-sm">No custom sources added yet</p>
              <p className="text-xs mt-1">Click "Add" to add your own blocklists</p>
            </div>
          )}
          
          {/* Custom status bar */}
          {customSources && customSources.length > 0 && (
            <div className={`mt-4 p-3 rounded-xl flex items-center justify-between ${
              useCustomStatus?.use_custom 
                ? 'bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800'
                : 'bg-gray-50 dark:bg-gray-700/30'
            }`}>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${useCustomStatus?.use_custom ? 'bg-amber-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className={`text-sm ${useCustomStatus?.use_custom ? 'text-amber-700 dark:text-amber-400 font-medium' : 'text-gray-500'}`}>
                  {customSources.reduce((sum, s) => sum + (s.domain_count || 0), 0).toLocaleString()} domains from {customSources.length} source{customSources.length !== 1 ? 's' : ''}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Info Section */}
      <div className="p-4 rounded-xl bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-900 dark:text-blue-300">How it works</h4>
            <p className="text-sm text-blue-700 dark:text-blue-400 mt-1">
              EasyPi uses a two-layer blocklist system. <strong>Verified sources</strong> (HaGeZi, OISD, 1Hosts, AdAway)
              are third-party lists downloaded directly to this device, never bundled with EasyPi. <strong>Custom
              sources</strong> let you add your own blocklists — check their licenses before using.
            </p>
          </div>
        </div>
      </div>

      {/* Add Custom Source Modal */}
      {showAddModal && (
        <AddCustomSourceModal
          customSources={customSources || []}
          onAddSource={addCustomSource.mutateAsync}
          onUploadFile={uploadCustomFile.mutateAsync}
          onClose={() => setShowAddModal(false)}
          isAdding={addCustomSource.isPending || uploadCustomFile.isPending}
        />
      )}
    </div>
  )
}

// Stat Card Component
function StatCard({ 
  icon, 
  label, 
  value, 
  color,
  badge,
}: { 
  icon: React.ReactNode
  label: string
  value: string
  color: 'indigo' | 'green' | 'amber' | 'blue'
  badge?: string
}) {
  const colorClasses = {
    indigo: 'from-indigo-50 to-indigo-100/50 dark:from-indigo-900/20 dark:to-indigo-900/10 border-indigo-100 dark:border-indigo-900/30',
    green: 'from-green-50 to-green-100/50 dark:from-green-900/20 dark:to-green-900/10 border-green-100 dark:border-green-900/30',
    amber: 'from-amber-50 to-amber-100/50 dark:from-amber-900/20 dark:to-amber-900/10 border-amber-100 dark:border-amber-900/30',
    blue: 'from-blue-50 to-blue-100/50 dark:from-blue-900/20 dark:to-blue-900/10 border-blue-100 dark:border-blue-900/30',
  }
  
  return (
    <div className={`p-4 rounded-xl bg-gradient-to-br ${colorClasses[color]} border`}>
      <div className="flex items-center justify-between mb-2">
        {icon}
        {badge && (
          <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-200 dark:bg-green-800 text-green-700 dark:text-green-300">
            {badge}
          </span>
        )}
      </div>
      <div className="text-2xl font-bold text-gray-900 dark:text-white">
        {value}
      </div>
      <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
        {label}
      </div>
    </div>
  )
}

// Format date helper
function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  const days = Math.floor(diff / (1000 * 60 * 60 * 24))
  
  if (days === 0) return 'Today'
  if (days === 1) return 'Yesterday'
  if (days < 7) return `${days} days ago`
  return date.toLocaleDateString()
}

// Add Custom Source Modal
function AddCustomSourceModal({
  customSources,
  onAddSource,
  onUploadFile,
  onClose,
  isAdding,
}: {
  customSources: Array<{ id: string; name: string; url: string; format: string; last_error?: string | null; domain_count?: number }>
  onAddSource: (data: { url: string; name: string; format: 'hosts' | 'domains' | 'adblock'; user_confirmed_risks: boolean }) => Promise<any>
  onUploadFile: (data: { file: File; name: string; format: 'hosts' | 'domains' | 'adblock' | 'auto'; user_confirmed_risks: boolean }) => Promise<any>
  onClose: () => void
  isAdding: boolean
}) {
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [format, setFormat] = useState<'hosts' | 'domains' | 'adblock'>('hosts')
  const [confirmed, setConfirmed] = useState(false)
  const [activeTab, setActiveTab] = useState<'url' | 'file'>('url')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleAdd = async () => {
    if (!url || !name || !confirmed) return
    
    try {
      await onAddSource({
        url,
        name,
        format,
        user_confirmed_risks: confirmed,
      })
      setUrl('')
      setName('')
      setConfirmed(false)
      toast.success('Custom source added. Click "Update Blocklists" to apply.')
    } catch (error: any) {
      toast.error(error.response?.data?.detail || error.message || 'Failed to add source')
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedFile(file)
      if (!name) {
        setName(file.name.replace(/\.[^.]+$/, ''))
      }
    }
  }

  const handleFileUpload = async () => {
    if (!selectedFile || !name || !confirmed) return
    
    try {
      const result = await onUploadFile({
        file: selectedFile,
        name,
        format: 'auto',
        user_confirmed_risks: confirmed,
      })
      
      setSelectedFile(null)
      setName('')
      setConfirmed(false)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
      const detectedFormat = result.source?.format || 'auto'
      toast.success(`Uploaded ${result.entries_count?.toLocaleString() || '?'} domains (${detectedFormat} format detected)`)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || error.message || 'Failed to upload file')
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 max-w-lg w-full shadow-2xl max-h-[90vh] overflow-y-auto">
        <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
          <Plus className="w-5 h-5 text-indigo-500" />
          Add Custom Blocklist
        </h3>
        
        {/* Warning */}
        <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 mb-4">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-amber-700 dark:text-amber-400">
              <strong>License Warning:</strong> Custom blocklists may have license restrictions (GPL, CC-NC). 
              Verify legal rights before adding.
            </p>
          </div>
        </div>
        
        {/* Tab Switcher */}
        <div className="flex gap-1 p-1 bg-gray-100 dark:bg-gray-700 rounded-xl mb-4">
          <button
            onClick={() => setActiveTab('url')}
            className={`flex-1 px-3 py-2.5 text-sm font-medium rounded-lg transition-all flex items-center justify-center gap-2 ${
              activeTab === 'url'
                ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <Globe className="w-4 h-4" />
            From URL
          </button>
          <button
            onClick={() => setActiveTab('file')}
            className={`flex-1 px-3 py-2.5 text-sm font-medium rounded-lg transition-all flex items-center justify-center gap-2 ${
              activeTab === 'file'
                ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <FileText className="w-4 h-4" />
            Upload File
          </button>
        </div>
        
        {/* Form */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
              Source Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., My Custom List"
              className="w-full px-4 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
            />
          </div>
          
          {activeTab === 'url' ? (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  URL
                </label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/blocklist.txt"
                  className="w-full px-4 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  Format
                </label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value as any)}
                  className="w-full px-4 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                >
                  <option value="hosts">Hosts file (0.0.0.0 domain.com)</option>
                  <option value="domains">Domain list (one per line)</option>
                  <option value="adblock">AdBlock syntax (||domain^)</option>
                </select>
              </div>
            </>
          ) : (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Select File
              </label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.hosts,.list"
                onChange={handleFileSelect}
                className="hidden"
              />
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="w-full px-4 py-6 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-700/50 text-center cursor-pointer hover:border-indigo-400 dark:hover:border-indigo-500 transition-all group"
              >
                {selectedFile ? (
                  <div className="flex items-center justify-center gap-2 text-gray-900 dark:text-white">
                    <FileText className="w-5 h-5 text-indigo-500" />
                    <span className="font-medium">{selectedFile.name}</span>
                    <span className="text-sm text-gray-500">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                  </div>
                ) : (
                  <div className="text-gray-500 dark:text-gray-400">
                    <Upload className="w-8 h-8 mx-auto mb-2 group-hover:text-indigo-500 transition-colors" />
                    <span className="text-sm">Click to select a blocklist file</span>
                    <p className="text-xs mt-1 text-gray-400">.txt, .hosts, .list</p>
                  </div>
                )}
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                Format is auto-detected: hosts, domains, or adblock syntax
              </p>
            </div>
          )}
          
          {/* Confirmation checkbox */}
          <label className="flex items-start gap-3 cursor-pointer p-3 rounded-xl bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="mt-0.5 rounded border-gray-300 text-indigo-500 focus:ring-indigo-500"
            />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              I confirm that I have verified the license of this blocklist source and understand the risks.
            </span>
          </label>
          
          {/* Submit button */}
          {activeTab === 'url' ? (
            <button
              onClick={handleAdd}
              disabled={isAdding || !url || !name || !confirmed}
              className="w-full px-4 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-all font-medium flex items-center justify-center gap-2"
            >
              {isAdding ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Plus className="w-4 h-4" />
              )}
              Add Custom Source
            </button>
          ) : (
            <button
              onClick={handleFileUpload}
              disabled={isAdding || !selectedFile || !name || !confirmed}
              className="w-full px-4 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-all font-medium flex items-center justify-center gap-2"
            >
              {isAdding ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Upload className="w-4 h-4" />
              )}
              Upload File
            </button>
          )}
        </div>
        
        {/* Current sources */}
        {customSources.length > 0 && (
          <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Current Sources ({customSources.length})
            </h4>
            <div className="space-y-1.5 max-h-32 overflow-y-auto">
              {customSources.map((source) => (
                <div 
                  key={source.id}
                  className={`flex items-center justify-between p-2 rounded-lg text-sm ${
                    source.last_error 
                      ? 'bg-red-50 dark:bg-red-900/20'
                      : 'bg-gray-50 dark:bg-gray-700/50'
                  }`}
                >
                  <span className="text-gray-900 dark:text-white truncate">{source.name}</span>
                  <span className="ml-2 px-2 py-0.5 text-xs rounded bg-amber-200 dark:bg-amber-800 text-amber-700 dark:text-amber-300 flex-shrink-0">
                    {source.format}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* Close button */}
        <div className="mt-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-xl transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
