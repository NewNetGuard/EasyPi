import { useState } from 'react'
import { Zap, Loader2, TrendingUp, TrendingDown } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { startSpeedTest } from '../../../api/network'
import { StatCard } from '../shared/StatCard'
import type { SpeedTestConfig } from '../../../types/network'

export function SpeedTest() {
  const { speedTestResult, setSpeedTestResult, scanProgress, setScanProgress } = useNetworkToolkitStore()
  
  const [config, setConfig] = useState<SpeedTestConfig>({
    testDownload: true,
    testUpload: true,
    testPing: true,
    testJitter: true,
  })
  
  const handleTest = async () => {
    setScanProgress('speed-test', {
      status: 'running',
      progress: 0,
      message: 'Speed test is running; exact progress and phase are not reported.',
    })

    try {
      const response = await startSpeedTest(config)

      if (response.success && response.data) {
        setSpeedTestResult(response.data)
        setScanProgress('speed-test', { status: 'completed', progress: 100, message: 'Test completed' })
      } else {
        setScanProgress('speed-test', { status: 'error', progress: 0, message: response.error })
      }
    } catch (error) {
      setScanProgress('speed-test', {
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Test error',
      })
    }
  }

  const progress = scanProgress['speed-test']

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <div className="space-y-3">
        <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Select test parameters:</p>
        <div className="flex flex-wrap gap-3 sm:gap-4">
          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.testDownload}
              onChange={(e) => setConfig({ ...config, testDownload: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Download Speed
          </label>
          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.testUpload}
              onChange={(e) => setConfig({ ...config, testUpload: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Upload Speed
          </label>
          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.testPing}
              onChange={(e) => setConfig({ ...config, testPing: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Ping
          </label>
          <label className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={config.testJitter}
              onChange={(e) => setConfig({ ...config, testJitter: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500"
            />
            Jitter
          </label>
        </div>
      </div>

      {/* Test Button */}
      <button
        onClick={handleTest}
        disabled={progress.status === 'running'}
        className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 sm:px-6 py-2.5 sm:py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-sm sm:text-base text-white font-medium transition-all"
      >
        {progress.status === 'running' ? (
          <>
            <Loader2 className="w-4 h-4 sm:w-5 sm:h-5 animate-spin" />
            Testing...
          </>
        ) : (
          <>
            <Zap className="w-4 h-4 sm:w-5 sm:h-5" />
            Start Test
          </>
        )}
      </button>

      {/* Progress */}
      {progress.status === 'running' && (
        <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
          <span>{progress.message}</span>
        </div>
      )}

      {/* Error */}
      {progress.status === 'error' && (
        <div className="p-3 sm:p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-xs sm:text-sm text-red-400">{progress.message}</div>
      )}

      {/* Results */}
      {speedTestResult && (
        <div className="space-y-6">
          {/* Main Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
            <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 dark:from-green-500/20 dark:to-emerald-500/20 rounded-2xl p-4 sm:p-6 backdrop-blur-sm border border-green-500/20 dark:border-white/10">
              <div className="flex items-center justify-between mb-3 sm:mb-4">
                <TrendingDown className="w-5 h-5 sm:w-6 sm:h-6 text-green-500 dark:text-green-400" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Download</span>
              </div>
              <div className="space-y-2">
                <p className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white">
                  {speedTestResult.download.toFixed(2)}
                  <span className="text-base sm:text-lg ml-2 text-gray-500 dark:text-gray-400">Mbps</span>
                </p>
              </div>
            </div>

            <div className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 dark:from-blue-500/20 dark:to-cyan-500/20 rounded-2xl p-4 sm:p-6 backdrop-blur-sm border border-blue-500/20 dark:border-white/10">
              <div className="flex items-center justify-between mb-3 sm:mb-4">
                <TrendingUp className="w-5 h-5 sm:w-6 sm:h-6 text-blue-500 dark:text-blue-400" />
                <span className="text-xs text-gray-500 dark:text-gray-400">Upload</span>
              </div>
              <div className="space-y-2">
                <p className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white">
                  {speedTestResult.upload.toFixed(2)}
                  <span className="text-base sm:text-lg ml-2 text-gray-500 dark:text-gray-400">Mbps</span>
                </p>
              </div>
            </div>
          </div>

          {/* Additional Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
            <StatCard icon={Zap} label="Ping" value={speedTestResult.ping.toFixed(0)} unit="ms" color="yellow" />
            <StatCard icon={Zap} label="Jitter" value={speedTestResult.jitter.toFixed(0)} unit="ms" color="purple" />
            <StatCard icon={Zap} label="ISP" value={speedTestResult.isp || 'N/A'} color="blue" />
            <StatCard icon={Zap} label="IP Address" value={speedTestResult.ipAddress || 'N/A'} color="green" />
          </div>

          {/* Server Info */}
          <div className="p-3 sm:p-4 bg-gray-100 dark:bg-white/5 backdrop-blur-sm rounded-xl border border-gray-200 dark:border-white/10">
            <h3 className="text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Server Information</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 text-xs sm:text-sm">
              <div>
                <p className="text-gray-500 dark:text-gray-400">Name</p>
                <p className="text-gray-900 dark:text-white break-all">{speedTestResult.server.name}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Location</p>
                <p className="text-gray-900 dark:text-white break-all">{speedTestResult.server.location}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Country</p>
                <p className="text-gray-900 dark:text-white break-all">{speedTestResult.server.country}</p>
              </div>
              <div>
                <p className="text-gray-500 dark:text-gray-400">Distance</p>
                <p className="text-gray-900 dark:text-white">{speedTestResult.server.distance.toFixed(0)} km</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
