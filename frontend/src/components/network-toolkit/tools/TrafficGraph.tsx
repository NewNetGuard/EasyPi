import { useCallback, useState, useEffect } from 'react'
import { Activity, TrendingUp, TrendingDown, Pause, Play } from 'lucide-react'
import { useNetworkToolkitStore } from '../../../stores/networkToolkitStore'
import { getTrafficData, getTrafficStats } from '../../../api/network'
import { StatCard } from '../shared/StatCard'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import type { TrafficInterval } from '../../../types/network'

export function TrafficGraph() {
  const { trafficData, setTrafficData, trafficStats, setTrafficStats } = useNetworkToolkitStore()
  
  const [interval, setInterval] = useState<TrafficInterval>('1min')
  const [isMonitoring, setIsMonitoring] = useState(false)

  const fetchTrafficData = useCallback(async () => {
    try {
      const duration = {
        '1min': 60,
        '5min': 300,
        '15min': 900,
        '1hour': 3600,
      }[interval]
      
      const response = await getTrafficData(duration)
      
      if (response.success && response.data) {
        setTrafficData(response.data)
      }
    } catch (error) {
      console.error('Error fetching traffic data:', error)
    }
  }, [interval, setTrafficData])

  const fetchTrafficStats = useCallback(async () => {
    try {
      const response = await getTrafficStats()
      
      if (response.success && response.data) {
        setTrafficStats(response.data)
      }
    } catch (error) {
      console.error('Error fetching traffic stats:', error)
    }
  }, [setTrafficStats])

  useEffect(() => {
    let intervalId: number | null = null

    if (isMonitoring) {
      void fetchTrafficData()
      void fetchTrafficStats()

      intervalId = window.setInterval(() => {
        void fetchTrafficData()
        void fetchTrafficStats()
      }, 2000)
    }

    return () => {
      if (intervalId) clearInterval(intervalId)
    }
  }, [isMonitoring, fetchTrafficData, fetchTrafficStats])

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const formatSpeed = (kbps: number) => {
    if (kbps < 1024) return `${kbps.toFixed(2)} KB/s`
    return `${(kbps / 1024).toFixed(2)} MB/s`
  }

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 sm:gap-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-4">
          <label className="text-xs sm:text-sm font-medium text-gray-700 dark:text-gray-300">Interval:</label>
          <select
            value={interval}
            onChange={(e) => setInterval(e.target.value as TrafficInterval)}
            disabled={isMonitoring}
            className="px-3 sm:px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm sm:text-base text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <option value="1min">1 minute</option>
            <option value="5min">5 minutes</option>
            <option value="15min">15 minutes</option>
            <option value="1hour">1 hour</option>
          </select>
        </div>
        
        <button
          onClick={() => setIsMonitoring(!isMonitoring)}
          className={`flex items-center justify-center gap-2 px-4 sm:px-6 py-2.5 sm:py-3 ${
            isMonitoring
              ? 'bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700'
              : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700'
          } rounded-lg text-sm sm:text-base text-white font-medium transition-all`}
        >
          {isMonitoring ? (
            <>
              <Pause className="w-4 h-4 sm:w-5 sm:h-5" />
              Stop Monitoring
            </>
          ) : (
            <>
              <Play className="w-4 h-4 sm:w-5 sm:h-5" />
              Start Monitoring
            </>
          )}
        </button>
      </div>

      {/* Stats */}
      {trafficStats && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 sm:gap-4">
          <StatCard
            icon={TrendingDown}
            label="Current Download"
            value={formatSpeed(trafficStats.currentDownload)}
            color="green"
          />
          <StatCard
            icon={TrendingUp}
            label="Current Upload"
            value={formatSpeed(trafficStats.currentUpload)}
            color="blue"
          />
          <StatCard
            icon={Activity}
            label="Total Received"
            value={formatBytes(trafficStats.totalReceived)}
            color="purple"
          />
          <StatCard
            icon={Activity}
            label="Total Sent"
            value={formatBytes(trafficStats.totalSent)}
            color="yellow"
          />
          <StatCard
            icon={TrendingDown}
            label="Peak Download"
            value={formatSpeed(trafficStats.peakDownload)}
            color="green"
          />
          <StatCard
            icon={TrendingUp}
            label="Peak Upload"
            value={formatSpeed(trafficStats.peakUpload)}
            color="blue"
          />
        </div>
      )}

      {/* Graph */}
      <div className="bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 p-3 sm:p-6">
        {trafficData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis
                dataKey="timestamp"
                stroke="rgba(255,255,255,0.5)"
                tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 12 }}
                tickFormatter={(value) => new Date(value).toLocaleTimeString()}
              />
              <YAxis
                stroke="rgba(255,255,255,0.5)"
                tick={{ fill: 'rgba(255,255,255,0.5)', fontSize: 12 }}
                tickFormatter={(value) => formatSpeed(value)}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(0,0,0,0.8)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                }}
                labelStyle={{ color: '#fff' }}
                formatter={(value: number) => formatSpeed(value)}
                labelFormatter={(value) => new Date(value).toLocaleString()}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="download"
                stroke="#10b981"
                strokeWidth={2}
                dot={false}
                name="Download"
              />
              <Line
                type="monotone"
                dataKey="upload"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
                name="Upload"
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-64 sm:h-96 text-gray-400">
            <div className="text-center space-y-4">
              <Activity className="w-12 h-12 sm:w-16 sm:h-16 mx-auto opacity-20" />
              <p className="text-base sm:text-lg">No traffic data</p>
              <p className="text-xs sm:text-sm text-gray-500">Start monitoring to display the graph</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
