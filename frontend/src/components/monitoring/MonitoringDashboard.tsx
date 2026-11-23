import { useMemo, useState } from 'react'
import { Activity } from 'lucide-react'
import CPUChart from './CPUChart'
import RAMChart from './RAMChart'
import TempChart from './TempChart'
import DiskChart from './DiskChart'
import NetworkChart from './NetworkChart'
import Select from '../common/Select'
import { useMonitoringStream } from '../../hooks/useMonitoring'
import { bytesToGigabytes } from '../../utils/formatters'
import { formatTimeLabel } from '../../utils/helpers'

const RANGE_MAP: Record<string, number> = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
}

const MonitoringDashboard = () => {
  const [timeRange, setTimeRange] = useState('1h')
  const { samples, latest } = useMonitoringStream()

  const filteredSamples = useMemo(() => {
    const range = RANGE_MAP[timeRange] ?? RANGE_MAP['1h']
    const cutoff = Date.now() - range
    return samples.filter((sample) => {
      const ts = new Date(sample.timestamp).getTime()
      return ts >= cutoff
    })
  }, [samples, timeRange])

  const cpuSeries = filteredSamples.map((sample) => ({
    time: formatTimeLabel(sample.timestamp),
    value: Number(sample.cpu?.toFixed(2) ?? 0),
  }))

  const ramSeries = filteredSamples.map((sample) => ({
    time: formatTimeLabel(sample.timestamp),
    used: bytesToGigabytes(sample.ramUsed, 2),
    total: bytesToGigabytes(sample.ramTotal, 2),
  }))

  const tempSeries = filteredSamples
    .filter((sample) => sample.temp !== null && sample.temp !== undefined)
    .map((sample) => ({
      time: formatTimeLabel(sample.timestamp),
      value: sample.temp as number,
    }))

  const networkSeries = filteredSamples.map((sample) => ({
    time: formatTimeLabel(sample.timestamp),
    download: sample.netRx / (1024 * 1024),
    upload: sample.netTx / (1024 * 1024),
  }))

  const diskStats = latest
    ? {
        used: bytesToGigabytes(latest.diskUsed, 2),
        total: bytesToGigabytes(latest.diskTotal, 2),
      }
    : { used: 0, total: 0 }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
            <Activity className="h-6 w-6 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">System Monitoring</h1>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Real-time system metrics and performance data
            </p>
          </div>
        </div>

        <Select
          options={[
            { value: '1h', label: 'Last Hour' },
            { value: '6h', label: 'Last 6 Hours' },
            { value: '24h', label: 'Last 24 Hours' },
            { value: '7d', label: 'Last 7 Days' },
          ]}
          value={timeRange}
          onChange={setTimeRange}
          className="w-40"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <CPUChart data={cpuSeries} />
        <RAMChart data={ramSeries} />
        <TempChart data={tempSeries} />
        <DiskChart used={diskStats.used} total={diskStats.total} />
      </div>

      <NetworkChart data={networkSeries} />
    </div>
  )
}

export default MonitoringDashboard
