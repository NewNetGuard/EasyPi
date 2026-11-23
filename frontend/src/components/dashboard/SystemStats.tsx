import { Cpu, HardDrive, MemoryStick, Thermometer } from 'lucide-react'
import Card from '../common/Card'
import ProgressBar from '../common/ProgressBar'
import { useSystemStats } from '../../hooks/useMonitoring'
import { bytesToGigabytes, formatTemperature } from '../../utils/formatters'

const getColorByValue = (
  value: number,
  thresholds = { warning: 70, danger: 85 },
) => {
  if (value >= thresholds.danger) return 'danger'
  if (value >= thresholds.warning) return 'warning'
  return 'success'
}

const SystemStats = () => {
  const { data, isLoading } = useSystemStats()

  const cpuUsage = Math.round(data?.cpu.usage ?? 0)

  const ramUsedGb = bytesToGigabytes(data?.ram.used, 1)
  const ramTotalGb = bytesToGigabytes(data?.ram.total, 1)
  const ramPercent =
    data && data.ram.total > 0
      ? Math.round((data.ram.used / data.ram.total) * 100)
      : 0

  const diskStats = (() => {
    const disks = data?.disk ?? []
    if (disks.length === 0) {
      return { used: 0, total: 0 }
    }
    const rootDisk = disks.find((disk) => disk.mount === '/')
    if (rootDisk) {
      return { used: rootDisk.used, total: rootDisk.total }
    }
    const largestDisk = disks.reduce(
      (best, disk) => (disk.total > best.total ? disk : best),
      disks[0],
    )
    return { used: largestDisk.used, total: largestDisk.total }
  })()
  const diskPercent =
    diskStats.total > 0 ? Math.round((diskStats.used / diskStats.total) * 100) : 0
  const diskUsedGb = bytesToGigabytes(diskStats.used, 1)
  const diskTotalGb = bytesToGigabytes(diskStats.total, 1)

  const tempValue =
    data?.temp.celsius !== undefined && data?.temp.celsius !== null
      ? Math.round(data.temp.celsius)
      : null
  const tempPercent = tempValue ? Math.min((tempValue / 80) * 100, 100) : 0

  return (
    <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary-100 dark:bg-primary-900/20 p-3">
              <Cpu className="h-6 w-6 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">CPU</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {isLoading ? '—' : `${cpuUsage}%`}
              </p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <ProgressBar
            progress={cpuUsage}
            color={getColorByValue(cpuUsage)}
            size="sm"
          />
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-purple-100 dark:bg-purple-900/20 p-3">
              <MemoryStick className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">RAM</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {isLoading ? '—' : `${ramPercent}%`}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {ramUsedGb}GB / {ramTotalGb}GB
              </p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <ProgressBar
            progress={ramPercent}
            color={getColorByValue(ramPercent)}
            size="sm"
          />
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-100 dark:bg-blue-900/20 p-3">
              <HardDrive className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Disk</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {isLoading ? '—' : `${diskPercent}%`}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {diskUsedGb}GB / {diskTotalGb}GB
              </p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <ProgressBar
            progress={diskPercent}
            color={getColorByValue(diskPercent, { warning: 80, danger: 90 })}
            size="sm"
          />
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-orange-100 dark:bg-orange-900/20 p-3">
              <Thermometer className="h-6 w-6 text-orange-600 dark:text-orange-400" />
            </div>
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Temp</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {isLoading ? '—' : formatTemperature(tempValue ?? null)}
              </p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <ProgressBar
            progress={tempPercent}
            color={getColorByValue(tempValue ?? 0, { warning: 65, danger: 75 })}
            size="sm"
          />
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Max: 80°C</p>
        </div>
      </Card>
    </div>
  )
}

export default SystemStats
