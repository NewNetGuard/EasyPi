import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import Card from '../common/Card'
import { HardDrive } from 'lucide-react'

interface DiskChartProps {
  used: number
  total: number
}

const DiskChart: React.FC<DiskChartProps> = ({ used, total }) => {
  const free = Math.max(total - used, 0)
  const percentage = total > 0 ? (used / total) * 100 : 0
  const data = [
    { name: 'Used', value: used, color: '#0ea5e9' },
    { name: 'Free', value: free, color: '#e5e7eb' },
  ]

  if (!total) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-100 dark:bg-blue-900/20 p-2">
              <HardDrive className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">Disk Usage</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Storage space</p>
            </div>
          </div>
          <span className="text-sm text-gray-500 dark:text-gray-400">Waiting for data…</span>
        </div>
      </Card>
    )
  }

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-blue-100 dark:bg-blue-900/20 p-2">
            <HardDrive className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">Disk Usage</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Storage space</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {percentage.toFixed(1)}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {used.toFixed(1)} / {total.toFixed(1)} GB
          </p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{
              backgroundColor: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid #374151',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={(value: number) => `${value.toFixed(2)} GB`}
          />
        </PieChart>
      </ResponsiveContainer>

      <div className="mt-4 grid grid-cols-2 gap-4">
        <div className="rounded-lg bg-primary-50 dark:bg-primary-900/20 p-3">
          <p className="text-xs text-primary-600 dark:text-primary-400">Used Space</p>
          <p className="text-lg font-bold text-primary-700 dark:text-primary-300">
            {used.toFixed(2)} GB
          </p>
        </div>
        <div className="rounded-lg bg-gray-100 dark:bg-dark-800 p-3">
          <p className="text-xs text-gray-600 dark:text-gray-400">Free Space</p>
          <p className="text-lg font-bold text-gray-700 dark:text-gray-300">
            {data[1].value.toFixed(2)} GB
          </p>
        </div>
      </div>
    </Card>
  )
}

export default DiskChart
