import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import Card from '../common/Card'
import { Network } from 'lucide-react'

interface NetworkChartProps {
  data: { time: string; download: number; upload: number }[]
}

const NetworkChart: React.FC<NetworkChartProps> = ({ data }) => {
  const current = data[data.length - 1]

  if (!data.length) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-green-100 dark:bg-green-900/20 p-2">
              <Network className="h-5 w-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">Network Activity</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Upload and download speeds</p>
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
          <div className="rounded-lg bg-green-100 dark:bg-green-900/20 p-2">
            <Network className="h-5 w-5 text-green-600 dark:text-green-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">Network Activity</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Upload and download speeds</p>
          </div>
        </div>
        <div className="flex gap-6">
          <div className="text-right">
            <p className="text-sm text-gray-500 dark:text-gray-400">Download</p>
            <p className="text-xl font-bold text-green-600 dark:text-green-400">
              {current?.download.toFixed(2)} MB/s
            </p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-500 dark:text-gray-400">Upload</p>
            <p className="text-xl font-bold text-blue-600 dark:text-blue-400">
              {current?.upload.toFixed(2)} MB/s
            </p>
          </div>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.2} />
          <XAxis 
            dataKey="time" 
            stroke="#9ca3af"
            style={{ fontSize: '12px' }}
            tickCount={8}
          />
          <YAxis 
            stroke="#9ca3af"
            style={{ fontSize: '12px' }}
            tickFormatter={(value) => `${value} MB/s`}
          />
          <Tooltip 
            contentStyle={{
              backgroundColor: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid #374151',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={(value: number) => `${value.toFixed(2)} MB/s`}
          />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="download" 
            stroke="#10b981" 
            strokeWidth={2}
            name="Download"
            dot={false}
          />
          <Line 
            type="monotone" 
            dataKey="upload" 
            stroke="#3b82f6" 
            strokeWidth={2}
            name="Upload"
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </Card>
  )
}

export default NetworkChart
