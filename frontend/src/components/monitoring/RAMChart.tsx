import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import Card from '../common/Card'
import { MemoryStick } from 'lucide-react'

interface RAMChartProps {
  data: { time: string; used: number; total: number }[]
}

const RAMChart: React.FC<RAMChartProps> = ({ data }) => {
  const current = data[data.length - 1]
  const percentage = current ? ((current.used || 0) / (current.total || 1)) * 100 : 0

  if (!data.length) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-purple-100 dark:bg-purple-900/20 p-2">
              <MemoryStick className="h-5 w-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">RAM Usage</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Memory consumption</p>
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
          <div className="rounded-lg bg-purple-100 dark:bg-purple-900/20 p-2">
            <MemoryStick className="h-5 w-5 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">RAM Usage</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Memory consumption</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {percentage.toFixed(1)}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {current?.used.toFixed(2)} / {current?.total} GB
          </p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="ramGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.2} />
          <XAxis 
            dataKey="time" 
            stroke="#9ca3af"
            style={{ fontSize: '12px' }}
            tickCount={6}
          />
          <YAxis 
            stroke="#9ca3af"
            style={{ fontSize: '12px' }}
            domain={[0, Math.max(4, current?.total || 4)]}
            ticks={[0, 1, 2, 3, 4]}
            tickFormatter={(value) => `${value}GB`}
          />
          <Tooltip 
            contentStyle={{
              backgroundColor: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid #374151',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={(value: number) => [`${value.toFixed(2)} GB`, 'Used']}
          />
          <Area 
            type="monotone" 
            dataKey="used" 
            stroke="#a855f7" 
            strokeWidth={2}
            fill="url(#ramGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>

      <div className="mt-4 flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          <span className="text-gray-600 dark:text-gray-400">Normal (&lt;70%)</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-yellow-500" />
          <span className="text-gray-600 dark:text-gray-400">Warning (70-85%)</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-red-500" />
          <span className="text-gray-600 dark:text-gray-400">Critical (&gt;85%)</span>
        </div>
      </div>
    </Card>
  )
}

export default RAMChart
