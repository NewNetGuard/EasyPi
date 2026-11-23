import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts'
import Card from '../common/Card'
import { Cpu } from 'lucide-react'

interface CPUChartProps {
  data: { time: string; value: number }[]
}

const CPUChart: React.FC<CPUChartProps> = ({ data }) => {
  const currentValue = data[data.length - 1]?.value || 0

  if (!data.length) {
    return (
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-primary-100 dark:bg-primary-900/20 p-2">
              <Cpu className="h-5 w-5 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">CPU Usage</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Processor load</p>
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
          <div className="rounded-lg bg-primary-100 dark:bg-primary-900/20 p-2">
            <Cpu className="h-5 w-5 text-primary-600 dark:text-primary-400" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">CPU Usage</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">Processor load</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {currentValue.toFixed(1)}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Current</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
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
            domain={[0, 100]}
            ticks={[0, 25, 50, 75, 100]}
          />
          <Tooltip 
            contentStyle={{
              backgroundColor: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid #374151',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={(value: number) => [`${value.toFixed(1)}%`, 'CPU']}
          />
          <Area 
            type="monotone" 
            dataKey="value" 
            stroke="#0ea5e9" 
            strokeWidth={2}
            fill="url(#cpuGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>

      {/* Status Indicators */}
      <div className="mt-4 flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          <span className="text-gray-600 dark:text-gray-400">Normal (&lt;50%)</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-yellow-500" />
          <span className="text-gray-600 dark:text-gray-400">Warning (50-80%)</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-red-500" />
          <span className="text-gray-600 dark:text-gray-400">Critical (&gt;80%)</span>
        </div>
      </div>
    </Card>
  )
}

export default CPUChart
