import { useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Calendar, TrendingUp, TrendingDown, Activity, Shield, BarChart3,
  Sparkles, Monitor, ChevronDown, ChevronRight, ShieldAlert, Clock,
} from 'lucide-react'
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts'
import { getStats } from '../../api/guardSecurity'
import { getAnalytics, getDeviceDetail, type AnalyticsDevice, type ThreatCategory } from '../../api/analytics'
import { blockSourceStyle } from './blockSourceStyles'

type Period = '24h' | '7d'

const catColor = (k: string) => blockSourceStyle(k).chart

function ChangeBadge({ pct }: { pct?: number | null }) {
  if (pct === null || pct === undefined) return null
  const up = pct > 0
  const flat = pct === 0
  const Icon = up ? TrendingUp : TrendingDown
  return (
    <span className={`inline-flex items-center gap-0.5 text-xs font-medium ${
      flat ? 'text-gray-400' : up ? 'text-amber-500' : 'text-emerald-500'
    }`}>
      {!flat && <Icon className="w-3 h-3" />}
      {Math.abs(pct) > 300 ? 'high' : `${up ? '+' : ''}${pct}%`}
    </span>
  )
}

export default function Statistics() {
  const [period, setPeriod] = useState<Period>('7d')
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data } = useQuery({
    queryKey: ['security-stats', period],
    queryFn: () => getStats(period),
    staleTime: 10_000,
  })
  const { data: analytics } = useQuery({
    queryKey: ['security-analytics', period],
    queryFn: () => getAnalytics(period),
    staleTime: 10_000,
  })

  const totalQueries = data?.totalQueries ?? 0
  const blocked = data?.blocked ?? 0
  const blockRate = data?.blockRate ?? 0
  const queryData = data?.queryTrend ?? []
  const topBlockedDomains = (data?.topBlocked ?? []).map((d: any) => ({ domain: d.domain, queries: d.hits }))
  const topQueriedDomains = (data?.topQueried ?? []).map((d: any) => ({ domain: d.domain, queries: d.queries }))

  const categories = analytics?.threatCategories ?? []
  const devices = analytics?.devices ?? []
  const insights = analytics?.insights ?? []
  const cmp = analytics?.comparison ?? {}
  const totalBlocks = categories.reduce((s, c) => s + c.count, 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <BarChart3 className="w-10 h-10 sm:w-16 sm:h-16 text-blue-600 dark:text-blue-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Statistics</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">Detailed analytics and insights</p>
            </div>
          </div>
          <div className="flex gap-1 sm:gap-2">
            {(['24h', '7d'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-3 sm:px-4 py-1.5 sm:py-2 rounded-lg transition-colors text-sm ${
                  period === p ? 'bg-blue-500 text-white'
                    : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                }`}
              >{p}</button>
            ))}
          </div>
        </div>
      </div>

      {/* Agent insights — plain-language read of the numbers */}
      <div className="rounded-xl border border-indigo-200 dark:border-indigo-800 bg-gradient-to-br from-indigo-50 to-white dark:from-indigo-950/40 dark:to-gray-800/40 p-4 sm:p-5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 rounded-lg bg-indigo-100 dark:bg-indigo-900/50">
            <Sparkles className="w-4 h-4 text-indigo-600 dark:text-indigo-300" />
          </div>
          <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-100">What the numbers say</h3>
          {analytics?.peakHour && (
            <span className="ml-auto inline-flex items-center gap-1 text-xs text-indigo-500 dark:text-indigo-300">
              <Clock className="w-3.5 h-3.5" /> peak {analytics.peakHour}
            </span>
          )}
        </div>
        {insights.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">Not enough activity yet to summarise.</p>
        ) : (
          <ul className="space-y-1.5">
            {insights.map((line, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-200">
                <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-indigo-400" />
                {line}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <StatCard icon={<Activity className="w-6 h-6 sm:w-8 sm:h-8 text-blue-500" />} label="Total Queries"
          value={totalQueries.toLocaleString()} extra={<ChangeBadge pct={cmp.queriesChangePct} />} />
        <StatCard icon={<Shield className="w-6 h-6 sm:w-8 sm:h-8 text-red-500" />} label="Blocked"
          value={blocked.toLocaleString()} extra={<ChangeBadge pct={cmp.blockedChangePct} />} />
        <StatCard icon={<TrendingUp className="w-6 h-6 sm:w-8 sm:h-8 text-green-500" />} label="Block Rate"
          value={`${blockRate}%`} />
        <StatCard icon={<Calendar className="w-6 h-6 sm:w-8 sm:h-8 text-purple-500" />} label="Avg Daily"
          value={(period === '24h' ? totalQueries : Math.round(totalQueries / (period === '7d' ? 7 : 30))).toLocaleString()} />
      </div>

      {/* Charts Row 1: trend + threat categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Query Trend</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={queryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9CA3AF" />
              <YAxis stroke="#9CA3AF" />
              <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
              <Legend />
              <Area type="monotone" dataKey="queries" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.6} />
              <Area type="monotone" dataKey="blocked" stackId="1" stroke="#EF4444" fill="#EF4444" fillOpacity={0.6} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-500" /> Blocked by Category
          </h3>
          {categories.length === 0 ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-gray-500">Nothing blocked in this window.</div>
          ) : (
            <div className="flex flex-col sm:flex-row items-center gap-4">
              <ResponsiveContainer width="100%" height={200} className="max-w-[220px]">
                <PieChart>
                  <Pie data={categories} dataKey="count" nameKey="label" cx="50%" cy="50%"
                    innerRadius={52} outerRadius={80} paddingAngle={2}>
                    {categories.map((c) => <Cell key={c.key} fill={catColor(c.key)} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }}
                    formatter={(v: any, n: any) => [`${Number(v).toLocaleString()}`, n]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 w-full space-y-1.5">
                {categories.slice(0, 8).map((c) => (
                  <div key={c.key} className="flex items-center gap-2 text-sm">
                    <span className="h-2.5 w-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: catColor(c.key) }} />
                    <span className="text-gray-700 dark:text-gray-300 truncate">{c.label}</span>
                    <span className="ml-auto font-medium text-gray-900 dark:text-white">{c.count.toLocaleString()}</span>
                    <span className="text-xs text-gray-400 w-9 text-right">
                      {totalBlocks ? Math.round((c.count / totalBlocks) * 100) : 0}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Per-device breakdown with drill-down */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-3 sm:p-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2">
          <Monitor className="w-5 h-5 text-blue-500" />
          <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">By Device</h3>
          <span className="text-xs text-gray-400 ml-auto">click a device to drill in</span>
        </div>
        {devices.length === 0 ? (
          <div className="p-6 text-center text-sm text-gray-500">No device activity in this window.</div>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700/60">
            {devices.map((d) => (
              <DeviceRow key={d.client_id || d.ip || d.name} device={d} period={period}
                open={expanded === (d.client_id || d.ip)}
                onToggle={() => setExpanded(expanded === (d.client_id || d.ip) ? null : (d.client_id || d.ip))} />
            ))}
          </div>
        )}
      </div>

      {/* Top domains */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        <DomainList title="Top Blocked Domains" tone="blocked" rows={topBlockedDomains} empty="No blocked domains yet." />
        <DomainList title="Top Queried Domains" tone="queried" rows={topQueriedDomains} empty="No queried domains yet." />
      </div>

      {/* Activity detail */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
        <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">Activity Detail</h3>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={queryData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="time" stroke="#9CA3AF" />
            <YAxis stroke="#9CA3AF" />
            <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
            <Line type="monotone" dataKey="queries" stroke="#10B981" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function StatCard({ icon, label, value, extra }: { icon: ReactNode; label: string; value: string; extra?: ReactNode }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
      <div className="flex items-center gap-2 sm:gap-3">
        {icon}
        <div className="min-w-0">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">{label}</div>
          <div className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
          <div className="text-xs mt-0.5 h-4">{extra}</div>
        </div>
      </div>
    </div>
  )
}

function DomainList({ title, tone, rows, empty }: {
  title: string; tone: 'blocked' | 'queried'; rows: { domain: string; queries: number }[]; empty: string
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-6 border border-gray-200 dark:border-gray-700">
      <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4">{title}</h3>
      <div className="space-y-3">
        {rows.length === 0 && <div className="text-sm text-gray-500">{empty}</div>}
        {rows.map((d, i) => (
          <div key={i} className="flex items-center justify-between">
            <div className="text-sm font-medium text-gray-900 dark:text-white font-mono truncate flex-1 min-w-0">{d.domain}</div>
            <div className="flex items-center gap-3">
              <span className={`px-2 py-1 text-xs rounded-full ${
                tone === 'blocked' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                  : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
              }`}>{tone === 'blocked' ? 'Blocked' : 'Queried'}</span>
              <div className="text-sm font-semibold text-gray-900 dark:text-white w-16 text-right">{d.queries.toLocaleString()}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function DeviceRow({ device, period, open, onToggle }: {
  device: AnalyticsDevice; period: Period; open: boolean; onToggle: () => void
}) {
  const { data: detail, isFetching } = useQuery({
    queryKey: ['device-detail', device.client_id, period],
    queryFn: () => getDeviceDetail(device.client_id, period),
    enabled: open && !!device.client_id,
    staleTime: 10_000,
  })
  const pct = Math.min(100, device.blockRate)
  return (
    <div>
      <button onClick={onToggle} className="w-full flex items-center gap-3 px-3 sm:px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700/40">
        {open ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />}
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-gray-900 dark:text-white truncate">{device.name}</div>
          {device.ip && device.ip !== device.name && <div className="text-xs text-gray-400 font-mono">{device.ip}</div>}
        </div>
        <div className="hidden sm:block w-28">
          <div className="h-1.5 rounded-full bg-gray-100 dark:bg-gray-700 overflow-hidden">
            <div className="h-full bg-red-400" style={{ width: `${pct}%` }} />
          </div>
        </div>
        <div className="text-right w-16">
          <div className="text-sm font-semibold text-gray-900 dark:text-white">{device.requests.toLocaleString()}</div>
          <div className="text-xs text-red-500">{device.blocked.toLocaleString()} blk</div>
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 bg-gray-50/60 dark:bg-gray-900/30">
          {isFetching && !detail ? (
            <div className="text-xs text-gray-400 py-2">Loading…</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <MiniList title="Top blocked" rows={detail?.topBlocked ?? []} tone="red" />
              <MiniList title="Top queried" rows={detail?.topQueried ?? []} tone="gray" />
              <div>
                <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">Why blocked</div>
                {(detail?.categories ?? []).length === 0 ? (
                  <div className="text-xs text-gray-400">—</div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {(detail?.categories ?? []).map((c: ThreatCategory) => (
                      <span key={c.key} className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs"
                        style={{ backgroundColor: `${catColor(c.key)}22`, color: catColor(c.key) }}>
                        {c.label} {c.count}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function MiniList({ title, rows, tone }: { title: string; rows: { domain: string; count: number }[]; tone: 'red' | 'gray' }) {
  return (
    <div>
      <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">{title}</div>
      {rows.length === 0 ? <div className="text-xs text-gray-400">—</div> : (
        <ul className="space-y-1">
          {rows.slice(0, 6).map((r, i) => (
            <li key={i} className="flex items-center justify-between gap-2">
              <span className="font-mono text-xs text-gray-700 dark:text-gray-300 truncate">{r.domain}</span>
              <span className={`text-xs font-medium ${tone === 'red' ? 'text-red-500' : 'text-gray-500'}`}>{r.count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
