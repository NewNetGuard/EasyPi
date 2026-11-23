// Visual style for each "who blocked this" source key returned by the backend
// (source_key / sourceKey). Behaviour-based sources (heuristics, DGA, brand
// spoof, Shadow Mode, Ad/Tracker AI) get distinct colours so they stand out from
// a plain list block. Shared by the Query Log, Network Activity, Statistics and
// Blocked & Allowed views so one key always looks the same.
export interface BlockSourceStyle {
  color: string
  emoji: string
  chart: string
}

const BLOCK_SOURCE_STYLES: Record<string, BlockSourceStyle> = {
  blocklist: { color: 'bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300', emoji: '📋', chart: '#ef4444' },
  blacklist: { color: 'bg-stone-100 dark:bg-stone-700 text-stone-700 dark:text-stone-300', emoji: '✋', chart: '#78716c' },
  shadow: { color: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300', emoji: '👁️', chart: '#6366f1' },
  ad_ai: { color: 'bg-fuchsia-100 dark:bg-fuchsia-900/30 text-fuchsia-700 dark:text-fuchsia-300', emoji: '🎯', chart: '#d946ef' },
  heuristic: { color: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300', emoji: '🧠', chart: '#f59e0b' },
  name: { color: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300', emoji: '🔤', chart: '#eab308' },
  dga: { color: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300', emoji: '🤖', chart: '#a855f7' },
  homoglyph: { color: 'bg-pink-100 dark:bg-pink-900/30 text-pink-700 dark:text-pink-300', emoji: '🎭', chart: '#ec4899' },
  nrd: { color: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300', emoji: '🆕', chart: '#f43f5e' },
  threat: { color: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300', emoji: '☣️', chart: '#dc2626' },
  cname: { color: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300', emoji: '🪞', chart: '#7c3aed' },
  rebinding: { color: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300', emoji: '🔁', chart: '#ea580c' },
  behavioral: { color: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300', emoji: '📈', chart: '#8b5cf6' },
  parental: { color: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300', emoji: '🛡️', chart: '#3b82f6' },
  profile: { color: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300', emoji: '📱', chart: '#6366f1' },
  unknown_device: { color: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300', emoji: '❔', chart: '#0891b2' },
  schedule: { color: 'bg-teal-100 dark:bg-teal-900/30 text-teal-700 dark:text-teal-300', emoji: '⏰', chart: '#0ea5e9' },
  safesearch: { color: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300', emoji: '🔍', chart: '#10b981' },
  rewrite: { color: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300', emoji: '↪️', chart: '#22c55e' },
  app: { color: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300', emoji: '📵', chart: '#14b8a6' },
  rule: { color: 'bg-stone-100 dark:bg-stone-700 text-stone-700 dark:text-stone-300', emoji: '⚙️', chart: '#64748b' },
}

const FALLBACK: BlockSourceStyle = {
  color: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300',
  emoji: '•',
  chart: '#94a3b8',
}

export const blockSourceStyle = (key?: string): BlockSourceStyle =>
  BLOCK_SOURCE_STYLES[key || ''] || FALLBACK
