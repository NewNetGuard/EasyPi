import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Send, Save, CheckCircle2, ExternalLink, Bell } from 'lucide-react'
import { getTelegramAlerts, setTelegramAlerts, testTelegramAlerts } from '../../api/alerts'

// Telegram alert channel: watchdog/security alerts pushed to your phone via a bot.
export default function TelegramAlertsCard() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['telegram-alerts'], queryFn: getTelegramAlerts })
  const [token, setToken] = useState('')      // write-only; never returned from server
  const [chatId, setChatId] = useState('')
  const [chatIdTouched, setChatIdTouched] = useState(false)

  useEffect(() => {
    if (data?.chat_id && !chatIdTouched) setChatId(data.chat_id)
  }, [data?.chat_id, chatIdTouched])

  const invalidate = () => qc.invalidateQueries({ queryKey: ['telegram-alerts'] })

  const save = useMutation({
    mutationFn: () => setTelegramAlerts({
      bot_token: token || undefined,
      chat_id: chatId || undefined,
      enabled: data?.enabled ?? false,
    }),
    onSuccess: () => { setToken(''); invalidate(); toast.success('Telegram settings saved') },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to save'),
  })
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => setTelegramAlerts({ enabled }),
    onSuccess: invalidate,
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed'),
  })
  const test = useMutation({
    mutationFn: testTelegramAlerts,
    onSuccess: () => toast.success('Test sent — check Telegram'),
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Test failed'),
  })

  const configured = !!data?.configured

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 sm:p-6">
      <div className="flex items-center gap-3 mb-1">
        <div className="p-2 rounded-lg bg-sky-100 dark:bg-sky-900/40"><Send className="w-5 h-5 text-sky-500" /></div>
        <div className="flex-1">
          <h3 className="font-semibold text-gray-900 dark:text-white">Telegram alerts</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">Get watchdog & security alerts on your phone via a Telegram bot.</p>
        </div>
        {configured && (
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <span className="text-xs text-gray-500 dark:text-gray-400">{data?.enabled ? 'On' : 'Off'}</span>
            <input type="checkbox" className="sr-only peer" checked={!!data?.enabled}
              onChange={(e) => toggle.mutate(e.target.checked)} />
            <div className="relative w-9 h-5 bg-gray-300 dark:bg-gray-600 rounded-full peer-checked:bg-emerald-500 transition-colors after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:h-4 after:w-4 after:bg-white after:rounded-full after:transition-transform peer-checked:after:translate-x-4" />
          </label>
        )}
      </div>

      <ol className="mt-3 mb-3 text-xs text-gray-500 dark:text-gray-400 space-y-1 list-decimal list-inside">
        <li>In Telegram, message <a className="text-sky-500 hover:underline inline-flex items-center gap-0.5" href="https://t.me/BotFather" target="_blank" rel="noreferrer">@BotFather<ExternalLink className="w-3 h-3" /></a> → <code>/newbot</code> → copy the token.</li>
        <li>Message your new bot once (any text), then get your chat id from <a className="text-sky-500 hover:underline inline-flex items-center gap-0.5" href="https://t.me/userinfobot" target="_blank" rel="noreferrer">@userinfobot<ExternalLink className="w-3 h-3" /></a>.</li>
        <li>Paste both below, Save, then turn it On.</li>
      </ol>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <input value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off"
          placeholder={data?.has_token ? 'Bot token (saved — leave blank to keep)' : 'Bot token'}
          className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white" />
        <input value={chatId} onChange={(e) => { setChatId(e.target.value); setChatIdTouched(true) }}
          placeholder="Chat ID (e.g. 123456789)"
          className="px-3 py-2 text-sm rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white" />
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button onClick={() => save.mutate()} disabled={save.isPending || (!token && !chatId)}
          className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 hover:bg-sky-600 disabled:opacity-50 px-3 py-2 text-sm font-medium text-white">
          <Save className="w-4 h-4" /> Save
        </button>
        <button onClick={() => test.mutate()} disabled={test.isPending || !configured}
          className="inline-flex items-center gap-1.5 rounded-md border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50">
          <Bell className="w-4 h-4" /> Send test
        </button>
        {configured && (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" /> configured
          </span>
        )}
      </div>
    </div>
  )
}
