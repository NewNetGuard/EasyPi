import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Mail, Save, Send, ServerCog } from 'lucide-react'
import { toast } from 'react-hot-toast'

import {
  getAlertTypes,
  getNotificationPreferences,
  getSMTPConfiguration,
  saveNotificationPreferences,
  saveSMTPConfiguration,
  sendDigestNow,
  sendTestEmail,
  testSMTPConnection,
  type NotificationPreferences,
  type SMTPConfiguration,
} from '../../api/notifications'
import { useAuthStore } from '../../stores/authStore'
import Button from '../common/Button'
import Card from '../common/Card'
import Input from '../common/Input'

type PreferencesForm = Omit<NotificationPreferences, 'current_usage'>
type SMTPForm = Omit<SMTPConfiguration, 'is_configured'> & { password: string }

const defaultPreferences: PreferencesForm = {
  enabled: true,
  email: null,
  alert_types: [],
  min_priority: 'normal',
  max_emails_per_hour: 10,
  max_emails_per_day: 50,
  digest_mode: false,
  digest_interval_hours: 24,
  quiet_hours_enabled: false,
  quiet_hours_start: 22,
  quiet_hours_end: 8,
}

const defaultSMTP: SMTPForm = {
  host: 'smtp.gmail.com',
  port: 587,
  username: '',
  password: '',
  use_tls: true,
  use_ssl: false,
  from_email: null,
  from_name: 'EasyPi Notifications',
}

const errorMessage = (error: any, fallback: string) =>
  error?.response?.data?.detail || error?.message || fallback

export default function EmailNotificationSettings() {
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((state) => state.user?.role === 'admin')
  const [preferences, setPreferences] = useState<PreferencesForm>(defaultPreferences)
  const [smtp, setSMTP] = useState<SMTPForm>(defaultSMTP)

  const preferencesQuery = useQuery({
    queryKey: ['notification-preferences'],
    queryFn: getNotificationPreferences,
  })
  const alertTypesQuery = useQuery({
    queryKey: ['notification-alert-types'],
    queryFn: getAlertTypes,
  })
  const smtpQuery = useQuery({
    queryKey: ['notification-smtp-config'],
    queryFn: getSMTPConfiguration,
    enabled: isAdmin,
  })

  useEffect(() => {
    if (!preferencesQuery.data) return
    const { current_usage: _usage, ...saved } = preferencesQuery.data
    setPreferences(saved)
  }, [preferencesQuery.data])

  useEffect(() => {
    if (!smtpQuery.data) return
    const { is_configured: _configured, ...saved } = smtpQuery.data
    setSMTP({ ...saved, password: '' })
  }, [smtpQuery.data])

  const savePreferences = useMutation({
    mutationFn: () => saveNotificationPreferences(preferences),
    onSuccess: (saved) => {
      queryClient.setQueryData(['notification-preferences'], saved)
      toast.success('Email notification preferences saved')
    },
    onError: (error) => toast.error(errorMessage(error, 'Failed to save email preferences')),
  })

  const saveSMTP = useMutation({
    mutationFn: () => saveSMTPConfiguration({
      ...smtp,
      password: smtp.password || undefined,
      from_email: smtp.from_email || null,
    }),
    onSuccess: () => {
      setSMTP((current) => ({ ...current, password: '' }))
      void queryClient.invalidateQueries({ queryKey: ['notification-smtp-config'] })
      toast.success('SMTP configuration saved and verified')
    },
    onError: (error) => toast.error(errorMessage(error, 'Failed to save SMTP configuration')),
  })

  const testSMTP = useMutation({
    mutationFn: testSMTPConnection,
    onSuccess: () => toast.success('SMTP connection succeeded'),
    onError: (error) => toast.error(errorMessage(error, 'SMTP connection failed')),
  })
  const testEmail = useMutation({
    mutationFn: () => sendTestEmail(preferences.email || ''),
    onSuccess: () => toast.success('Test email queued'),
    onError: (error) => toast.error(errorMessage(error, 'Test email failed')),
  })
  const sendDigest = useMutation({
    mutationFn: sendDigestNow,
    onSuccess: () => toast.success('Digest queued'),
    onError: (error) => toast.error(errorMessage(error, 'Failed to queue digest')),
  })

  const alertTypes = alertTypesQuery.data?.alert_types ?? []
  const usage = preferencesQuery.data?.current_usage

  return (
    <div className="space-y-6">
      <Card title="Email alerts" subtitle="Choose which EasyPi events are sent to your email address.">
        <div className="space-y-5">
          <label className="flex items-center justify-between gap-4 rounded-xl bg-gray-50 p-4 dark:bg-dark-800">
            <span>
              <span className="block font-medium text-gray-900 dark:text-white">Enable email alerts</span>
              <span className="mt-1 block text-sm text-gray-500 dark:text-gray-400">SMTP must also be configured by an administrator.</span>
            </span>
            <input
              type="checkbox"
              checked={preferences.enabled}
              onChange={(event) => setPreferences((current) => ({ ...current, enabled: event.target.checked }))}
              className="h-5 w-5 rounded border-gray-300 text-primary-600"
            />
          </label>

          <Input
            label="Delivery email"
            type="email"
            value={preferences.email || ''}
            maxLength={320}
            onChange={(event) => setPreferences((current) => ({ ...current, email: event.target.value || null }))}
            placeholder="you@example.com"
          />

          <div>
            <div className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">Alert types</div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {alertTypes.map((alertType) => (
                <label key={alertType.value} className="flex items-center gap-2 rounded-lg border border-gray-200 p-3 text-sm dark:border-dark-700">
                  <input
                    type="checkbox"
                    checked={preferences.alert_types.includes(alertType.value)}
                    onChange={(event) => setPreferences((current) => ({
                      ...current,
                      alert_types: event.target.checked
                        ? [...new Set([...current.alert_types, alertType.value])]
                        : current.alert_types.filter((value) => value !== alertType.value),
                    }))}
                    className="h-4 w-4 rounded border-gray-300 text-primary-600"
                  />
                  <span className="text-gray-700 dark:text-gray-300">{alertType.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Minimum priority
              <select
                value={preferences.min_priority}
                onChange={(event) => setPreferences((current) => ({
                  ...current,
                  min_priority: event.target.value as PreferencesForm['min_priority'],
                }))}
                className="input mt-2"
              >
                {(alertTypesQuery.data?.priorities ?? []).map((priority) => (
                  <option key={priority.value} value={priority.value}>{priority.label}</option>
                ))}
              </select>
            </label>
            <Input
              label="Hourly limit"
              type="number"
              min={1}
              max={100}
              value={preferences.max_emails_per_hour}
              onChange={(event) => setPreferences((current) => ({ ...current, max_emails_per_hour: Number(event.target.value) }))}
            />
            <Input
              label="Daily limit"
              type="number"
              min={1}
              max={500}
              value={preferences.max_emails_per_day}
              onChange={(event) => setPreferences((current) => ({ ...current, max_emails_per_day: Number(event.target.value) }))}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <label className="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
              <span className="flex items-center gap-2 font-medium text-gray-900 dark:text-white">
                <input
                  type="checkbox"
                  checked={preferences.digest_mode}
                  onChange={(event) => setPreferences((current) => ({ ...current, digest_mode: event.target.checked }))}
                  className="h-4 w-4 rounded border-gray-300 text-primary-600"
                />
                Digest mode
              </span>
              <Input
                className="mt-3"
                aria-label="Digest interval in hours"
                type="number"
                min={1}
                max={168}
                value={preferences.digest_interval_hours}
                disabled={!preferences.digest_mode}
                onChange={(event) => setPreferences((current) => ({ ...current, digest_interval_hours: Number(event.target.value) }))}
              />
            </label>
            <label className="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
              <span className="flex items-center gap-2 font-medium text-gray-900 dark:text-white">
                <input
                  type="checkbox"
                  checked={preferences.quiet_hours_enabled}
                  onChange={(event) => setPreferences((current) => ({ ...current, quiet_hours_enabled: event.target.checked }))}
                  className="h-4 w-4 rounded border-gray-300 text-primary-600"
                />
                Quiet hours
              </span>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <Input aria-label="Quiet hours start" type="number" min={0} max={23} value={preferences.quiet_hours_start} disabled={!preferences.quiet_hours_enabled} onChange={(event) => setPreferences((current) => ({ ...current, quiet_hours_start: Number(event.target.value) }))} />
                <Input aria-label="Quiet hours end" type="number" min={0} max={23} value={preferences.quiet_hours_end} disabled={!preferences.quiet_hours_enabled} onChange={(event) => setPreferences((current) => ({ ...current, quiet_hours_end: Number(event.target.value) }))} />
              </div>
            </label>
          </div>

          {usage && <p className="text-sm text-gray-500 dark:text-gray-400">Sent: {usage.hourly} this hour, {usage.daily} today.</p>}
          <div className="flex flex-wrap gap-2">
            <Button icon={<Save className="h-4 w-4" />} loading={savePreferences.isPending} disabled={!preferences.email || preferences.alert_types.length === 0} onClick={() => savePreferences.mutate()}>Save email preferences</Button>
            <Button variant="outline" icon={<Mail className="h-4 w-4" />} loading={testEmail.isPending} disabled={!preferences.email} onClick={() => testEmail.mutate()}>Send test email</Button>
            <Button variant="outline" icon={<Send className="h-4 w-4" />} loading={sendDigest.isPending} disabled={!preferences.digest_mode} onClick={() => sendDigest.mutate()}>Send digest now</Button>
          </div>
        </div>
      </Card>

      {isAdmin && (
        <Card title="SMTP server" subtitle="The password is write-only. Leave it blank to keep the saved value.">
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Input label="SMTP host" value={smtp.host} maxLength={255} onChange={(event) => setSMTP((current) => ({ ...current, host: event.target.value }))} />
              <Input label="Port" type="number" min={1} max={65535} value={smtp.port} onChange={(event) => setSMTP((current) => ({ ...current, port: Number(event.target.value) }))} />
              <Input label="Username" value={smtp.username} maxLength={255} autoComplete="username" onChange={(event) => setSMTP((current) => ({ ...current, username: event.target.value }))} />
              <Input label="Password" type="password" value={smtp.password} maxLength={500} autoComplete="new-password" placeholder={smtpQuery.data?.is_configured ? 'Saved — leave blank to keep' : 'SMTP password'} onChange={(event) => setSMTP((current) => ({ ...current, password: event.target.value }))} />
              <Input label="From email" type="email" value={smtp.from_email || ''} maxLength={320} onChange={(event) => setSMTP((current) => ({ ...current, from_email: event.target.value || null }))} />
              <Input label="From name" value={smtp.from_name} maxLength={100} onChange={(event) => setSMTP((current) => ({ ...current, from_name: event.target.value }))} />
            </div>
            <div className="flex flex-wrap gap-4 text-sm text-gray-700 dark:text-gray-300">
              <label className="flex items-center gap-2"><input type="checkbox" checked={smtp.use_tls} onChange={(event) => setSMTP((current) => ({ ...current, use_tls: event.target.checked, use_ssl: event.target.checked ? false : current.use_ssl }))} /> STARTTLS</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={smtp.use_ssl} onChange={(event) => setSMTP((current) => ({ ...current, use_ssl: event.target.checked, use_tls: event.target.checked ? false : current.use_tls }))} /> Implicit SSL/TLS</label>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button icon={<ServerCog className="h-4 w-4" />} loading={saveSMTP.isPending} disabled={!smtp.host || !smtp.username || (!smtp.password && !smtpQuery.data?.is_configured)} onClick={() => saveSMTP.mutate()}>Save and verify SMTP</Button>
              <Button variant="outline" loading={testSMTP.isPending} disabled={!smtpQuery.data?.is_configured} onClick={() => testSMTP.mutate()}>Test saved connection</Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  )
}
