import api from './client'

export interface NotificationPreferences {
  enabled: boolean
  email: string | null
  alert_types: string[]
  min_priority: 'low' | 'normal' | 'high' | 'critical'
  max_emails_per_hour: number
  max_emails_per_day: number
  digest_mode: boolean
  digest_interval_hours: number
  quiet_hours_enabled: boolean
  quiet_hours_start: number
  quiet_hours_end: number
  current_usage: { hourly: number; daily: number }
}

export interface SMTPConfiguration {
  host: string
  port: number
  username: string
  use_tls: boolean
  use_ssl: boolean
  from_email: string | null
  from_name: string
  is_configured: boolean
}

export interface AlertTypesResponse {
  alert_types: Array<{ value: string; label: string }>
  priorities: Array<{ value: string; label: string }>
}

export const getNotificationPreferences = async (): Promise<NotificationPreferences> =>
  (await api.get('/notifications/preferences')).data

export const saveNotificationPreferences = async (
  preferences: Omit<NotificationPreferences, 'current_usage'>,
): Promise<NotificationPreferences> =>
  (await api.put('/notifications/preferences', preferences)).data

export const getAlertTypes = async (): Promise<AlertTypesResponse> =>
  (await api.get('/notifications/alert-types')).data

export const sendDigestNow = async (): Promise<void> => {
  await api.post('/notifications/send-digest')
}

export const getSMTPConfiguration = async (): Promise<SMTPConfiguration> =>
  (await api.get('/notifications/smtp/config')).data

export const saveSMTPConfiguration = async (configuration: {
  host: string
  port: number
  username: string
  password?: string
  use_tls: boolean
  use_ssl: boolean
  from_email?: string | null
  from_name: string
}): Promise<void> => {
  await api.put('/notifications/smtp/config', configuration)
}

export const testSMTPConnection = async (): Promise<void> => {
  const response = await api.post('/notifications/smtp/test')
  if (!response.data?.success) throw new Error(response.data?.message || 'SMTP connection failed')
}

export const sendTestEmail = async (toEmail: string): Promise<void> => {
  await api.post('/notifications/test-email', { to_email: toEmail })
}
