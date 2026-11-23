import api from './client'

export interface TelegramAlertStatus {
  enabled: boolean
  configured: boolean
  has_token: boolean
  chat_id: string | null
}

export const getTelegramAlerts = async (): Promise<TelegramAlertStatus> => {
  const { data } = await api.get('/netprotection/alerts/telegram')
  return data
}

export const setTelegramAlerts = async (
  body: { bot_token?: string; chat_id?: string; enabled?: boolean },
): Promise<TelegramAlertStatus & { success: boolean }> => {
  const { data } = await api.post('/netprotection/alerts/telegram', body)
  return data
}

export const testTelegramAlerts = async (): Promise<{ success: boolean }> => {
  const { data } = await api.post('/netprotection/alerts/telegram/test')
  return data
}
