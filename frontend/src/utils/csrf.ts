import { getApiV1BaseUrl } from './apiBase'

const csrfRequests = new Map<string, Promise<string | null>>()

export const getCsrfToken = (): string | null => {
  const cookies = document.cookie.split(';')
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=')
    if (name === 'csrf_token') {
      return decodeURIComponent(value)
    }
  }
  return null
}

export const ensureCsrfToken = async (apiBaseUrl: string = getApiV1BaseUrl()): Promise<string | null> => {
  const token = getCsrfToken()
  if (token) {
    return token
  }

  const existing = csrfRequests.get(apiBaseUrl)
  if (existing) {
    return existing
  }

  const request = (async (): Promise<string | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/auth/csrf`, {
        method: 'GET',
        credentials: 'include',
      })
      if (response.ok) {
        // The double-submit header must match the cookie that is current after
        // Set-Cookie has been applied. Never return a stale response-body token.
        return getCsrfToken()
      }
    } catch (_) {
      // Ignore and fall back to cookie check below.
    }
    return getCsrfToken()
  })()
  csrfRequests.set(apiBaseUrl, request)

  try {
    return await request
  } finally {
    if (csrfRequests.get(apiBaseUrl) === request) {
      csrfRequests.delete(apiBaseUrl)
    }
  }
}

export const getCsrfHeaders = async (apiBaseUrl?: string): Promise<Record<string, string>> => {
  const token = await ensureCsrfToken(apiBaseUrl)
  return token ? { 'X-CSRF-Token': token } : {}
}
