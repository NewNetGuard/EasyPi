import axios, { AxiosError } from 'axios'
import { getApiV1BaseUrl, getSecurityApiBaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'
import { redirectToLogin, refreshAuthSession } from './authSession'

const DEFAULT_REQUEST_TIMEOUT_MS = 60_000

const api = axios.create({
  baseURL: getApiV1BaseUrl(),
  timeout: DEFAULT_REQUEST_TIMEOUT_MS,
  withCredentials: true,  // Send httpOnly cookies with requests
})

// Legacy API client (for /api/* endpoints)
export const legacyApi = axios.create({
  baseURL: '/api',
  timeout: DEFAULT_REQUEST_TIMEOUT_MS,
  withCredentials: true,
})

// Guard Security / NetProtection API client
export const securityApi = axios.create({
  baseURL: getSecurityApiBaseUrl(),
  timeout: DEFAULT_REQUEST_TIMEOUT_MS,
  withCredentials: true,
})

function isTimeoutError(error: AxiosError): boolean {
  const msg = (error.message || '').toLowerCase()
  return error.code === 'ECONNABORTED' || msg.includes('timeout')
}

// Add CSRF token to mutating requests
api.interceptors.request.use(async (config) => {
  // Add CSRF token for non-GET requests
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

// Same CSRF interceptor for securityApi
securityApi.interceptors.request.use(async (config) => {
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

// Same CSRF interceptor for legacyApi
legacyApi.interceptors.request.use(async (config) => {
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

securityApi.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean }

    if (!error.response) {
      if (isTimeoutError(error)) {
        const timeoutError = new Error('Request timed out. Backend may be busy, please retry.') as Error & { isTimeoutError: boolean }
        timeoutError.isTimeoutError = true
        return Promise.reject(timeoutError)
      }
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const networkError = new Error('Server unavailable. Please check if the backend is running.') as Error & { isNetworkError: boolean }
      networkError.isNetworkError = true
      return Promise.reject(networkError)
    }

    const contentType = String(error.response.headers?.['content-type'] || '')
    if (contentType.includes('text/html') && error.response.status >= 500) {
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const serverError = new Error('Server error. The backend service may be down.') as Error & { isServerError: boolean }
      serverError.isServerError = true
      return Promise.reject(serverError)
    }

    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest!._retry = true

      try {
        await refreshAuthSession()
        return securityApi(originalRequest!)
      } catch {
        redirectToLogin()
      }
    }

    if (error.response?.status === 403) {
      const detail = (error.response.data as { detail?: string })?.detail || ''
      if (detail.includes('CSRF')) {
        console.warn('CSRF token invalid, reloading...')
        window.location.reload()
        return Promise.reject(error)
      }
    }

    return Promise.reject(error)
  }
)

// Handle errors and 401 responses
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean }

    // Network error or server unavailable
    if (!error.response) {
      if (isTimeoutError(error)) {
        const timeoutError = new Error('Request timed out. Backend may be busy, please retry.') as Error & { isTimeoutError: boolean }
        timeoutError.isTimeoutError = true
        return Promise.reject(timeoutError)
      }
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const networkError = new Error('Server unavailable. Please check if the backend is running.') as Error & { isNetworkError: boolean }
      networkError.isNetworkError = true
      return Promise.reject(networkError)
    }

    // Server returned HTML instead of JSON (e.g., Nginx error page)
    const contentType = String(error.response.headers?.['content-type'] || '')
    if (contentType.includes('text/html') && error.response.status >= 500) {
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const serverError = new Error('Server error. The backend service may be down.') as Error & { isServerError: boolean }
      serverError.isServerError = true
      return Promise.reject(serverError)
    }

    // Handle 401 - try to refresh token via cookie
    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest!._retry = true

      try {
        await refreshAuthSession()
        return api(originalRequest!)
      } catch {
        redirectToLogin()
      }
    }

    // Handle 403 CSRF errors
    if (error.response?.status === 403) {
      const detail = (error.response.data as { detail?: string })?.detail || ''
      if (detail.includes('CSRF')) {
        // CSRF token expired/invalid - reload page to get new one
        console.warn('CSRF token invalid, reloading...')
        window.location.reload()
        return Promise.reject(error)
      }
    }

    return Promise.reject(error)
  }
)

// Reuse same response handling for legacyApi
legacyApi.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean }

    if (!error.response) {
      if (isTimeoutError(error)) {
        const timeoutError = new Error('Request timed out. Backend may be busy, please retry.') as Error & { isTimeoutError: boolean }
        timeoutError.isTimeoutError = true
        return Promise.reject(timeoutError)
      }
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const networkError = new Error('Server unavailable. Please check if the backend is running.') as Error & { isNetworkError: boolean }
      networkError.isNetworkError = true
      return Promise.reject(networkError)
    }

    const contentType = String(error.response.headers?.['content-type'] || '')
    if (contentType.includes('text/html') && error.response.status >= 500) {
      window.dispatchEvent(new CustomEvent('easypi:server-error'))
      const serverError = new Error('Server error. The backend service may be down.') as Error & { isServerError: boolean }
      serverError.isServerError = true
      return Promise.reject(serverError)
    }

    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest!._retry = true

      try {
        await refreshAuthSession()
        return legacyApi(originalRequest!)
      } catch {
        redirectToLogin()
      }
    }

    if (error.response?.status === 403) {
      const detail = (error.response.data as { detail?: string })?.detail || ''
      if (detail.includes('CSRF')) {
        console.warn('CSRF token invalid, reloading...')
        window.location.reload()
        return Promise.reject(error)
      }
    }

    return Promise.reject(error)
  }
)

export default api
