import axios from 'axios'
import { getApiV1BaseUrl } from '../utils/apiBase'

let refreshPromise: Promise<unknown> | null = null
let recentlyRefreshedUser: unknown = null
let refreshedAt = 0
let loginRedirectStarted = false

const REFRESH_BURST_WINDOW_MS = 5_000

/**
 * Rotate the httpOnly session cookies once for all concurrent API requests.
 * The backend refresh token is single-use, so parallel refreshes would revoke
 * each other and incorrectly force an active user back to the login page.
 */
export function refreshAuthSession<T = unknown>(): Promise<T> {
  if (
    recentlyRefreshedUser &&
    Date.now() - refreshedAt < REFRESH_BURST_WINDOW_MS
  ) {
    return Promise.resolve(recentlyRefreshedUser as T)
  }

  if (!refreshPromise) {
    refreshPromise = axios
      .post(
        `${getApiV1BaseUrl()}/auth/refresh`,
        {},
        { withCredentials: true },
      )
      .then((response) => {
        const user = response.data?.user
        if (!user) {
          throw new Error('Session refresh response did not include a user')
        }
        recentlyRefreshedUser = user
        refreshedAt = Date.now()
        return user
      })
      .finally(() => {
        refreshPromise = null
      })
  }

  return refreshPromise as Promise<T>
}

export function redirectToLogin(): void {
  if (loginRedirectStarted) {
    return
  }

  loginRedirectStarted = true
  localStorage.removeItem('easypi-auth')
  window.location.assign('/login')
}
