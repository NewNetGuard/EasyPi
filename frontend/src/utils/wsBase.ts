/**
 * Gets the base URL for WebSocket connections.
 * Automatically determines protocol (ws/wss) and host from current window.
 * Works correctly via LAN, Tailscale and any other access method.
 */
export const getWsBaseUrl = (): string => {
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${protocol}//${window.location.host}`
  }
  
  // Fallback for SSR or tests
  return 'ws://localhost:8000'
}

/**
 * Creates full WebSocket URL for the specified path.
 */
export const getWsUrl = (path: string): string => {
  const base = getWsBaseUrl()
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  return `${base}${cleanPath}`
}
