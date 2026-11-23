/**
 * API Base URL utilities.
 * 
 * All API calls are relative to the current origin.
 * This ensures the frontend works correctly when accessed via:
 * - localhost
 * - LAN IP (192.168.x.x)
 * - Tailscale IP (100.x.x.x)
 * - Any domain name
 */

/**
 * Returns empty string so all API calls are relative to current origin.
 * The nginx proxy handles routing /api/* to the backend.
 */
export const getApiBaseUrl = (): string => {
  // Always use relative URLs - nginx proxies /api/* to backend
  return '';
};

/**
 * Returns the base URL for API v1 endpoints.
 */
export const getApiV1BaseUrl = (): string => '/api/v1';

/**
 * Returns the canonical base URL for Guard Security / NetProtection endpoints.
 */
export const getSecurityApiBaseUrl = (): string => '/api/v1/netprotection';
