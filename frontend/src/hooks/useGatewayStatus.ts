import { useQuery } from '@tanstack/react-query'

export interface GatewayModeStatus {
  enabled: boolean
  static_ip?: boolean
  nat_enabled?: boolean
  ip_forward?: boolean
  current_ip?: string
  current_gateway?: string
  interface?: string
  error?: string
}

export const gatewayStatusQueryKey = ['gateway-mode-status'] as const

export const fetchGatewayStatus = async (): Promise<GatewayModeStatus> => {
  const response = await fetch('/api/network-toolkit/gateway-mode/status', {
    credentials: 'include',
  })
  if (!response.ok) {
    throw new Error('Failed to read gateway status')
  }
  return response.json()
}

export const useGatewayStatus = () =>
  useQuery({
    queryKey: gatewayStatusQueryKey,
    queryFn: fetchGatewayStatus,
    staleTime: 0,
    refetchInterval: 3000,
    refetchOnWindowFocus: true,
  })
