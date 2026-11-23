import axios from 'axios'
import { getApiBaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'
import type {
  HostScanResponse,
  PortScanResponse,
  PingResponse,
  DnsLookupResponse,
  SpeedtestResponse,
  LANScanResult,
  LANScanConfig,
  PortScanResult,
  PortScanConfig,
  SpeedTestResult,
  SpeedTestConfig,
  // SpeedTestProgress,
  NetworkMapData,
  NetworkMapConfig,
  TrafficData,
  TrafficStats,
  ActiveConnection,
  ConnectionFilters,
  ARPScanResult,
  PortAlert,
  PortAlertConfig,
  NetworkApiResponse,
} from '../types/network'

const client = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 120000,
  withCredentials: true,  // Send httpOnly cookies
})

// Add CSRF token to mutating requests
client.interceptors.request.use(async (config) => {
  if (config.method && ['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase())) {
    const csrfHeaders = await getCsrfHeaders()
    for (const [key, value] of Object.entries(csrfHeaders)) {
      config.headers[key] = value
    }
  }
  return config
})

// Auth is handled via httpOnly cookies
// No need for Authorization header interceptor

const handleError = (error: unknown) => {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (detail) {
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    }
  }
  throw error
}

// Legacy API (for backward compatibility)
export const scanHosts = async (network: string, opts?: { deep?: boolean }): Promise<HostScanResponse> => {
  try {
    const response = await client.get<HostScanResponse>('/api/network/hosts', {
      params: { network, deep: opts?.deep ?? false },
    })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const quickPortScan = async (target: string): Promise<PortScanResponse> => {
  try {
    const response = await client.get<PortScanResponse>('/api/network/ports/quick', { params: { target } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const fullPortScan = async (target: string): Promise<PortScanResponse> => {
  try {
    const response = await client.get<PortScanResponse>('/api/network/ports/full', { params: { target } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const deepPortScan = async (target: string): Promise<PortScanResponse> => {
  try {
    const response = await client.get<PortScanResponse>('/api/network/ports/deep', { params: { target } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const pingHost = async (target: string): Promise<PingResponse> => {
  try {
    const response = await client.get<PingResponse>('/api/network/ping', { params: { target } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const dnsLookup = async (domain: string): Promise<DnsLookupResponse> => {
  try {
    const response = await client.get<DnsLookupResponse>('/api/network/dns', { params: { domain } })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const runSpeedtest = async (): Promise<SpeedtestResponse> => {
  try {
    const response = await client.get<SpeedtestResponse>('/api/network/speedtest')
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// New Network Toolkit API

// LAN Scanner
export const scanLAN = async (config: LANScanConfig): Promise<NetworkApiResponse<LANScanResult>> => {
  try {
    const response = await client.post<NetworkApiResponse<LANScanResult>>('/api/network-toolkit/lan-scan', config)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Port Scanner
export const scanPorts = async (config: PortScanConfig): Promise<NetworkApiResponse<PortScanResult>> => {
  try {
    const response = await client.post<NetworkApiResponse<PortScanResult>>('/api/network-toolkit/port-scan', config)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Speed Test
export const startSpeedTest = async (
  config: SpeedTestConfig
): Promise<NetworkApiResponse<SpeedTestResult>> => {
  try {
    const response = await client.post<NetworkApiResponse<SpeedTestResult>>(
      '/api/network-toolkit/speed-test',
      config,
      {
        timeout: 180000, // 3 минуты для теста скорости
      }
    )
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Network Map
export const getNetworkMap = async (config: NetworkMapConfig): Promise<NetworkApiResponse<NetworkMapData>> => {
  try {
    const response = await client.post<NetworkApiResponse<NetworkMapData>>('/api/network-toolkit/network-map', config)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Traffic Graph
export const getTrafficData = async (duration: number = 60): Promise<NetworkApiResponse<TrafficData[]>> => {
  try {
    const response = await client.get<NetworkApiResponse<TrafficData[]>>('/api/network-toolkit/traffic', {
      params: { duration },
    })
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const getTrafficStats = async (): Promise<NetworkApiResponse<TrafficStats>> => {
  try {
    const response = await client.get<NetworkApiResponse<TrafficStats>>('/api/network-toolkit/traffic/stats')
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Active Connections
export const getActiveConnections = async (
  filters?: ConnectionFilters
): Promise<NetworkApiResponse<ActiveConnection[]>> => {
  try {
    const response = await client.post<NetworkApiResponse<ActiveConnection[]>>(
      '/api/network-toolkit/connections',
      filters || {}
    )
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// ARP Scanner
export const scanARP = async (): Promise<NetworkApiResponse<ARPScanResult>> => {
  try {
    const response = await client.get<NetworkApiResponse<ARPScanResult>>('/api/network-toolkit/arp-scan')
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Network Info (auto-detect network range)
export interface NetworkInfo {
  localIp: string
  gateway: string
  netmask: string
  interface: string
  networkRange: string
}

export const getNetworkInfo = async (): Promise<NetworkApiResponse<NetworkInfo>> => {
  try {
    const response = await client.get<NetworkApiResponse<NetworkInfo>>('/api/network-toolkit/network-info')
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

// Open Ports Alert
export const getPortAlerts = async (): Promise<NetworkApiResponse<PortAlert[]>> => {
  try {
    const response = await client.get<NetworkApiResponse<PortAlert[]>>('/api/network-toolkit/port-alerts')
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const updatePortAlertConfig = async (config: PortAlertConfig): Promise<NetworkApiResponse<PortAlertConfig>> => {
  try {
    const response = await client.post<NetworkApiResponse<PortAlertConfig>>(
      '/api/network-toolkit/port-alerts/config',
      config
    )
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}

export const dismissPortAlert = async (alertId: string): Promise<NetworkApiResponse<void>> => {
  try {
    const response = await client.delete<NetworkApiResponse<void>>(`/api/network-toolkit/port-alerts/${alertId}`)
    return response.data
  } catch (error) {
    handleError(error)
    throw error
  }
}
