import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getServiceMetrics, getSystemStats } from '../api/monitoring'
import { ServiceMetric, SystemStats } from '../types/monitoring'
import { getWsUrl } from '../utils/wsBase'
import { getApiV1BaseUrl } from '../utils/apiBase'
import { getCsrfHeaders } from '../utils/csrf'

export const useSystemStats = () =>
  useQuery<SystemStats>({
    queryKey: ['systemStats'],
    queryFn: getSystemStats,
    refetchInterval: 5000,
  })

export const useServiceMetrics = () =>
  useQuery<ServiceMetric[]>({
    queryKey: ['serviceMetrics'],
    queryFn: getServiceMetrics,
    refetchInterval: 15000,
  })

export interface MonitoringSample {
  timestamp: string
  cpu: number
  ramUsed: number
  ramTotal: number
  temp: number | null
  diskUsed: number
  diskTotal: number
  netRx: number
  netTx: number
}

const MAX_SAMPLES = 7200 // ~2 часов истории при обновлении каждую секунду

export const useMonitoringStream = () => {
  const [samples, setSamples] = useState<MonitoringSample[]>([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<number | null>(null)

  useEffect(() => {
    const connect = async () => {
      try {
        // Get temporary WS token via authenticated request
        const csrfHeaders = await getCsrfHeaders(getApiV1BaseUrl())
        const response = await fetch(`${getApiV1BaseUrl()}/auth/ws-token`, {
          method: 'POST',
          credentials: 'include',  // Send httpOnly cookies
          headers: Object.keys(csrfHeaders).length ? csrfHeaders : undefined,
        })
        
        if (!response.ok) {
          console.error('Failed to get WebSocket token for monitoring')
          reconnectRef.current = window.setTimeout(connect, 3000)
          return
        }
        
        const data = await response.json()
        const wsToken = data.ws_token
        
        if (!wsToken) {
          console.error('No WebSocket token received for monitoring')
          reconnectRef.current = window.setTimeout(connect, 3000)
          return
        }

        const wsUrl = getWsUrl(`/ws/monitoring?ws_token=${encodeURIComponent(wsToken)}`)
        const socket = new WebSocket(wsUrl)
        wsRef.current = socket

        socket.onopen = () => setConnected(true)
        socket.onclose = () => {
          setConnected(false)
          reconnectRef.current = window.setTimeout(connect, 3000)
        }
        socket.onerror = () => {
          socket.close()
        }

        socket.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data)
            const disks = Array.isArray(payload.disk) ? payload.disk : []
            let diskTotals = { used: 0, total: 0 }
            if (disks.length > 0) {
              const rootDisk = disks.find((disk: any) => disk.mount === '/')
              const bestDisk =
                rootDisk ||
                disks.reduce(
                  (best: any, disk: any) => ((disk.total || 0) > (best.total || 0) ? disk : best),
                  disks[0],
                )
              diskTotals = {
                used: Number(bestDisk?.used ?? 0),
                total: Number(bestDisk?.total ?? 0),
              }
            }

            const sample: MonitoringSample = {
              timestamp: payload.timestamp,
              cpu: Number(payload.cpu?.usage ?? 0),
              ramUsed: Number(payload.ram?.used ?? 0),
              ramTotal: Number(payload.ram?.total ?? 0),
              temp: payload.temp?.celsius ?? null,
              diskUsed: diskTotals.used,
              diskTotal: diskTotals.total,
              netRx: Number(payload.net?.rx ?? 0),
              netTx: Number(payload.net?.tx ?? 0),
            }

            setSamples((prev) => {
              const next = [...prev, sample]
              return next.length > MAX_SAMPLES ? next.slice(next.length - MAX_SAMPLES) : next
            })
          } catch (error) {
            console.error('Failed to parse monitoring payload', error)
          }
        }
      } catch (error) {
        console.error('Failed to initialize monitoring WebSocket:', error)
        reconnectRef.current = window.setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current)
      }
      wsRef.current?.close()
    }
  }, [])

  const latest = samples[samples.length - 1]

  return { samples, latest, connected }
}
