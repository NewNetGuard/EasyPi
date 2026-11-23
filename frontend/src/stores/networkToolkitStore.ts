import { create } from 'zustand'
import type {
  ToolId,
  LANScanResult,
  PortScanResult,
  SpeedTestResult,
  NetworkMapData,
  TrafficData,
  TrafficStats,
  ActiveConnection,
  ARPScanResult,
  PortAlert,
  ScanProgress,
} from '../types/network'

interface NetworkToolkitState {
  // Active tool
  activeTool: ToolId | null
  
  // Scan progress
  scanProgress: Record<ToolId, ScanProgress>
  
  // LAN Scanner
  lanScanResult: LANScanResult | null
  
  // Port Scanner
  portScanResult: PortScanResult | null
  
  // Speed Test
  speedTestResult: SpeedTestResult | null
  
  // Network Map
  networkMapData: NetworkMapData | null
  
  // Traffic Graph
  trafficData: TrafficData[]
  trafficStats: TrafficStats | null
  
  // Active Connections
  activeConnections: ActiveConnection[]
  
  // ARP Scanner
  arpScanResult: ARPScanResult | null
  
  // Open Ports Alert
  portAlerts: PortAlert[]
  
  // Actions
  setActiveTool: (tool: ToolId | null) => void
  setScanProgress: (tool: ToolId, progress: ScanProgress) => void
  setLANScanResult: (result: LANScanResult | null) => void
  setPortScanResult: (result: PortScanResult | null) => void
  setSpeedTestResult: (result: SpeedTestResult | null) => void
  setNetworkMapData: (data: NetworkMapData | null) => void
  setTrafficData: (data: TrafficData[]) => void
  setTrafficStats: (stats: TrafficStats | null) => void
  setActiveConnections: (connections: ActiveConnection[]) => void
  setARPScanResult: (result: ARPScanResult | null) => void
  setPortAlerts: (alerts: PortAlert[]) => void
  clearToolData: (tool: ToolId) => void
  resetAll: () => void
}

const initialProgress: ScanProgress = {
  status: 'idle',
  progress: 0,
}

export const useNetworkToolkitStore = create<NetworkToolkitState>((set) => ({
  // Initial state
  activeTool: null,
  scanProgress: {
    'lan-scanner': { ...initialProgress },
    'port-scanner': { ...initialProgress },
    'speed-test': { ...initialProgress },
    'network-map': { ...initialProgress },
    'traffic-graph': { ...initialProgress },
    'active-connections': { ...initialProgress },
    'arp-scanner': { ...initialProgress },
    'open-ports-alert': { ...initialProgress },
  },
  lanScanResult: null,
  portScanResult: null,
  speedTestResult: null,
  networkMapData: null,
  trafficData: [],
  trafficStats: null,
  activeConnections: [],
  arpScanResult: null,
  portAlerts: [],
  
  // Actions
  setActiveTool: (tool) => set({ activeTool: tool }),
  
  setScanProgress: (tool, progress) =>
    set((state) => ({
      scanProgress: {
        ...state.scanProgress,
        [tool]: progress,
      },
    })),
  
  setLANScanResult: (result) => set({ lanScanResult: result }),
  
  setPortScanResult: (result) => set({ portScanResult: result }),
  
  setSpeedTestResult: (result) => set({ speedTestResult: result }),
  
  setNetworkMapData: (data) => set({ networkMapData: data }),
  
  setTrafficData: (data) => set({ trafficData: data }),
  
  setTrafficStats: (stats) => set({ trafficStats: stats }),
  
  setActiveConnections: (connections) => set({ activeConnections: connections }),
  
  setARPScanResult: (result) => set({ arpScanResult: result }),
  
  setPortAlerts: (alerts) => set({ portAlerts: alerts }),
  
  clearToolData: (tool) =>
    set((state) => {
      const updates: Partial<NetworkToolkitState> = {
        scanProgress: {
          ...state.scanProgress,
          [tool]: { ...initialProgress },
        },
      }
      
      switch (tool) {
        case 'lan-scanner':
          updates.lanScanResult = null
          break
        case 'port-scanner':
          updates.portScanResult = null
          break
        case 'speed-test':
          updates.speedTestResult = null
          break
        case 'network-map':
          updates.networkMapData = null
          break
        case 'traffic-graph':
          updates.trafficData = []
          updates.trafficStats = null
          break
        case 'active-connections':
          updates.activeConnections = []
          break
        case 'arp-scanner':
          updates.arpScanResult = null
          break
        case 'open-ports-alert':
          updates.portAlerts = []
          break
      }
      
      return updates as NetworkToolkitState
    }),
  
  resetAll: () =>
    set({
      activeTool: null,
      scanProgress: {
        'lan-scanner': { ...initialProgress },
        'port-scanner': { ...initialProgress },
        'speed-test': { ...initialProgress },
        'network-map': { ...initialProgress },
        'traffic-graph': { ...initialProgress },
        'active-connections': { ...initialProgress },
        'arp-scanner': { ...initialProgress },
        'open-ports-alert': { ...initialProgress },
      },
      lanScanResult: null,
      portScanResult: null,
      speedTestResult: null,
      networkMapData: null,
      trafficData: [],
      trafficStats: null,
      activeConnections: [],
      arpScanResult: null,
      portAlerts: [],
    }),
}))
