export interface CpuStat {
  usage: number
}

export interface RamStat {
  used: number
  total: number
}

export interface DiskStat {
  used: number
  total: number
  mount: string
}

export interface NetStat {
  rx: number
  tx: number
}

export interface TempStat {
  celsius: number | null
}

export interface SystemStats {
  cpu: CpuStat
  ram: RamStat
  disk: DiskStat[]
  net: NetStat
  temp: TempStat
  timestamp: string
}

export interface ServiceMetric {
  name: string
  running: boolean
  uptime?: number | null
  cpu?: number | null
  ram?: number | null
}
