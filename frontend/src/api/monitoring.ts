import api from './client'
import { ServiceMetric, SystemStats } from '../types/monitoring'

const BASE_PATH = '/monitoring'

export const getSystemStats = async (): Promise<SystemStats> => {
  const response = await api.get<SystemStats>(`${BASE_PATH}/stats`)
  return response.data
}

export const getServiceMetrics = async (): Promise<ServiceMetric[]> => {
  const response = await api.get<ServiceMetric[]>(`${BASE_PATH}/services`)
  return response.data
}
