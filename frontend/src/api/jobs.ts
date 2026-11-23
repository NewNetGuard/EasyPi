import apiClient from './client'

export type JobSource = 'installer' | 'backup' | 'rollback' | 'action'
export type JobStatus = 'queued' | 'running' | 'success' | 'failed' | 'cancelled' | 'unknown'

export interface JobSummary {
  total: number
  running: number
  queued: number
  success: number
  failed: number
  cancelled: number
  unknown: number
}

export interface JobRecord {
  job_id: string
  source: JobSource
  status: JobStatus
  title: string
  subtitle?: string | null
  route?: string | null
  started_at?: string | null
  updated_at?: string | null
  progress?: number | null
  message?: string | null
}

export interface JobsResponse {
  generated_at: string
  summary: JobSummary
  jobs: JobRecord[]
}

export const listJobs = async (limit = 40): Promise<JobsResponse> => {
  const response = await apiClient.get('/jobs', { params: { limit } })
  return response.data
}
