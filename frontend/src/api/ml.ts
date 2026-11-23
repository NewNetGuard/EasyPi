import api from './client'

export interface MlModelStatus {
  available: boolean
  trained_at?: string | null
  n_benign?: number
  vocab_size?: number
  gibberish_caught?: number
  gibberish_total?: number
  threshold_logp?: number
  benign_mean?: number
  model_bytes?: number
}

export interface MlQuality {
  available: boolean
  benign_tested?: number
  benign_flagged?: number
  benign_from_traffic?: boolean
  clean_pass_rate?: number | null
  false_positive_rate?: number | null
  gibberish_tested?: number
  gibberish_caught?: number
  detection_rate?: number | null
}

export interface FlowBehaviorModelStatus {
  available: boolean
  kind?: string
  model_version?: number
  updated_at?: string | null
  ad_samples?: number
  clean_samples?: number
  min_class_samples?: number
  threshold?: number
  features?: number
  model_bytes?: number
}

export interface MlStatus {
  model: MlModelStatus
  quality: MlQuality
  behavior_model: FlowBehaviorModelStatus
  auto_retrain: { enabled: boolean; interval_hours: number }
}

export const getMlStatus = async (): Promise<MlStatus> => {
  const { data } = await api.get('/dns/heuristics/ml/status')
  return data
}

export interface MlRetrainResult {
  success: boolean
  n_benign?: number
  gibberish_caught?: string
  message?: string
}

export const retrainMl = async (): Promise<MlRetrainResult> => {
  const { data } = await api.post('/dns/heuristics/ml/retrain')
  return data
}
