export interface PTZCapabilities {
  available: boolean
  adapter: string
  detected: boolean
  pan: boolean
  tilt: boolean
  optical_zoom: boolean
  continuous_move: boolean
  relative_move: boolean
  absolute_move: boolean
  stop: boolean
  home: boolean
  presets: boolean
  position_feedback: boolean
  last_probe_at?: string | null
  probe_error?: string | null
}

export interface PTZPreset {
  token: string
  name: string
}

export type PTZMode = 'continuous' | 'relative' | 'absolute'

// 8-way direction tokens; a letter present means that axis moves:
//  u=up  d=down  l=left  r=right  (diagonals combine, e.g. 'ur')
export type PTZDirection = 'u' | 'd' | 'l' | 'r' | 'ul' | 'ur' | 'dl' | 'dr'
