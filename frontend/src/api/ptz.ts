import api from './client'
import { PTZCapabilities, PTZMode, PTZPreset } from '../types/ptz'

const base = (id: string) => `/cameras/${id}/ptz`

export interface PTZMoveBody {
  pan: number
  tilt: number
  zoom: number
  speed: number
  mode: PTZMode
}

export async function getCapabilities(id: string): Promise<PTZCapabilities> {
  const { data } = await api.get(`${base(id)}/capabilities`)
  return data
}

export async function move(id: string, body: PTZMoveBody) {
  const { data } = await api.post(`${base(id)}/move`, body)
  return data
}

export async function stop(id: string) {
  const { data } = await api.post(`${base(id)}/stop`, {})
  return data
}

export async function goHome(id: string) {
  const { data } = await api.post(`${base(id)}/home`, {})
  return data
}

export async function setHome(id: string) {
  const { data } = await api.post(`${base(id)}/home/set`, {})
  return data
}

export async function detect(id: string): Promise<PTZCapabilities> {
  const { data } = await api.post(`${base(id)}/detect`, {})
  return data
}

export interface DiscoveredCamera {
  ip: string
  onvif_port: number
  xaddr: string
  name: string
  hardware: string
}

// WS-Discovery: find ONVIF cameras on the local network (admin). Each device
// reports its own IP + ONVIF port, so nothing is scanned or guessed. An optional
// ip adds a directed unicast probe (for a camera on another subnet).
export async function discoverCameras(ip?: string): Promise<{ devices: DiscoveredCamera[]; count: number }> {
  const { data } = await api.post(`/cameras/discover`, ip ? { ip } : {})
  return data
}

export async function setAdapter(id: string, adapter: string): Promise<PTZCapabilities> {
  const { data } = await api.post(`${base(id)}/adapter`, { adapter })
  return data
}

export async function getPresets(id: string): Promise<{ presets: PTZPreset[] }> {
  const { data } = await api.get(`${base(id)}/presets`)
  return data
}

export async function gotoPreset(id: string, token: string) {
  const { data } = await api.post(`${base(id)}/presets/${encodeURIComponent(token)}/goto`, {})
  return data
}

export async function createPreset(id: string, name: string) {
  const { data } = await api.post(`${base(id)}/presets`, { name })
  return data
}

export async function deletePreset(id: string, token: string) {
  const { data } = await api.delete(`${base(id)}/presets/${encodeURIComponent(token)}`)
  return data
}
