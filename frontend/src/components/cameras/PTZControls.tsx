import { KeyboardEvent as ReactKeyboardEvent, useCallback, useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  ArrowUp,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUpLeft,
  ArrowUpRight,
  ArrowDownLeft,
  ArrowDownRight,
  Home,
  Square,
  ZoomIn,
  ZoomOut,
  Loader2,
  Search,
  Trash2,
  Plus,
  Move,
  ChevronDown,
  ChevronUp,
  Gamepad2,
} from 'lucide-react'

import { usePTZ } from '../../hooks/usePTZ'
import * as ptzApi from '../../api/ptz'
import { useAuthStore } from '../../stores/authStore'
import { PTZDirection } from '../../types/ptz'

interface Props {
  cameraId: string
  isOpen: boolean
}

const DIRS: { dir: PTZDirection; icon: JSX.Element; cell: string }[] = [
  { dir: 'ul', icon: <ArrowUpLeft className="h-4 w-4" />, cell: 'col-start-1 row-start-1' },
  { dir: 'u', icon: <ArrowUp className="h-4 w-4" />, cell: 'col-start-2 row-start-1' },
  { dir: 'ur', icon: <ArrowUpRight className="h-4 w-4" />, cell: 'col-start-3 row-start-1' },
  { dir: 'l', icon: <ArrowLeft className="h-4 w-4" />, cell: 'col-start-1 row-start-2' },
  { dir: 'r', icon: <ArrowRight className="h-4 w-4" />, cell: 'col-start-3 row-start-2' },
  { dir: 'dl', icon: <ArrowDownLeft className="h-4 w-4" />, cell: 'col-start-1 row-start-3' },
  { dir: 'd', icon: <ArrowDown className="h-4 w-4" />, cell: 'col-start-2 row-start-3' },
  { dir: 'dr', icon: <ArrowDownRight className="h-4 w-4" />, cell: 'col-start-3 row-start-3' },
]

const padBtn =
  'flex h-9 w-9 items-center justify-center rounded-lg bg-white/10 text-white transition hover:bg-white/25 active:bg-white/40 disabled:cursor-not-allowed disabled:opacity-30'

export default function PTZControls({ cameraId, isOpen }: Props) {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const ptz = usePTZ(cameraId, isOpen)
  const { caps, refetch } = ptz
  const [detecting, setDetecting] = useState(false)
  const heldKeys = useRef<Set<string>>(new Set())
  const autoTried = useRef(false)
  // Remembered across cameras/sessions: the pad hides a big chunk of the frame,
  // so let the user collapse it to a small handle and keep that choice.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem('ptzPadCollapsed') === '1'
    } catch {
      return false
    }
  })
  const setCollapsedPersist = (v: boolean) => {
    setCollapsed(v)
    try {
      localStorage.setItem('ptzPadCollapsed', v ? '1' : '0')
    } catch {
      /* ignore storage errors */
    }
  }

  const presetsQuery = useQuery({
    queryKey: ['ptz-presets', cameraId],
    queryFn: () => ptzApi.getPresets(cameraId),
    enabled: isOpen && !!caps?.available && !!caps?.presets,
    staleTime: 30_000,
    retry: false,
  })
  const [newPreset, setNewPreset] = useState('')

  const runDetect = useCallback(async () => {
    setDetecting(true)
    try {
      const result = await ptzApi.detect(cameraId)
      await refetch()
      if (result?.available) {
        toast.success(`PTZ detected via ${(result.adapter || '').toUpperCase()}`)
      } else if (result?.probe_error) {
        // Surface the real reason (e.g. "onvif: camera rejected ONVIF credentials;
        // thingino: camera rejected the API key") instead of failing silently.
        toast.error(`PTZ not detected — ${result.probe_error}`, { duration: 8000 })
      } else {
        toast.error('No PTZ protocol answered on this camera')
      }
    } catch {
      toast.error('PTZ detection could not run')
    } finally {
      setDetecting(false)
    }
  }, [cameraId, refetch])

  // First time an admin opens a camera that has never been probed, auto-detect so
  // the pad can appear without a manual step, using the camera's own login. Runs
  // once per open; a probe (even a failed one) sets detected=true so it never
  // loops — manual retry stays available on the "not set up" hint.
  useEffect(() => {
    if (!isOpen) {
      autoTried.current = false
      return
    }
    if (autoTried.current || !isAdmin || detecting || ptz.isLoading || !caps) return
    if (caps.detected === false) {
      autoTried.current = true
      void runDetect()
    }
  }, [isOpen, isAdmin, caps, ptz.isLoading, detecting, runDetect])

  const dirEnabled = (dir: PTZDirection) => {
    if (!caps?.available) return false
    if (!(caps.continuous_move || caps.relative_move)) return false
    const needsPan = dir.includes('l') || dir.includes('r')
    const needsTilt = dir.includes('u') || dir.includes('d')
    return (!needsPan || caps.pan) && (!needsTilt || caps.tilt)
  }

  const onKeyDown = (e: ReactKeyboardEvent) => {
    const map: Record<string, PTZDirection> = { ArrowUp: 'u', ArrowDown: 'd', ArrowLeft: 'l', ArrowRight: 'r' }
    if (e.key in map) {
      e.preventDefault()
      if (e.repeat || heldKeys.current.has(e.key)) return
      if (!dirEnabled(map[e.key])) return
      heldKeys.current.add(e.key)
      ptz.startMove(map[e.key])
    } else if (e.key === 'Escape' || e.key === ' ') {
      e.preventDefault()
      heldKeys.current.clear()
      ptz.stopNow()
    }
  }
  const onKeyUp = (e: ReactKeyboardEvent) => {
    if (heldKeys.current.has(e.key)) {
      heldKeys.current.delete(e.key)
      ptz.stopMove()
    }
  }

  // --- unavailable / loading states -------------------------------------
  if (ptz.isLoading) {
    return (
      <div className="pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 rounded-lg bg-black/60 px-3 py-1.5 text-xs text-gray-300 backdrop-blur">
        <Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> PTZ…
      </div>
    )
  }

  if (!caps?.available) {
    return (
      <div className="absolute bottom-3 left-1/2 flex max-w-[22rem] -translate-x-1/2 flex-col items-center gap-1 rounded-lg bg-black/65 px-3 py-2 text-xs text-gray-200 backdrop-blur">
        <div className="flex items-center gap-1.5">
          <Move className="h-3.5 w-3.5 text-gray-400" />
          <span>{detecting ? 'Checking for camera movement…' : "Camera movement (PTZ) isn't set up"}</span>
        </div>
        {caps?.probe_error && !detecting && (
          <span className="max-w-[20rem] text-center text-[11px] leading-snug text-amber-300/90">
            {caps.probe_error}
          </span>
        )}
        {isAdmin ? (
          <button
            onClick={runDetect}
            disabled={detecting}
            className="flex items-center gap-1 rounded bg-white/15 px-2 py-0.5 text-[11px] text-white hover:bg-white/25 disabled:opacity-50"
          >
            {detecting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
            {caps?.probe_error ? 'Retry detection' : 'Detect PTZ'}
          </button>
        ) : (
          <span className="text-[11px] text-gray-400">Ask an admin to enable it</span>
        )}
      </div>
    )
  }

  const adapterLabel = caps.adapter === 'onvif' ? 'ONVIF' : caps.adapter === 'thingino' ? 'Thingino' : caps.adapter

  // --- collapsed: just a small handle so the pad doesn't cover the frame ---
  if (collapsed) {
    return (
      <button
        onClick={() => setCollapsedPersist(false)}
        title="Show camera controls"
        className="absolute bottom-3 left-1/2 flex -translate-x-1/2 items-center gap-1.5 rounded-full bg-black/55 px-3 py-1.5 text-xs font-medium text-white shadow-lg backdrop-blur transition hover:bg-black/75"
      >
        <Gamepad2 className="h-4 w-4" />
        Controls
        <ChevronUp className="h-3.5 w-3.5" />
      </button>
    )
  }

  // --- active control pad -----------------------------------------------
  return (
    <div
      tabIndex={0}
      onKeyDown={onKeyDown}
      onKeyUp={onKeyUp}
      onBlur={ptz.stopMove}
      className="absolute bottom-3 left-1/2 flex -translate-x-1/2 items-center gap-4 rounded-2xl bg-black/55 px-4 py-3 text-white shadow-xl outline-none backdrop-blur"
    >
      {/* D-pad + Home */}
      <div className="grid grid-cols-3 grid-rows-3 gap-1">
        {DIRS.map(({ dir, icon, cell }) => (
          <button
            key={dir}
            className={`${padBtn} ${cell}`}
            disabled={!dirEnabled(dir)}
            title={dir}
            onPointerDown={() => ptz.startMove(dir)}
            onPointerUp={ptz.stopMove}
            onPointerLeave={ptz.stopMove}
            onPointerCancel={ptz.stopMove}
          >
            {icon}
          </button>
        ))}
        <button
          className={`${padBtn} col-start-2 row-start-2`}
          disabled={!caps.home}
          title="Home / center"
          onClick={ptz.goHome}
        >
          <Home className="h-4 w-4" />
        </button>
      </div>

      {/* Stop + speed */}
      <div className="flex flex-col items-center gap-2">
        <button
          onClick={ptz.stopNow}
          title="Stop (Esc / Space)"
          className="flex h-10 w-10 items-center justify-center rounded-full bg-red-600 text-white transition hover:bg-red-500 active:bg-red-700"
        >
          <Square className="h-5 w-5" fill="currentColor" />
        </button>
        <div className="flex w-24 flex-col items-center">
          <input
            type="range"
            min={0.1}
            max={1}
            step={0.05}
            value={ptz.speed}
            onChange={(e) => ptz.setSpeed(Number(e.target.value))}
            className="w-full accent-blue-500"
            title="Speed"
          />
          <span className="text-[10px] text-gray-300">speed {Math.round(ptz.speed * 100)}%</span>
        </div>
      </div>

      {/* Optical zoom (only if hardware supports it; digital zoom is separate) */}
      {caps.optical_zoom && (
        <div className="flex flex-col items-center gap-1">
          <span className="text-[9px] font-medium uppercase tracking-wide text-gray-400" title="Hardware lens zoom — moves the camera optics">
            optical
          </span>
          <button
            className={padBtn}
            title="Optical zoom in"
            onPointerDown={() => ptz.zoomStart('in')}
            onPointerUp={ptz.zoomStop}
            onPointerLeave={ptz.zoomStop}
            onPointerCancel={ptz.zoomStop}
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            className={padBtn}
            title="Optical zoom out"
            onPointerDown={() => ptz.zoomStart('out')}
            onPointerUp={ptz.zoomStop}
            onPointerLeave={ptz.zoomStop}
            onPointerCancel={ptz.zoomStop}
          >
            <ZoomOut className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Presets */}
      {caps.presets && (
        <div className="flex max-w-[9rem] flex-col gap-1">
          <div className="flex flex-wrap gap-1">
            {(presetsQuery.data?.presets ?? []).map((p) => (
              <span key={p.token} className="flex items-center gap-0.5">
                <button
                  onClick={() => ptzApi.gotoPreset(cameraId, p.token).catch(() => undefined)}
                  className="rounded bg-white/10 px-2 py-0.5 text-xs hover:bg-white/25"
                  title={`Go to ${p.name}`}
                >
                  {p.name}
                </button>
                {isAdmin && (
                  <button
                    onClick={async () => {
                      await ptzApi.deletePreset(cameraId, p.token).catch(() => undefined)
                      queryClient.invalidateQueries({ queryKey: ['ptz-presets', cameraId] })
                    }}
                    className="text-gray-400 hover:text-red-400"
                    title="Delete preset"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                )}
              </span>
            ))}
          </div>
          {isAdmin && (
            <form
              className="flex items-center gap-1"
              onSubmit={async (e) => {
                e.preventDefault()
                if (!newPreset.trim()) return
                await ptzApi.createPreset(cameraId, newPreset.trim()).catch(() => undefined)
                setNewPreset('')
                queryClient.invalidateQueries({ queryKey: ['ptz-presets', cameraId] })
              }}
            >
              <input
                value={newPreset}
                onChange={(e) => setNewPreset(e.target.value)}
                placeholder="new preset"
                maxLength={64}
                className="w-20 rounded bg-white/10 px-1.5 py-0.5 text-xs placeholder:text-gray-500"
              />
              <button type="submit" className="text-gray-300 hover:text-white" title="Save preset">
                <Plus className="h-3.5 w-3.5" />
              </button>
            </form>
          )}
        </div>
      )}

      {/* Adapter indicator */}
      <span className="rounded-full bg-white/10 px-2 py-1 text-[10px] font-medium uppercase tracking-wide text-gray-200">
        {adapterLabel}
      </span>

      {/* Collapse the pad out of the way */}
      <button
        onClick={() => setCollapsedPersist(true)}
        title="Hide controls"
        className="ml-1 rounded-lg p-1.5 text-gray-300 transition hover:bg-white/10 hover:text-white"
      >
        <ChevronDown className="h-4 w-4" />
      </button>
    </div>
  )
}
