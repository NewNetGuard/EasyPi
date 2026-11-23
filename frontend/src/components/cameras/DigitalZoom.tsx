import { ReactNode, useCallback, useRef, useState } from 'react'
import type { PointerEvent as ReactPointerEvent } from 'react'
import { ZoomIn, ZoomOut, Scan, Monitor } from 'lucide-react'

const MIN = 1
const MAX = 4
const STEP = 0.5

/**
 * Browser-only digital zoom (1x-4x) for the live view. It applies a CSS
 * transform to a wrapper around the player and lets the user drag to pan the
 * magnified image. It never touches the RTSP stream or any camera setting, and
 * is kept entirely separate from hardware/optical zoom.
 */
export default function DigitalZoom({ children }: { children: ReactNode }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const drag = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null)
  const [dragging, setDragging] = useState(false)

  const clamp = useCallback((o: { x: number; y: number }, z: number) => {
    const el = containerRef.current
    if (!el || z <= 1) return { x: 0, y: 0 }
    const maxX = (el.clientWidth * (z - 1)) / 2
    const maxY = (el.clientHeight * (z - 1)) / 2
    return {
      x: Math.max(-maxX, Math.min(maxX, o.x)),
      y: Math.max(-maxY, Math.min(maxY, o.y)),
    }
  }, [])

  const setZoomLevel = (z: number) => {
    const nz = Math.max(MIN, Math.min(MAX, z))
    setZoom(nz)
    setOffset((o) => clamp(o, nz))
  }

  const reset = () => {
    setZoom(1)
    setOffset({ x: 0, y: 0 })
  }

  const onPointerDown = (e: ReactPointerEvent) => {
    if (zoom <= 1) return
    drag.current = { px: e.clientX, py: e.clientY, ox: offset.x, oy: offset.y }
    setDragging(true)
    ;(e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId)
  }
  const onPointerMove = (e: ReactPointerEvent) => {
    const d = drag.current
    if (!d) return
    setOffset(clamp({ x: d.ox + (e.clientX - d.px), y: d.oy + (e.clientY - d.py) }, zoom))
  }
  const endDrag = () => {
    drag.current = null
    setDragging(false)
  }

  const btn =
    'flex h-8 w-8 items-center justify-center rounded-lg bg-black/70 text-white ring-1 ring-white/25 backdrop-blur transition hover:bg-black/90 disabled:cursor-not-allowed disabled:opacity-40'

  return (
    <div ref={containerRef} className="relative h-full w-full overflow-hidden">
      <div
        className="h-full w-full"
        style={{
          transform: `translate(${offset.x}px, ${offset.y}px) scale(${zoom})`,
          transformOrigin: 'center center',
          transition: dragging ? 'none' : 'transform 0.15s ease-out',
        }}
      >
        {children}
      </div>

      {/* Drag-catcher only while zoomed, so the un-zoomed stream stays interactive. */}
      {zoom > 1 && (
        <div
          className="absolute inset-0"
          style={{ cursor: dragging ? 'grabbing' : 'grab', touchAction: 'none' }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerLeave={endDrag}
          onPointerCancel={endDrag}
        />
      )}

      <div className="absolute right-3 top-3 z-10 flex flex-col items-end gap-1">
        <span
          className="mb-0.5 flex items-center gap-1 rounded-md bg-black/70 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-white/90 ring-1 ring-white/20 backdrop-blur"
          title="Browser zoom — magnifies the picture on screen. It does not move the camera."
        >
          <Monitor className="h-3 w-3" /> digital
        </span>
        <button className={btn} title="Digital zoom in (browser only)" onClick={() => setZoomLevel(zoom + STEP)} disabled={zoom >= MAX}>
          <ZoomIn className="h-4 w-4" />
        </button>
        <button className={btn} title="Digital zoom out (browser only)" onClick={() => setZoomLevel(zoom - STEP)} disabled={zoom <= MIN}>
          <ZoomOut className="h-4 w-4" />
        </button>
        {zoom > 1 && (
          <button className={btn} title="Reset digital zoom" onClick={reset}>
            <Scan className="h-4 w-4" />
          </button>
        )}
      </div>

      {zoom > 1 && (
        <div className="absolute left-3 top-3 z-10 rounded-md bg-black/60 px-2 py-1 text-xs font-medium text-white backdrop-blur">
          {zoom.toFixed(1)}× digital
        </div>
      )}
    </div>
  )
}
