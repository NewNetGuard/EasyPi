import { useQuery } from '@tanstack/react-query'
import { useCallback, useState } from 'react'

import * as ptzApi from '../api/ptz'
import { PTZCapabilities, PTZDirection, PTZMode } from '../types/ptz'

/**
 * Capability-driven PTZ controller for one camera.
 *
 * The backend re-checks every capability and role, so this hook only shapes the
 * UX: continuous cameras move-while-held + Stop on release; relative-only
 * cameras (e.g. Thingino step motors) send one short relative step per press.
 */
export function usePTZ(cameraId: string, enabled: boolean) {
  const [speed, setSpeed] = useState(0.5)

  const {
    data: caps,
    isLoading,
    error,
    refetch,
  } = useQuery<PTZCapabilities>({
    queryKey: ['ptz-capabilities', cameraId],
    queryFn: () => ptzApi.getCapabilities(cameraId),
    enabled: enabled && !!cameraId,
    staleTime: 30_000,
    retry: false,
  })

  const isContinuous = !!caps?.continuous_move

  const dirVec = (dir: PTZDirection) => ({
    pan: dir.includes('r') ? 1 : dir.includes('l') ? -1 : 0,
    tilt: dir.includes('u') ? 1 : dir.includes('d') ? -1 : 0,
  })

  const startMove = useCallback(
    (dir: PTZDirection) => {
      if (!caps?.available) return
      const { pan, tilt } = dirVec(dir)
      const mode: PTZMode | null = isContinuous
        ? 'continuous'
        : caps?.relative_move
          ? 'relative'
          : null
      if (!mode) return
      void ptzApi.move(cameraId, { pan, tilt, zoom: 0, speed, mode }).catch(() => undefined)
    },
    [cameraId, caps, speed, isContinuous],
  )

  // For continuous motion, releasing must Stop. Relative steps end on their own.
  const stopMove = useCallback(() => {
    if (isContinuous && caps?.stop) void ptzApi.stop(cameraId).catch(() => undefined)
  }, [cameraId, caps, isContinuous])

  // Explicit Stop button: always send Stop (highest priority; harmless no-op if idle).
  const stopNow = useCallback(() => {
    void ptzApi.stop(cameraId).catch(() => undefined)
  }, [cameraId])

  const zoomStart = useCallback(
    (dir: 'in' | 'out') => {
      if (!caps?.optical_zoom) return
      const mode: PTZMode = isContinuous ? 'continuous' : 'relative'
      void ptzApi
        .move(cameraId, { pan: 0, tilt: 0, zoom: dir === 'in' ? 1 : -1, speed, mode })
        .catch(() => undefined)
    },
    [cameraId, caps, speed, isContinuous],
  )

  const goHome = useCallback(() => {
    if (caps?.home) void ptzApi.goHome(cameraId).catch(() => undefined)
  }, [cameraId, caps])

  return {
    caps,
    isLoading,
    error,
    refetch,
    speed,
    setSpeed,
    isContinuous,
    startMove,
    stopMove,
    stopNow,
    zoomStart,
    zoomStop: stopMove,
    goHome,
  }
}
