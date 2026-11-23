import { useEffect, useRef, useState } from 'react'
import { X, Loader2, RefreshCw } from 'lucide-react'
import { Camera } from '../../types/camera'
import { getApiV1BaseUrl } from '../../utils/apiBase'
import { getCsrfHeaders } from '../../utils/csrf'
import { getWsUrl } from '../../utils/wsBase'
import DigitalZoom from './DigitalZoom'
import PTZControls from './PTZControls'

interface LiveViewModalProps {
  camera: Camera | null
  isOpen: boolean
  onClose: () => void
}

interface StreamInfo {
  transport: 'mse-websocket'
  websocketPath: string
}

interface SignalingMessage {
  type: string
  value?: string
}

const LiveViewModal = ({ camera, isOpen, onClose }: LiveViewModalProps) => {
  const [loading, setLoading] = useState(true)
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [retryKey, setRetryKey] = useState(0)
  const videoRef = useRef<HTMLVideoElement | null>(null)

  useEffect(() => {
    if (!camera || !isOpen) return

    let disposed = false
    let failed = false
    let socket: WebSocket | null = null
    let mediaSource: MediaSource | null = null
    let sourceBuffer: SourceBuffer | null = null
    let mediaUrl: string | null = null
    const pendingSegments: ArrayBuffer[] = []
    let pendingBytes = 0
    let receivedMedia = false
    const videoElement = videoRef.current

    setLoading(true)
    setConnected(false)
    setError(null)

    const stopPlayback = () => {
      socket?.close()
      pendingSegments.length = 0
      pendingBytes = 0
      if (sourceBuffer?.updating) {
        try {
          sourceBuffer.abort()
        } catch {
          // The MediaSource may already have closed.
        }
      }
      if (videoElement) {
        videoElement.pause()
        videoElement.removeAttribute('src')
        videoElement.load()
      }
      if (mediaUrl) URL.revokeObjectURL(mediaUrl)
      sourceBuffer = null
      mediaSource = null
      mediaUrl = null
    }

    const fail = (message: string) => {
      if (disposed || failed) return
      failed = true
      stopPlayback()
      setConnected(false)
      setLoading(false)
      setError(message)
    }

    const start = async () => {
      try {
        const streamResponse = await fetch(
          `${getApiV1BaseUrl()}/cameras/${camera.id}/stream-url`,
          { credentials: 'include' },
        )
        if (!streamResponse.ok) throw new Error('stream unavailable')
        const streamInfo = (await streamResponse.json()) as StreamInfo
        if (
          streamInfo.transport !== 'mse-websocket' ||
          typeof streamInfo.websocketPath !== 'string' ||
          !streamInfo.websocketPath.startsWith('/ws/cameras/')
        ) {
          throw new Error('invalid stream response')
        }

        const csrfHeaders = await getCsrfHeaders(getApiV1BaseUrl())
        const tokenResponse = await fetch(`${getApiV1BaseUrl()}/auth/ws-token`, {
          method: 'POST',
          credentials: 'include',
          headers: Object.keys(csrfHeaders).length ? csrfHeaders : undefined,
        })
        if (!tokenResponse.ok) throw new Error('authorization failed')
        const tokenPayload = await tokenResponse.json()
        if (typeof tokenPayload.ws_token !== 'string' || !tokenPayload.ws_token) {
          throw new Error('authorization failed')
        }
        if (disposed) return

        if (!videoElement || typeof MediaSource === 'undefined') {
          throw new Error('live media is unsupported')
        }
        mediaSource = new MediaSource()
        mediaUrl = URL.createObjectURL(mediaSource)
        videoElement.src = mediaUrl

        const pump = () => {
          if (!sourceBuffer || sourceBuffer.updating || pendingSegments.length === 0) return
          const segment = pendingSegments.shift()
          if (!segment) return
          pendingBytes -= segment.byteLength
          try {
            sourceBuffer.appendBuffer(segment)
          } catch {
            fail('Live stream data could not be played')
          }
        }

        const configureMedia = (contentType: string) => {
          if (!mediaSource || sourceBuffer || !MediaSource.isTypeSupported(contentType)) {
            if (!sourceBuffer) fail('This camera format is not supported by the browser')
            return
          }
          const attach = () => {
            if (!mediaSource || sourceBuffer || mediaSource.readyState !== 'open') return
            try {
              sourceBuffer = mediaSource.addSourceBuffer(contentType)
              sourceBuffer.mode = 'segments'
              sourceBuffer.addEventListener('updateend', () => {
                if (!receivedMedia) {
                  receivedMedia = true
                  setConnected(true)
                  setLoading(false)
                }
                if (
                  videoElement.currentTime > 45 &&
                  sourceBuffer &&
                  !sourceBuffer.updating &&
                  sourceBuffer.buffered.length > 0 &&
                  sourceBuffer.buffered.start(0) < videoElement.currentTime - 30
                ) {
                  try {
                    sourceBuffer.remove(0, videoElement.currentTime - 30)
                    return
                  } catch {
                    // Continue playback; the next update can retry trimming.
                  }
                }
                pump()
              })
              sourceBuffer.addEventListener('error', () => fail('Live stream data is invalid'))
              pump()
            } catch {
              fail('This camera format is not supported by the browser')
            }
          }
          if (mediaSource.readyState === 'open') attach()
          else mediaSource.addEventListener('sourceopen', attach, { once: true })
        }

        const separator = streamInfo.websocketPath.includes('?') ? '&' : '?'
        socket = new WebSocket(
          getWsUrl(
            `${streamInfo.websocketPath}${separator}ws_token=${encodeURIComponent(tokenPayload.ws_token)}`,
          ),
        )
        socket.binaryType = 'arraybuffer'
        socket.onopen = () => {
          if (!socket || disposed) return
          const codecCandidates = [
            'avc1.640029',
            'avc1.64002A',
            'avc1.640033',
            'avc1.4D401F',
            'avc1.42E01E',
            'hvc1.1.6.L153.B0',
            'mp4a.40.2',
            'mp4a.40.5',
            'flac',
            'opus',
          ]
          const supportedCodecs = codecCandidates.filter((codec) =>
            MediaSource.isTypeSupported(`video/mp4; codecs="${codec}"`) ||
            MediaSource.isTypeSupported(`audio/mp4; codecs="${codec}"`),
          )
          socket.send(JSON.stringify({ type: 'mse', value: supportedCodecs.join(',') }))
        }
        socket.onmessage = (event) => {
          if (disposed) return
          if (typeof event.data === 'string') {
            try {
              const message = JSON.parse(event.data) as SignalingMessage
              if (message.type === 'mse' && message.value) configureMedia(message.value)
              else if (message.type === 'error') fail('Live stream is unavailable')
            } catch {
              fail('Live stream returned an invalid response')
            }
            return
          }
          if (!(event.data instanceof ArrayBuffer)) {
            fail('Live stream returned invalid media data')
            return
          }
          pendingBytes += event.data.byteLength
          if (pendingBytes > 32 * 1024 * 1024) {
            fail('Live stream buffer limit exceeded')
            return
          }
          pendingSegments.push(event.data)
          pump()
        }
        socket.onerror = () => fail('Live stream connection failed')
        socket.onclose = () => {
          if (!disposed) fail('Live stream authorization ended')
        }
      } catch {
        fail('Failed to start live stream')
      }
    }

    void start()

    return () => {
      disposed = true
      stopPlayback()
    }
  }, [camera, isOpen, retryKey])

  if (!isOpen || !camera) return null

  const handleRetry = () => setRetryKey((value) => value + 1)

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/80" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="relative w-full max-w-6xl overflow-hidden rounded-2xl bg-gray-900 shadow-2xl">
          <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
            <div>
              <h2 className="text-xl font-bold text-white">{camera.name}</h2>
              <p className="text-sm text-gray-400">{camera.ip}:{camera.port} • RTSP Live</p>
            </div>
            <button onClick={onClose} className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white">
              <X className="h-6 w-6" />
            </button>
          </div>

          <div className="relative aspect-video bg-black">
            <DigitalZoom>
              <video
                ref={videoRef}
                className="h-full w-full bg-black object-contain"
                autoPlay
                muted
                playsInline
                controls
              />
            </DigitalZoom>

            {loading && (
              <div className="absolute inset-0 flex items-center justify-center bg-black">
                <Loader2 className="h-12 w-12 animate-spin text-white" />
              </div>
            )}

            {error && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/80">
                <div className="text-center">
                  <p className="text-lg font-semibold text-white">Stream Error</p>
                  <p className="mt-2 text-sm text-gray-300">{error}</p>
                  <button onClick={handleRetry} className="mt-4 mx-auto flex items-center gap-2 rounded-lg bg-white/20 px-4 py-2 text-white hover:bg-white/30">
                    <RefreshCw className="h-4 w-4" />
                    Retry
                  </button>
                </div>
              </div>
            )}

            {connected && !error && <PTZControls cameraId={camera.id} isOpen={isOpen} />}
          </div>
        </div>
      </div>
    </>
  )
}

export default LiveViewModal
