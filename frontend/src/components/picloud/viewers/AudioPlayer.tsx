import { useState, useRef, useEffect } from 'react'
import { Play, Pause, SkipBack, SkipForward } from 'lucide-react'

interface AudioPlayerProps {
  src: string
  playlist?: string[]
  onClose: () => void
}

const AudioPlayer = ({ src, onClose }: AudioPlayerProps) => {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const [playing, setPlaying] = useState(true)
  const [current] = useState(src)

  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.src = current
      audioRef.current.play()
    }
  }, [current])

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur flex items-center justify-center">
      <div className="absolute top-4 right-4">
        <button className="rounded-full bg-white/10 px-4 py-2 text-white" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="w-full max-w-xl rounded-2xl bg-white p-6 shadow-2xl space-y-4">
        <audio ref={audioRef} src={current} autoPlay onPlay={() => setPlaying(true)} onPause={() => setPlaying(false)} controls className="w-full" />
        <div className="flex items-center justify-center gap-3">
          <button className="rounded-full bg-gray-100 p-2">
            <SkipBack className="h-5 w-5" />
          </button>
          <button
            className="rounded-full bg-primary-500 p-3 text-white"
            onClick={() => {
              if (audioRef.current) {
                if (playing) audioRef.current.pause()
                else audioRef.current.play()
              }
            }}
          >
            {playing ? <Pause className="h-5 w-5" /> : <Play className="h-5 w-5" />}
          </button>
          <button className="rounded-full bg-gray-100 p-2">
            <SkipForward className="h-5 w-5" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default AudioPlayer
