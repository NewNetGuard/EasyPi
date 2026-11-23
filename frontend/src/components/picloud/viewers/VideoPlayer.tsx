import { useState } from 'react'

interface VideoPlayerProps {
  src: string
  onClose: () => void
}

const VideoPlayer = ({ src, onClose }: VideoPlayerProps) => {
  const [failed, setFailed] = useState(false)
  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur flex items-center justify-center">
      <div className="absolute top-4 right-4 flex gap-2">
        <button className="rounded-full bg-white/10 px-4 py-2 text-white" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="w-full max-w-5xl aspect-video">
        {failed ? (
          <p role="alert" className="p-6 text-center text-white">Could not play this video in the browser.</p>
        ) : (
          <video src={src} controls autoPlay playsInline onError={() => setFailed(true)} className="h-full w-full" />
        )}
      </div>
    </div>
  )
}

export default VideoPlayer
