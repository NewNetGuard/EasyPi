import ImageGallery from 'react-image-gallery'
import 'react-image-gallery/styles/css/image-gallery.css'

interface ImageViewerProps {
  images: string[]
  startIndex?: number
  onClose: () => void
}

const ImageViewer = ({ images, startIndex = 0, onClose }: ImageViewerProps) => {
  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur flex items-center justify-center">
      <div className="absolute top-4 right-4">
        <button className="rounded-full bg-white/10 px-4 py-2 text-white" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="w-full max-w-5xl">
        <ImageGallery
          items={images.map((src) => ({ original: src, thumbnail: src }))}
          startIndex={startIndex}
          showFullscreenButton={false}
          showPlayButton={false}
          showIndex
        />
      </div>
    </div>
  )
}

export default ImageViewer
