import { useState } from 'react'
import { Document, Page, pdfjs } from 'react-pdf'
import ReactMarkdown from 'react-markdown'
import 'react-pdf/dist/Page/AnnotationLayer.css'
import 'react-pdf/dist/Page/TextLayer.css'
import pdfWorkerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url'

pdfjs.GlobalWorkerOptions.workerSrc = pdfWorkerUrl

interface DocumentViewerProps {
  src: string
  type: 'pdf' | 'markdown' | 'text' | 'image'
  content?: string
  onClose: () => void
}

const DocumentViewer = ({ src, type, content, onClose }: DocumentViewerProps) => {
  const [numPages, setNumPages] = useState<number>()

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur flex items-center justify-center">
      <div className="absolute top-4 right-4">
        <button className="rounded-full bg-white/10 px-4 py-2 text-white" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="w-full max-w-5xl h-[80vh] overflow-auto bg-white rounded-2xl p-4 shadow-2xl">
        {type === 'pdf' && (
          <Document file={src} onLoadSuccess={({ numPages }) => setNumPages(numPages)}>
            {Array.from(new Array(numPages), (_el, index) => (
              <Page key={`page_${index + 1}`} pageNumber={index + 1} />
            ))}
          </Document>
        )}
        {type === 'image' && (
          <img src={src} alt="Document preview" className="mx-auto max-w-full" />
        )}
        {type === 'markdown' && <ReactMarkdown className="prose max-w-none">{content || ''}</ReactMarkdown>}
        {type === 'text' && <pre className="text-sm text-gray-800 whitespace-pre-wrap">{content}</pre>}
      </div>
    </div>
  )
}

export default DocumentViewer
