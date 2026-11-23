import type { PiCloudFile } from '../types/cloud'

const TEXT_DOCUMENT_EXTENSIONS = new Set([
  '.txt',
  '.md',
  '.csv',
  '.log',
  '.json',
  '.yaml',
  '.yml',
])

const COMPOUND_EXTENSIONS = ['.tar.gz', '.tar.bz2', '.tar.xz']

export type CloudPreviewKind = 'file' | 'text' | 'markdown' | 'document-image'

type CloudFileName = Pick<PiCloudFile, 'name' | 'extension'>
type CloudCardFile = Pick<PiCloudFile, 'type' | 'name' | 'extension' | 'mime' | 'category'>

const IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'])
const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.mkv', '.avi', '.mpeg', '.mpg', '.m4v'])
const AUDIO_EXTENSIONS = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac', '.opus', '.wma'])

export const getCloudFileExtension = (file: CloudFileName): string => {
  const lowerName = file.name.toLowerCase()
  const compound = COMPOUND_EXTENSIONS.find((extension) => lowerName.endsWith(extension))
  if (compound) return compound
  if (file.extension) return file.extension.toLowerCase()
  const lastDot = lowerName.lastIndexOf('.')
  return lastDot >= 0 ? lowerName.slice(lastDot) : ''
}

export const getCloudFormatLabel = (file: CloudFileName): string => {
  const extension = getCloudFileExtension(file).replace(/^\./, '')
  return extension ? extension.toUpperCase() : 'FILE'
}

export const isFilesCategoryItem = (file: PiCloudFile): boolean =>
  file.type === 'file' && file.category === 'other'

export const showsCloudCardMedia = (file: CloudCardFile): boolean => {
  if (file.type !== 'file') return false
  const mime = file.mime || ''
  const extension = getCloudFileExtension(file)
  return (
    file.category === 'photos' ||
    file.category === 'videos' ||
    mime.startsWith('image/') ||
    mime.startsWith('video/') ||
    IMAGE_EXTENSIONS.has(extension) ||
    VIDEO_EXTENSIONS.has(extension)
  )
}

export const isCloudFilePreviewable = (file: PiCloudFile): boolean => {
  if (file.type !== 'file') return false
  const mime = file.mime || ''
  const extension = getCloudFileExtension(file)
  return (
    file.category === 'photos' ||
    file.category === 'videos' ||
    file.category === 'audio' ||
    mime.startsWith('image/') ||
    mime.startsWith('video/') ||
    mime.startsWith('audio/') ||
    IMAGE_EXTENSIONS.has(extension) ||
    VIDEO_EXTENSIONS.has(extension) ||
    AUDIO_EXTENSIONS.has(extension)
  )
}

export const getCloudPreviewKind = (file: PiCloudFile): CloudPreviewKind => {
  const extension = getCloudFileExtension(file)
  if (file.category !== 'documents') return 'file'
  if (extension === '.md') return 'markdown'
  if (TEXT_DOCUMENT_EXTENSIONS.has(extension)) return 'text'
  if (extension !== '.pdf') return 'document-image'
  return 'file'
}
