import { useState, useEffect, useCallback, useRef } from 'react'
import api from '../api/client'
import { encodeFileIdPath } from '../api/cloud'
import { getApiV1BaseUrl } from '../utils/apiBase'

// Cache for blob URLs to avoid re-fetching same files
const blobCache = new Map<string, { url: string; timestamp: number }>()
const CACHE_TTL = 5 * 60 * 1000 // 5 minutes

// Cleanup old cache entries periodically
const cleanupCache = () => {
  const now = Date.now()
  for (const [key, value] of blobCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      URL.revokeObjectURL(value.url)
      blobCache.delete(key)
    }
  }
}

// Run cleanup every minute
setInterval(cleanupCache, 60 * 1000)

/**
 * Hook to fetch file content with authentication and return a blob URL
 * Useful for images, videos, and other media that need auth headers
 */
export const useAuthenticatedUrl = (
  fileId: string | null,
  type: 'download' | 'thumbnail' = 'download'
) => {
  const [url, setUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const currentFileId = useRef<string | null>(null)

  useEffect(() => {
    if (!fileId) {
      setUrl(null)
      setLoading(false)
      setError(null)
      return
    }

    // Don't refetch if same file
    if (currentFileId.current === fileId) {
      return
    }

    currentFileId.current = fileId
    const cacheKey = `${type}:${fileId}`

    // Check cache first
    const cached = blobCache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      setUrl(cached.url)
      setLoading(false)
      setError(null)
      return
    }

    const fetchUrl = async () => {
      setLoading(true)
      setError(null)

      try {
        const encodedFileId = encodeFileIdPath(fileId)
        const endpoint = type === 'thumbnail' 
          ? `/picloud/thumbnail/${encodedFileId}`
          : `/picloud/file/${encodedFileId}/download`

        const response = await api.get(endpoint, {
          responseType: 'blob',
        })

        const blobUrl = URL.createObjectURL(response.data)
        
        // Cache the blob URL
        blobCache.set(cacheKey, { url: blobUrl, timestamp: Date.now() })
        
        setUrl(blobUrl)
      } catch (err) {
        console.error(`Failed to fetch ${type}:`, err)
        setError(err instanceof Error ? err : new Error('Failed to fetch file'))
        setUrl(null)
      } finally {
        setLoading(false)
      }
    }

    fetchUrl()

    // Cleanup function - note: we don't revoke URL here because it might be cached
    return () => {
      currentFileId.current = null
    }
  }, [fileId, type])

  return { url, loading, error }
}

/**
 * Hook to fetch thumbnail with authentication
 */
export const useAuthenticatedThumbnail = (fileId: string | null) => {
  return useAuthenticatedUrl(fileId, 'thumbnail')
}

/**
 * Fetch file with authentication and return blob URL (non-hook version)
 * For use in event handlers
 */
export const fetchAuthenticatedFileUrl = async (
  fileId: string,
  type: 'download' | 'thumbnail' = 'download'
): Promise<string> => {
  const cacheKey = `${type}:${fileId}`
  
  // Check cache first
  const cached = blobCache.get(cacheKey)
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.url
  }

  const encodedFileId = encodeFileIdPath(fileId)
  const endpoint = type === 'thumbnail'
    ? `/picloud/thumbnail/${encodedFileId}`
    : `/picloud/file/${encodedFileId}/download`

  const response = await api.get(endpoint, {
    responseType: 'blob',
  })

  const blobUrl = URL.createObjectURL(response.data)
  
  // Cache the blob URL
  blobCache.set(cacheKey, { url: blobUrl, timestamp: Date.now() })
  
  return blobUrl
}

/**
 * Revoke a blob URL and remove from cache
 */
export const revokeAuthenticatedUrl = (blobUrl: string) => {
  URL.revokeObjectURL(blobUrl)
  
  // Remove from cache if present
  for (const [key, value] of blobCache.entries()) {
    if (value.url === blobUrl) {
      blobCache.delete(key)
      break
    }
  }
}

/**
 * Clear all cached blob URLs
 */
export const clearUrlCache = () => {
  for (const value of blobCache.values()) {
    URL.revokeObjectURL(value.url)
  }
  blobCache.clear()
}
