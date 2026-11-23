import api from './client'
import { getApiBaseUrl } from '../utils/apiBase'

const BASE_PATH = '/files'

export interface FileSearchResult {
  name: string
  path: string
  type: 'file' | 'directory'
  parent: string
  size?: number
  size_formatted?: string
  modified?: string
}

export const listDirectory = async (path: string) => {
  const response = await api.get(`${BASE_PATH}/list`, { params: { path } })
  return response.data
}

export const searchFiles = async (
  query: string,
  path: string = '/home',
  limit: number = 50
): Promise<FileSearchResult[]> => {
  const response = await api.get(`${BASE_PATH}/search`, {
    params: { query, path, limit }
  })
  return response.data
}

export const readFile = async (path: string) => {
  const response = await api.get(`${BASE_PATH}/read`, { params: { path } })
  return response.data
}

export const writeFile = async (path: string, content: string) => {
  const response = await api.post(`${BASE_PATH}/write`, { path, content })
  return response.data
}

export const createFile = async (path: string) => {
  const response = await api.post(`${BASE_PATH}/create-file`, { path })
  return response.data
}

export const createFolder = async (path: string) => {
  const response = await api.post(`${BASE_PATH}/create-folder`, { path })
  return response.data
}

export const deleteFile = async (path: string) => {
  const response = await api.delete(`${BASE_PATH}/delete`, { data: { path } })
  return response.data
}

export const uploadFile = async (file: File, path: string) => {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('path', path)
  
  const response = await api.post(`${BASE_PATH}/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return response.data
}

export const getFileType = async (path: string) => {
  const response = await api.get(`${BASE_PATH}/type`, { params: { path } })
  return response.data
}

export const getImageUrl = (path: string) => {
  const baseURL = getApiBaseUrl()
  return `${baseURL}/api/v1/files/image?path=${encodeURIComponent(path)}`
}
