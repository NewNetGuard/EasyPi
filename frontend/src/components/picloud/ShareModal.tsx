import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Copy, QrCode, Link2, Lock, Clock } from 'lucide-react'
import { toast } from 'react-hot-toast'
import QRCode from 'qrcode'
import { copyToClipboard } from '../../utils/clipboard'

import Modal from '../common/Modal'
import Button from '../common/Button'
import Input from '../common/Input'
import { createShareLink } from '../../api/cloud'
import type { PiCloudFile } from '../../types/cloud'

interface ShareModalProps {
  file: PiCloudFile | null
  isOpen: boolean
  onClose: () => void
}

const ShareModal = ({ file, isOpen, onClose }: ShareModalProps) => {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState('')
  const [expiresIn, setExpiresIn] = useState(24) // hours
  const [shareUrl, setShareUrl] = useState('')
  const [qrCodeUrl, setQrCodeUrl] = useState('')
  
  const shareMutation = useMutation({
    mutationFn: () =>
      createShareLink(file!.id, {
        password: password || undefined,
        hours: expiresIn,
      }),
    onSuccess: async (data) => {
      const fullUrl = `${window.location.origin}/share/${data.id}`
      setShareUrl(fullUrl)
      
      const qr = await QRCode.toDataURL(fullUrl, {
        width: 256,
        margin: 2,
      })
      setQrCodeUrl(qr)
      
      toast.success('Share link created')
      queryClient.invalidateQueries({ queryKey: ['picloud-shares'] })
    },
    onError: () => toast.error('Failed to create share link'),
  })
  
  const handleCreate = () => {
    if (!file) return
    shareMutation.mutate()
  }
  
  const handleCopy = async (text: string) => {
    const success = await copyToClipboard(text)
    if (success) {
      toast.success('Copied to clipboard')
    } else {
      toast.error('Failed to copy')
    }
  }
  
  const handleReset = () => {
    setPassword('')
    setExpiresIn(24)
    setShareUrl('')
    setQrCodeUrl('')
  }
  
  const handleClose = () => {
    handleReset()
    onClose()
  }
  
  
  if (!file) return null
  
  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Share File</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{file.name}</p>
        </div>
        <button
          onClick={handleClose}
          className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
        >
          <X className="h-6 w-6" />
        </button>
      </div>
      
      {!shareUrl ? (
        // Create share form
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              <Lock className="inline h-4 w-4 mr-1" />
              Password (optional)
            </label>
            <Input
              type="password"
              placeholder="Leave empty for no password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Protect link with a password
            </p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              <Clock className="inline h-4 w-4 mr-1" />
              Expires in (hours)
            </label>
            <Input
              type="number"
              min={1}
              max={8760}
              value={expiresIn}
              onChange={(e) => setExpiresIn(Number(e.target.value))}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Link will expire after this time (max 365 days)
            </p>
          </div>
          
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button
              icon={<Link2 className="h-4 w-4" />}
              onClick={handleCreate}
              disabled={shareMutation.isPending}
            >
              {shareMutation.isPending ? 'Creating...' : 'Create Link'}
            </Button>
          </div>
        </div>
      ) : (
        // Share link created
        <div className="space-y-6">
          {/* Share URL */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Share Link
            </label>
            <div className="flex gap-2">
              <Input value={shareUrl} readOnly className="flex-1" />
              <Button
                variant="outline"
                icon={<Copy className="h-4 w-4" />}
                onClick={() => handleCopy(shareUrl)}
              >
                Copy
              </Button>
            </div>
          </div>
          
          {/* QR Code */}
          {qrCodeUrl && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                <QrCode className="inline h-4 w-4 mr-1" />
                QR Code
              </label>
              <div className="flex justify-center p-4 bg-white rounded-lg border border-gray-200">
                <img src={qrCodeUrl} alt="QR Code" className="w-64 h-64" />
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 text-center">
                Scan to open link
              </p>
            </div>
          )}
          
          
          
          {/* Share info */}
          <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600 dark:text-gray-400">Protected:</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {password ? 'Yes' : 'No'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600 dark:text-gray-400">Expires in:</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {expiresIn} hours
              </span>
            </div>
          </div>
          
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleReset}>
              Create Another
            </Button>
            <Button onClick={handleClose}>Done</Button>
          </div>
        </div>
      )}
    </Modal>
  )
}

export default ShareModal
