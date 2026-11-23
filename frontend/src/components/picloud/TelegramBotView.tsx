import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, Save, Play, Square, RefreshCw, Settings, Users, Upload, FolderOpen, Send } from 'lucide-react'
import { toast } from 'react-hot-toast'

import Button from '../common/Button'
import Input from '../common/Input'
import Card from '../common/Card'
import api from '../../api/client'

const API_BASE = '/picloud'

interface TelegramConfig {
  token: string
  allowedUserIds: number[]
  autoOrganize: boolean
  notifyOnUpload: boolean
  maxFileSize: number
  uploadFolder: string
}

interface TelegramStatus {
  enabled?: boolean
  configured?: boolean
  connected?: boolean
  isRunning: boolean
  botUsername?: string
  lastActivity?: string
  totalUploads: number
  authorizedUsers: Array<{ id: number; username: string; firstName: string }>
  message?: string
}

const TelegramBotView = () => {
  const queryClient = useQueryClient()
  
  const [token, setToken] = useState('')
  const [allowedIds, setAllowedIds] = useState('')
  
  // Fetch current config
  const { data: config } = useQuery({
    queryKey: ['telegram-config'],
    queryFn: async () => {
      try {
        const res = await api.get(`${API_BASE}/telegram/config`)
        return res.data as TelegramConfig
      } catch {
        return null
      }
    },
  })
  
  // Fetch bot status
  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: async () => {
      try {
        const res = await api.get(`${API_BASE}/telegram/status`)
        return res.data as TelegramStatus
      } catch {
        return null
      }
    },
    refetchInterval: 5000,
  })
  
  // Update form when config loads
  useEffect(() => {
    if (config) {
      setToken(config.token || '')
      setAllowedIds(config.allowedUserIds?.join(', ') || '')
    }
  }, [config])
  
  // Save config mutation
  const saveMutation = useMutation({
    mutationFn: async () => {
      const ids = allowedIds
        .split(',')
        .map(s => s.trim())
        .filter(s => s)
        .map(s => parseInt(s, 10))
        .filter(n => !isNaN(n))
      
      const res = await api.post(`${API_BASE}/telegram/config`, {
        token,
        allowed_user_ids: ids,
        auto_organize: true,
        upload_folder: '/',
      })
      return res.data
    },
    onSuccess: () => {
      toast.success('Configuration saved')
      queryClient.invalidateQueries({ queryKey: ['telegram-config'] })
    },
    onError: () => toast.error('Failed to save'),
  })
  
  // Start bot mutation
  const startMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post(`${API_BASE}/telegram/start`)
      return res.data
    },
    onSuccess: (data: TelegramStatus) => {
      queryClient.setQueryData(['telegram-status'], data)
      if (data?.enabled) {
        toast.success('Bot started')
      } else {
        toast.error(data?.message || 'Failed to start bot')
      }
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
    },
    onError: () => toast.error('Failed to start bot'),
  })
  
  // Stop bot mutation
  const stopMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post(`${API_BASE}/telegram/stop`)
      return res.data
    },
    onSuccess: (data: TelegramStatus) => {
      queryClient.setQueryData(['telegram-status'], data)
      if (!data?.enabled) {
        toast.success('Bot stopped')
      } else {
        toast.error(data?.message || 'Failed to stop bot')
      }
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
    },
    onError: () => toast.error('Failed to stop bot'),
  })
  
  // Restart bot mutation (stop + start)
  const restartMutation = useMutation({
    mutationFn: async () => {
      // First stop
      await api.post(`${API_BASE}/telegram/stop`)
      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 500))
      // Then start
      const res = await api.post(`${API_BASE}/telegram/start`)
      return res.data
    },
    onSuccess: (data: TelegramStatus) => {
      queryClient.setQueryData(['telegram-status'], data)
      if (data?.enabled) {
        toast.success('Bot restarted')
      } else {
        toast.error(data?.message || 'Failed to restart bot')
      }
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
    },
    onError: () => toast.error('Failed to restart bot'),
  })
  
  // Test bot mutation
  const testMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post(`${API_BASE}/telegram/test`)
      return res.data
    },
    onSuccess: () => {
      toast.success('Test message sent! Check your Telegram.')
    },
    onError: (err: Error) => toast.error(err.message || 'Failed to send test'),
  })
  
  const handleSave = () => {
    if (!token.trim()) {
      toast.error('Токен бота обязателен')
      return
    }
    saveMutation.mutate()
  }
  
  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-xl">
          <Bot className="h-8 w-8 text-blue-600 dark:text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Telegram Bot</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Upload files to PiCloud via Telegram
          </p>
        </div>
      </div>
      
      {/* Status Card */}
      <Card>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4 min-w-0">
            <div
              className={`w-3 h-3 sm:w-4 sm:h-4 rounded-full flex-shrink-0 ${
                status?.isRunning
                  ? 'bg-green-500 animate-pulse'
                  : status?.enabled
                    ? 'bg-yellow-400 animate-pulse'
                    : 'bg-gray-400'
              }`}
            />
            <div className="min-w-0">
              <div className="font-semibold text-gray-900 dark:text-white text-base sm:text-lg truncate">
                {status?.isRunning
                  ? 'Bot is running'
                  : status?.enabled
                    ? 'Bot is starting'
                    : 'Bot is stopped'}
              </div>
              {status?.botUsername && (
                <a 
                  href={`https://t.me/${status.botUsername}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm sm:text-base text-blue-600 hover:underline truncate block"
                >
                  @{status.botUsername}
                  </a>
                )}
              {status?.message && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">
                  {status.message}
                </p>
              )}
            </div>
          </div>
          
          {/* Buttons in 2x2 grid on mobile, horizontal on desktop */}
          <div className="grid grid-cols-2 sm:flex sm:flex-row gap-2 w-full sm:w-auto">
            {/* Start */}
            <Button
              variant="primary"
              size="sm"
              icon={<Play className="h-4 w-4" />}
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending || stopMutation.isPending || restartMutation.isPending || !token || status?.isRunning}
              title="Start bot"
            >
              <span className="hidden sm:inline">{startMutation.isPending ? 'Starting...' : 'Start'}</span>
              <span className="sm:hidden">{startMutation.isPending ? '...' : 'Start'}</span>
            </Button>
            
            {/* Stop */}
            <Button
              variant="danger"
              size="sm"
              icon={<Square className="h-4 w-4" />}
              onClick={() => stopMutation.mutate()}
              disabled={startMutation.isPending || stopMutation.isPending || restartMutation.isPending || !status?.isRunning}
              title="Stop bot"
            >
              <span className="hidden sm:inline">{stopMutation.isPending ? 'Stopping...' : 'Stop'}</span>
              <span className="sm:hidden">{stopMutation.isPending ? '...' : 'Stop'}</span>
            </Button>
            
            {/* Restart */}
            <Button
              variant="outline"
              size="sm"
              icon={<RefreshCw className={`h-4 w-4 ${restartMutation.isPending ? 'animate-spin' : ''}`} />}
              onClick={() => restartMutation.mutate()}
              disabled={startMutation.isPending || stopMutation.isPending || restartMutation.isPending || !token}
              title="Restart bot (stop + start)"
            >
              <span className="hidden sm:inline">{restartMutation.isPending ? 'Restarting...' : 'Restart'}</span>
              <span className="sm:hidden">{restartMutation.isPending ? '...' : 'Restart'}</span>
            </Button>
            
            {/* Test */}
            <Button
              variant="outline"
              size="sm"
              icon={<Send className="h-4 w-4" />}
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending || !status?.isRunning}
              title="Send test message"
            >
              <span className="hidden sm:inline">{testMutation.isPending ? 'Sending...' : 'Test'}</span>
              <span className="sm:hidden">{testMutation.isPending ? '...' : 'Test'}</span>
            </Button>
          </div>
        </div>
        
        {/* Stats */}
        {status && (
          <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 text-center">
              <Upload className="h-5 w-5 mx-auto mb-2 text-gray-500" />
              <div className="text-2xl font-bold text-gray-900 dark:text-white">{status.totalUploads}</div>
              <div className="text-sm text-gray-500">Uploads</div>
            </div>
            <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 text-center">
              <Users className="h-5 w-5 mx-auto mb-2 text-gray-500" />
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {status.authorizedUsers?.length || 0}
              </div>
              <div className="text-sm text-gray-500">Users</div>
            </div>
            <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 text-center">
              <FolderOpen className="h-5 w-5 mx-auto mb-2 text-gray-500" />
              <div className="truncate text-lg font-bold text-gray-900 dark:text-white">All Files</div>
              <div className="text-sm text-gray-500">Folder</div>
            </div>
            <div className="bg-gray-50 dark:bg-dark-800 rounded-lg p-4 text-center">
              <Settings className="h-5 w-5 mx-auto mb-2 text-gray-500" />
              <div className="text-lg font-bold text-gray-900 dark:text-white">
                Automatic
              </div>
              <div className="text-sm text-gray-500">Categories</div>
            </div>
          </div>
        )}
      </Card>
      
      {/* Configuration */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Settings</h3>
          <Button
            icon={<Save className="h-4 w-4" />}
            onClick={handleSave}
            disabled={saveMutation.isPending}
          >
            {saveMutation.isPending ? 'Saving...' : 'Save'}
          </Button>
        </div>
        <div className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Bot Token <span className="text-red-500">*</span>
            </label>
            <Input
              type="password"
              placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Get token from{' '}
              <a 
                href="https://t.me/BotFather" 
                target="_blank" 
                rel="noopener noreferrer" 
                className="text-blue-600 hover:underline"
              >
                @BotFather
              </a>
            </p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Allowed User IDs
            </label>
            <Input
              placeholder="123456789, 987654321"
              value={allowedIds}
              onChange={(e) => setAllowedIds(e.target.value)}
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Telegram User IDs separated by commas. Leave empty to allow all.
            </p>
          </div>
          
          <div className="pt-4 border-t border-gray-200 dark:border-dark-700">
            <Button
              icon={<Save className="h-4 w-4" />}
              onClick={handleSave}
              disabled={saveMutation.isPending}
            >
              {saveMutation.isPending ? 'Saving...' : 'Save Settings'}
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Instructions */}
      <Card className="bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
        <h3 className="font-semibold text-blue-900 dark:text-blue-300 mb-3">How to use:</h3>
        <ol className="text-sm text-blue-800 dark:text-blue-400 space-y-2 list-decimal list-inside">
          <li>Create a bot via <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer" className="underline font-medium">@BotFather</a> in Telegram</li>
          <li>Copy the bot token and paste it above</li>
          <li>Click "Save Settings", then "Start"</li>
          <li>Send files to your bot in Telegram</li>
          <li>Files will automatically appear in PiCloud</li>
        </ol>
      </Card>
    </div>
  )
}

export default TelegramBotView
