import { useState, useEffect } from 'react'
import { X, Eye, EyeOff } from 'lucide-react'
import { Camera } from '../../types/camera'
import Button from '../common/Button'

interface EditCameraModalProps {
  camera: Camera | null
  isOpen: boolean
  onClose: () => void
  onSubmit: (id: string, payload: Partial<Camera>) => void
  isLoading?: boolean
}

const EditCameraModal = ({ camera, isOpen, onClose, onSubmit, isLoading }: EditCameraModalProps) => {
  const [formData, setFormData] = useState({
    name: '',
    ip: '',
    port: 554,
    username: '',
    password: '',
    rtspPath: '',
    location: '',
    ptzUsername: '',
    ptzPassword: ''
  })
  const [showPassword, setShowPassword] = useState(false)
  const [showPtzAdvanced, setShowPtzAdvanced] = useState(false)

  // Secrets are never read back from the backend. Empty password fields mean
  // "keep the currently stored secret" and are omitted from the update.
  useEffect(() => {
    if (camera && isOpen) {
      setFormData({
        name: camera.name,
        ip: camera.ip,
        port: camera.port,
        username: camera.username || '',
        password: '',
        rtspPath: camera.rtspPath,
        location: camera.location || '',
        ptzUsername: camera.ptzUsername || '',
        ptzPassword: ''
      })
    }
  }, [camera, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!camera) return

    // Build payload - only include password if it was changed
    const payload: any = {
      name: formData.name,
      ip: formData.ip,
      port: formData.port,
      username: formData.username,
      rtspPath: formData.rtspPath,
      location: formData.location
    }

    // Only include password if user entered a new one
    if (formData.password) {
      payload.password = formData.password
    }

    // PTZ/ONVIF credentials: send username when it changed, password only if entered
    if (formData.ptzUsername !== (camera.ptzUsername || '')) {
      payload.ptzUsername = formData.ptzUsername
    }
    if (formData.ptzPassword) {
      payload.ptzPassword = formData.ptzPassword
    }

    onSubmit(camera.id, payload)
  }

  const handleChange = (field: keyof typeof formData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  if (!isOpen || !camera) return null

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-50 bg-black/50" onClick={onClose} />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl bg-white shadow-2xl dark:bg-dark-900">
          {/* Header */}
          <div className="flex flex-shrink-0 items-center justify-between border-b border-gray-200 px-6 py-4 dark:border-dark-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Edit Camera</h2>
            <button
              onClick={onClose}
              className="rounded-lg p-2 text-gray-500 transition hover:bg-gray-100 dark:hover:bg-dark-800"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col">
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-6">
              {/* Name */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Camera Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => handleChange('name', e.target.value)}
                  placeholder="e.g. Front Door, Backyard"
                  required
                  className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
              </div>

              {/* IP + Port */}
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                    IP Address <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={formData.ip}
                    onChange={(e) => handleChange('ip', e.target.value)}
                    placeholder="192.168.1.100"
                    required
                    className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                    Port
                  </label>
                  <input
                    type="number"
                    value={formData.port}
                    onChange={(e) => handleChange('port', parseInt(e.target.value) || 554)}
                    className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                  />
                </div>
              </div>

              {/* Credentials */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                    Username <span className="text-gray-400 font-normal">(if required)</span>
                  </label>
                  <input
                    type="text"
                    value={formData.username}
                    onChange={(e) => handleChange('username', e.target.value)}
                    placeholder="admin"
                    className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={formData.password}
                      onChange={(e) => handleChange('password', e.target.value)}
                      placeholder="Leave empty to keep current"
                      maxLength={127}
                      autoComplete="new-password"
                      className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 pr-10 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 mt-0.5 rounded p-1 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </div>

              <p className="-mt-2 text-xs text-gray-500">
                The camera's own login (for many cameras: user <span className="font-medium">root</span> and the
                password set on the camera). Used both for the video and for pan / tilt control.
              </p>

              {/* RTSP Path */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                  RTSP Path <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.rtspPath}
                  onChange={(e) => handleChange('rtspPath', e.target.value)}
                  placeholder="/stream1"
                  required
                  className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
                {formData.rtspPath && (
                  <p className="mt-1 text-xs text-gray-500">
                    URL: rtsp://{formData.username}:****@{formData.ip}:{formData.port}{formData.rtspPath}
                  </p>
                )}
              </div>

              {/* Advanced: separate PTZ login (only when control uses a different login) */}
              <div className="rounded-lg border border-gray-200 dark:border-dark-700">
                <button
                  type="button"
                  onClick={() => setShowPtzAdvanced((v) => !v)}
                  className="flex w-full items-center justify-between px-3 py-2 text-left text-sm font-semibold text-gray-700 dark:text-gray-300"
                >
                  <span>
                    Separate control (PTZ) login <span className="text-gray-400 font-normal">(advanced — usually not needed)</span>
                  </span>
                  <span className="flex items-center gap-2">
                    {camera.hasPtzAuth && <span className="text-xs font-medium text-amber-600 dark:text-amber-400">in use</span>}
                    <span className="text-gray-400">{showPtzAdvanced ? '−' : '+'}</span>
                  </span>
                </button>
                {showPtzAdvanced && (
                  <div className="border-t border-gray-200 p-3 dark:border-dark-700">
                    <p className="mb-2 text-xs text-gray-500">
                      Leave empty — pan / tilt uses the camera login above. Only set this if your camera
                      uses a <span className="font-medium">different</span> login for ONVIF / control than for the video stream.
                    </p>
                    <div className="grid grid-cols-2 gap-4">
                      <input
                        type="text"
                        value={formData.ptzUsername}
                        onChange={(e) => handleChange('ptzUsername', e.target.value)}
                        placeholder="control username"
                        autoComplete="off"
                        className="w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                      />
                      <input
                        type="password"
                        value={formData.ptzPassword}
                        onChange={(e) => handleChange('ptzPassword', e.target.value)}
                        placeholder={camera.hasPtzAuth ? 'Leave empty to keep' : 'control password'}
                        maxLength={127}
                        autoComplete="new-password"
                        className="w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Location (optional) */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Location <span className="text-gray-400 font-normal">(optional)</span>
                </label>
                <input
                  type="text"
                  value={formData.location}
                  onChange={(e) => handleChange('location', e.target.value)}
                  placeholder="e.g. Front yard, Garage"
                  className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
              </div>
            </div>

            {/* Actions — fixed footer so Save is always reachable */}
            <div className="flex flex-shrink-0 justify-end gap-3 border-t border-gray-200 px-6 py-4 dark:border-dark-700">
              <Button variant="secondary" onClick={onClose} disabled={isLoading}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={isLoading}>
                {isLoading ? 'Saving...' : 'Save Changes'}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </>
  )
}

export default EditCameraModal
