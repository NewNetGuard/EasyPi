import { useState, useEffect, useRef } from 'react'
import { X, Eye, EyeOff, Search, Loader2, CheckCircle, AlertCircle, Info, Radar } from 'lucide-react'
import { AddCameraPayload } from '../../types/camera'
import Button from '../common/Button'
import api from '../../api/client'
import { discoverCameras, DiscoveredCamera } from '../../api/ptz'

interface CameraBrandInfo {
  name: string
  default_port: number
  default_username: string
  rtsp_paths: string[]
  notes?: string
}

interface AddCameraModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (payload: AddCameraPayload) => void
  isLoading?: boolean
  submitError?: string | null
}

type CameraFormErrors = Partial<Record<'name' | 'ip' | 'password' | 'rtspPath', string>>

const AddCameraModal = ({ isOpen, onClose, onSubmit, isLoading, submitError }: AddCameraModalProps) => {
  const [formData, setFormData] = useState<AddCameraPayload>({
    name: '',
    ip: '',
    port: 554,
    username: 'admin',
    password: '',
    rtspPath: '',
    brand: '',
    model: '',
    location: ''
  })
  const [showPassword, setShowPassword] = useState(false)
  const [detecting, setDetecting] = useState(false)
  const [detectResult, setDetectResult] = useState<{ success: boolean; message: string } | null>(null)
  const [rtspPathManuallyEdited, setRtspPathManuallyEdited] = useState(false)
  const [brands, setBrands] = useState<Record<string, CameraBrandInfo>>({})
  const [selectedBrandKey, setSelectedBrandKey] = useState<string>('')
  const [discovering, setDiscovering] = useState(false)
  const [discovered, setDiscovered] = useState<DiscoveredCamera[]>([])
  const [discoverMsg, setDiscoverMsg] = useState<string | null>(null)
  const [formErrors, setFormErrors] = useState<CameraFormErrors>({})
  const passwordInputRef = useRef<HTMLInputElement>(null)
  const rtspPathInputRef = useRef<HTMLInputElement>(null)

  const handleDiscover = async () => {
    setDiscovering(true)
    setDiscoverMsg(null)
    setDiscovered([])
    try {
      const target = (formData.ip || '').trim()
      const { devices } = await discoverCameras(target || undefined)
      setDiscovered(devices)
      if (!devices.length) {
        setDiscoverMsg(
          target
            ? `No ONVIF device answered at ${target}. Check the IP and that ONVIF is enabled on the camera.`
            : 'No cameras answered on this segment. If the camera is on another subnet, type its IP in the field below, then Scan again to probe it directly.'
        )
      }
    } catch (error: any) {
      setDiscoverMsg(error?.response?.data?.detail || 'Discovery failed')
    } finally {
      setDiscovering(false)
    }
  }

  const pickDiscovered = (d: DiscoveredCamera) => {
    setFormData((prev) => ({
      ...prev,
      ip: d.ip,
      name: prev.name || d.name || d.hardware || `Camera ${d.ip}`,
      onvifPort: d.onvif_port,
    }))
    setDiscovered([])
    setDiscoverMsg(`Selected ${d.ip} (ONVIF port ${d.onvif_port}). Now enter the camera login below.`)
  }

  // Load camera brands on mount
  useEffect(() => {
    const loadBrands = async () => {
      try {
        const { data } = await api.get('/cameras/brands')
        setBrands(data.brands || {})
      } catch (error) {
        console.error('Failed to load camera brands:', error)
      }
    }
    if (isOpen) {
      loadBrands()
    }
  }, [isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: CameraFormErrors = {}
    if (!formData.name.trim()) errors.name = 'Enter a name for the camera.'
    if (!formData.ip.trim()) errors.ip = 'Enter the camera IP address.'
    if (!formData.password) {
      errors.password = 'Enter the camera password. If you forgot it, reset it on the camera first.'
    }
    if (!formData.rtspPath.trim()) {
      errors.rtspPath = 'Detect the stream settings or enter the RTSP path manually.'
    }

    setFormErrors(errors)
    if (Object.keys(errors).length > 0) {
      if (errors.password) passwordInputRef.current?.focus()
      else if (errors.rtspPath) rtspPathInputRef.current?.focus()
      return
    }

    onSubmit({
      ...formData,
      name: formData.name.trim(),
      ip: formData.ip.trim(),
      rtspPath: formData.rtspPath.trim(),
    })
  }

  const handleChange = (field: keyof AddCameraPayload, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    if (field in formErrors) {
      setFormErrors((prev) => ({ ...prev, [field]: undefined }))
    }
    // Clear detect result when user changes connection settings
    if (['ip', 'port', 'username', 'password'].includes(field)) {
      setDetectResult(null)
    }
  }

  const handleBrandChange = (brandKey: string) => {
    setSelectedBrandKey(brandKey)
    if (brandKey && brands[brandKey]) {
      const brand = brands[brandKey]
      setFormData((prev) => ({
        ...prev,
        brand: brand.name,
        port: brand.default_port,
        username: brand.default_username,
        // Suggest first RTSP path but don't lock it
        rtspPath: prev.rtspPath || ''
      }))
      setDetectResult(null)
    }
  }

  const handleAutoDetect = async () => {
    const errors: CameraFormErrors = {}
    if (!formData.ip.trim()) errors.ip = 'Enter the camera IP address first.'
    if (!formData.password) {
      errors.password = 'Enter the camera password. If you forgot it, reset it on the camera first.'
    }
    if (Object.keys(errors).length > 0) {
      setFormErrors((prev) => ({ ...prev, ...errors }))
      setDetectResult({ success: false, message: errors.password || errors.ip || 'Complete the camera login.' })
      if (errors.password) passwordInputRef.current?.focus()
      return
    }

    setDetecting(true)
    setDetectResult(null)

    try {
      const { data } = await api.post('/cameras/detect', {
        ip: formData.ip,
        port: formData.port,
        username: formData.username,
        password: formData.password,
        brand: selectedBrandKey || undefined,
        preferredPath: rtspPathManuallyEdited
          ? formData.rtspPath.trim() || undefined
          : undefined
      })

      if (data.success) {
        setRtspPathManuallyEdited(false)
        setFormData((prev) => ({
          ...prev,
          rtspPath: data.rtspPath,
          port: data.port || prev.port,
          brand: data.brand || prev.brand
        }))
        setDetectResult({ 
          success: true, 
          message: `${data.message}${data.attempts ? ` (${data.attempts} attempts)` : ''}`
        })
      } else {
        setDetectResult({ 
          success: false, 
          message: data.error || 'Could not detect camera'
        })
      }
    } catch (error: any) {
      setDetectResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to connect to camera'
      })
    } finally {
      setDetecting(false)
    }
  }

  if (!isOpen) return null

  const canDetect = !!formData.ip
  const selectedBrand = selectedBrandKey ? brands[selectedBrandKey] : null

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-50 bg-black/50" onClick={onClose} />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl bg-white shadow-2xl dark:bg-dark-900">
          {/* Header */}
          <div className="flex flex-shrink-0 items-center justify-between border-b border-gray-200 px-6 py-4 dark:border-dark-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Add IP Camera</h2>
            <button
              onClick={onClose}
              className="rounded-lg p-2 text-gray-500 transition hover:bg-gray-100 dark:hover:bg-dark-800"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} noValidate className="flex min-h-0 flex-1 flex-col">
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 py-6">
              {/* Auto-discovery: find ONVIF cameras on the network (no IP typing) */}
              <div className="rounded-lg border border-primary-200 bg-primary-50/50 p-3 dark:border-primary-900/40 dark:bg-primary-900/10">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm">
                    <span className="font-semibold text-gray-800 dark:text-gray-200">Find cameras on the network</span>
                    <p className="text-xs text-gray-500">ONVIF cameras announce their own address and port. On another subnet? Type the IP below, then Scan to probe it directly.</p>
                  </div>
                  <button
                    type="button"
                    onClick={handleDiscover}
                    disabled={discovering}
                    className="flex flex-shrink-0 items-center gap-2 rounded-lg bg-primary-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-primary-700 disabled:opacity-50"
                  >
                    {discovering ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
                    {discovering ? 'Searching…' : 'Scan network'}
                  </button>
                </div>

                {discovered.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {discovered.map((d) => (
                      <button
                        key={`${d.ip}:${d.onvif_port}`}
                        type="button"
                        onClick={() => pickDiscovered(d)}
                        className="flex w-full items-center justify-between rounded-md border border-gray-200 bg-white px-3 py-2 text-left text-sm transition hover:border-primary-400 hover:bg-primary-50 dark:border-dark-700 dark:bg-dark-800 dark:hover:border-primary-500"
                      >
                        <span className="truncate">
                          <span className="font-medium text-gray-800 dark:text-gray-100">{d.name || d.hardware || 'ONVIF camera'}</span>
                          <span className="ml-2 text-gray-500">{d.ip}:{d.onvif_port}</span>
                        </span>
                        <span className="ml-2 flex-shrink-0 text-xs font-medium text-primary-600 dark:text-primary-400">Use</span>
                      </button>
                    ))}
                  </div>
                )}
                {discoverMsg && <p className="mt-2 text-xs text-gray-500">{discoverMsg}</p>}
              </div>

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
                  aria-invalid={Boolean(formErrors.name)}
                  aria-describedby={formErrors.name ? 'camera-name-error' : undefined}
                  className={`mt-1 w-full rounded-lg border px-4 py-2 focus:border-primary-500 focus:outline-none dark:bg-dark-800 dark:text-white ${formErrors.name ? 'border-red-500 dark:border-red-500' : 'border-gray-300 dark:border-dark-700'}`}
                />
                {formErrors.name && <p id="camera-name-error" role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">{formErrors.name}</p>}
              </div>

              {/* Brand Selection */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                  Camera Brand <span className="text-gray-400 font-normal">(helps with auto-detect)</span>
                </label>
                <select
                  value={selectedBrandKey}
                  onChange={(e) => handleBrandChange(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                >
                  <option value="">-- Select brand (optional) --</option>
                  {Object.entries(brands).map(([key, brand]) => (
                    <option key={key} value={key}>
                      {brand.name}
                    </option>
                  ))}
                </select>
                {selectedBrand?.notes && (
                  <div className="mt-1 flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                    <Info className="h-3 w-3" />
                    {selectedBrand.notes}
                  </div>
                )}
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
                    aria-invalid={Boolean(formErrors.ip)}
                    aria-describedby={formErrors.ip ? 'camera-ip-error' : undefined}
                    className={`mt-1 w-full rounded-lg border px-4 py-2 focus:border-primary-500 focus:outline-none dark:bg-dark-800 dark:text-white ${formErrors.ip ? 'border-red-500 dark:border-red-500' : 'border-gray-300 dark:border-dark-700'}`}
                  />
                  {formErrors.ip && <p id="camera-ip-error" role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">{formErrors.ip}</p>}
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
                    Password <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      ref={passwordInputRef}
                      type={showPassword ? 'text' : 'password'}
                      value={formData.password}
                      onChange={(e) => handleChange('password', e.target.value)}
                      required
                      maxLength={127}
                      autoComplete="new-password"
                      aria-invalid={Boolean(formErrors.password)}
                      aria-describedby="camera-password-help"
                      className={`mt-1 w-full rounded-lg border px-4 py-2 pr-10 focus:border-primary-500 focus:outline-none dark:bg-dark-800 dark:text-white ${formErrors.password ? 'border-red-500 dark:border-red-500' : 'border-gray-300 dark:border-dark-700'}`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-gray-500 hover:text-gray-700"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <p
                    id="camera-password-help"
                    role={formErrors.password ? 'alert' : undefined}
                    className={`mt-1 text-xs ${formErrors.password ? 'text-red-600 dark:text-red-400' : 'text-gray-500'}`}
                  >
                    {formErrors.password || 'Required. Enter the password configured on the camera.'}
                  </p>
                </div>
              </div>

              <p className="-mt-2 text-xs text-gray-500">
                This is the camera's own login (for many cameras: user <span className="font-medium">root</span> and the
                password you set on the camera). It's used both for the video and for pan / tilt control.
              </p>

              {/* Auto-detect button */}
              <div>
                <button
                  type="button"
                  onClick={handleAutoDetect}
                  disabled={!canDetect || detecting}
                  className="flex w-full items-center justify-center gap-2 rounded-lg border-2 border-dashed border-gray-300 px-4 py-3 text-sm font-medium text-gray-600 transition hover:border-primary-500 hover:text-primary-600 disabled:cursor-not-allowed disabled:opacity-50 dark:border-dark-600 dark:text-gray-400 dark:hover:border-primary-500 dark:hover:text-primary-400"
                >
                  {detecting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Searching for camera stream...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4" />
                      Auto-detect Stream Settings
                    </>
                  )}
                </button>

                {/* Detection result */}
                {detectResult && (
                  <div
                    className={`mt-2 flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                      detectResult.success
                        ? 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                        : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                    }`}
                  >
                    {detectResult.success ? (
                      <CheckCircle className="h-4 w-4 flex-shrink-0" />
                    ) : (
                      <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    )}
                    {detectResult.message}
                  </div>
                )}
              </div>

              {/* RTSP Path - shows after detection or manual entry */}
              <div>
                <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300">
                  RTSP Path {!formData.rtspPath && <span className="text-gray-400 font-normal">(use auto-detect or enter manually)</span>}
                </label>
                <input
                  ref={rtspPathInputRef}
                  type="text"
                  value={formData.rtspPath}
                  onChange={(e) => {
                    setRtspPathManuallyEdited(true)
                    handleChange('rtspPath', e.target.value)
                  }}
                  placeholder="/stream1"
                  aria-invalid={Boolean(formErrors.rtspPath)}
                  aria-describedby={formErrors.rtspPath ? 'camera-rtsp-error' : undefined}
                  className={`mt-1 w-full rounded-lg border px-4 py-2 focus:border-primary-500 focus:outline-none dark:bg-dark-800 dark:text-white ${formErrors.rtspPath ? 'border-red-500 dark:border-red-500' : 'border-gray-300 dark:border-dark-700'}`}
                />
                {formErrors.rtspPath && <p id="camera-rtsp-error" role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">{formErrors.rtspPath}</p>}
                {formData.rtspPath && (
                  <p className="mt-1 text-xs text-gray-500">
                    URL: rtsp://{formData.username}:****@{formData.ip}:{formData.port}{formData.rtspPath}
                  </p>
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
              {submitError && (
                <div role="alert" className="mr-auto flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{submitError}</span>
                </div>
              )}
              <Button variant="secondary" onClick={onClose} disabled={isLoading}>
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                disabled={isLoading}
              >
                {isLoading ? 'Adding...' : 'Add Camera'}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </>
  )
}

export default AddCameraModal
