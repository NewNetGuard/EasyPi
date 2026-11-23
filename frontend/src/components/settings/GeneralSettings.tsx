import { useState } from 'react'
import { Sun, Moon, Monitor, Palette, Check, RotateCcw, Sparkles } from 'lucide-react'
import Card from '../common/Card'
import Button from '../common/Button'
import { toast } from 'react-hot-toast'
import { getCsrfHeaders } from '../../utils/csrf'
import { 
  useThemeStore, 
  ACCENT_COLORS, 
  THEME_PRESETS,
  type AccentColorKey,
  type ThemePresetKey,
  type ThemeMode,
  type BorderRadius,
  type FontScale
} from '../../stores/themeStore'

// Popular timezones grouped by region
const timezones = [
  { group: 'UTC', options: [
    { value: 'UTC', label: 'UTC (Coordinated Universal Time)' },
  ]},
  { group: 'Europe', options: [
    { value: 'Europe/London', label: 'London (GMT/BST)' },
    { value: 'Europe/Paris', label: 'Paris (CET/CEST)' },
    { value: 'Europe/Berlin', label: 'Berlin (CET/CEST)' },
    { value: 'Europe/Moscow', label: 'Moscow (MSK)' },
    { value: 'Europe/Kiev', label: 'Kyiv (EET/EEST)' },
    { value: 'Europe/Istanbul', label: 'Istanbul (TRT)' },
  ]},
  { group: 'Americas', options: [
    { value: 'America/New_York', label: 'New York (EST/EDT)' },
    { value: 'America/Chicago', label: 'Chicago (CST/CDT)' },
    { value: 'America/Denver', label: 'Denver (MST/MDT)' },
    { value: 'America/Los_Angeles', label: 'Los Angeles (PST/PDT)' },
    { value: 'America/Toronto', label: 'Toronto (EST/EDT)' },
    { value: 'America/Sao_Paulo', label: 'Sao Paulo (BRT)' },
  ]},
  { group: 'Asia', options: [
    { value: 'Asia/Dubai', label: 'Dubai (GST)' },
    { value: 'Asia/Kolkata', label: 'Mumbai/Delhi (IST)' },
    { value: 'Asia/Singapore', label: 'Singapore (SGT)' },
    { value: 'Asia/Hong_Kong', label: 'Hong Kong (HKT)' },
    { value: 'Asia/Tokyo', label: 'Tokyo (JST)' },
    { value: 'Asia/Seoul', label: 'Seoul (KST)' },
    { value: 'Asia/Shanghai', label: 'Shanghai (CST)' },
  ]},
  { group: 'Pacific', options: [
    { value: 'Australia/Sydney', label: 'Sydney (AEST/AEDT)' },
    { value: 'Australia/Melbourne', label: 'Melbourne (AEST/AEDT)' },
    { value: 'Pacific/Auckland', label: 'Auckland (NZST/NZDT)' },
  ]},
]

const BORDER_RADIUS_OPTIONS: { value: BorderRadius; label: string; preview: string }[] = [
  { value: 'none', label: 'None', preview: 'rounded-none' },
  { value: 'sm', label: 'Small', preview: 'rounded-sm' },
  { value: 'md', label: 'Medium', preview: 'rounded-md' },
  { value: 'lg', label: 'Large', preview: 'rounded-lg' },
  { value: 'xl', label: 'Extra Large', preview: 'rounded-xl' },
]

const FONT_SCALE_OPTIONS: { value: FontScale; label: string; size: string }[] = [
  { value: 'small', label: 'Small', size: '14px' },
  { value: 'normal', label: 'Normal', size: '16px' },
  { value: 'large', label: 'Large', size: '18px' },
]

const GeneralSettings = () => {
  const [timezone, setTimezone] = useState(() => {
    return localStorage.getItem('timezone') || Intl.DateTimeFormat().resolvedOptions().timeZone
  })
  const [saving, setSaving] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const {
    mode,
    accentColor,
    borderRadius,
    fontScale,
    activePreset,
    setMode,
    setAccentColor,
    setBorderRadius,
    setFontScale,
    applyPreset,
    resetToDefault,
  } = useThemeStore()

  const handleThemeChange = (newMode: ThemeMode) => {
    setMode(newMode)
    toast.success(`Theme changed to ${newMode}`)
  }

  const handleAccentColorChange = (color: AccentColorKey) => {
    setAccentColor(color)
    toast.success(`Accent color changed to ${ACCENT_COLORS[color].name}`)
  }

  const handlePresetChange = (preset: ThemePresetKey) => {
    applyPreset(preset)
    toast.success(`Applied ${THEME_PRESETS[preset].name} theme`)
  }

  const handleReset = () => {
    resetToDefault()
    toast.success('Theme reset to default')
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      // Save timezone to localStorage
      localStorage.setItem('timezone', timezone)
      
      // Try to set timezone on Pi (if API available)
      try {
        const csrfHeaders = await getCsrfHeaders()
        const response = await fetch(`/api/system/timezone`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', ...csrfHeaders },
          body: JSON.stringify({ timezone })
        })
        if (response.ok) {
          toast.success('Settings saved successfully')
        } else {
          // API not available, but local save worked
          toast.success('Settings saved locally')
        }
      } catch {
        // API not available
        toast.success('Settings saved locally')
      }
    } catch {
      toast.error('Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Timezone */}
      <Card title="Timezone">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Set the timezone for your Raspberry Pi. This affects logs, scheduled tasks, and displayed times.
          </p>
          <select
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            className="w-full rounded-lg border border-gray-300 dark:border-dark-700 bg-white dark:bg-dark-800 px-4 py-2.5 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            {timezones.map((group) => (
              <optgroup key={group.group} label={group.group}>
                {group.options.map((tz) => (
                  <option key={tz.value} value={tz.value}>
                    {tz.label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>
      </Card>

      {/* Language */}
      <Card title="Language">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Select the interface language.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button
              className="flex items-center justify-between p-4 rounded-lg border-2 border-primary-500 bg-primary-50 dark:bg-primary-900/20"
            >
              <div className="flex items-center gap-3">
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-primary-100 text-xs font-bold text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">EN</span>
                <span className="font-medium text-gray-900 dark:text-white">English</span>
              </div>
              <span className="text-primary-600 dark:text-primary-400 text-sm font-medium">Active</span>
            </button>
            
            <button
              disabled
              className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800 opacity-60 cursor-not-allowed"
            >
              <div className="flex items-center gap-3">
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-gray-200 text-xs font-bold text-gray-700 dark:bg-dark-700 dark:text-gray-300">DE</span>
                <span className="font-medium text-gray-900 dark:text-white">Deutsch</span>
              </div>
              <span className="text-gray-500 text-xs font-medium">Coming soon</span>
            </button>
            
            <button
              disabled
              className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-800 opacity-60 cursor-not-allowed"
            >
              <div className="flex items-center gap-3">
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-gray-200 text-xs font-bold text-gray-700 dark:bg-dark-700 dark:text-gray-300">RU</span>
                <span className="font-medium text-gray-900 dark:text-white">Russian</span>
              </div>
              <span className="text-gray-500 text-xs font-medium">Coming soon</span>
            </button>
          </div>
        </div>
      </Card>

      {/* Theme Mode */}
      <Card title="Theme Mode">
        <div className="space-y-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Choose your preferred color scheme.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button
              onClick={() => handleThemeChange('light')}
              className={`flex items-center gap-3 p-4 rounded-lg border-2 transition-all ${
                mode === 'light'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-dark-700 hover:border-gray-300 dark:hover:border-dark-600'
              }`}
            >
              <div className="p-2 rounded-lg bg-yellow-100 dark:bg-yellow-900/30">
                <Sun className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
              </div>
              <div className="text-left">
                <div className="font-medium text-gray-900 dark:text-white">Light</div>
                <div className="text-xs text-gray-500">Bright and clean</div>
              </div>
            </button>
            
            <button
              onClick={() => handleThemeChange('dark')}
              className={`flex items-center gap-3 p-4 rounded-lg border-2 transition-all ${
                mode === 'dark'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-dark-700 hover:border-gray-300 dark:hover:border-dark-600'
              }`}
            >
              <div className="p-2 rounded-lg bg-indigo-100 dark:bg-indigo-900/30">
                <Moon className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
              </div>
              <div className="text-left">
                <div className="font-medium text-gray-900 dark:text-white">Dark</div>
                <div className="text-xs text-gray-500">Easy on the eyes</div>
              </div>
            </button>
            
            <button
              onClick={() => handleThemeChange('auto')}
              className={`flex items-center gap-3 p-4 rounded-lg border-2 transition-all ${
                mode === 'auto'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-dark-700 hover:border-gray-300 dark:hover:border-dark-600'
              }`}
            >
              <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
                <Monitor className="h-5 w-5 text-gray-600 dark:text-gray-400" />
              </div>
              <div className="text-left">
                <div className="font-medium text-gray-900 dark:text-white">System</div>
                <div className="text-xs text-gray-500">Match device theme</div>
              </div>
            </button>
          </div>
        </div>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button 
          variant="primary" 
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>
    </div>
  )
}

export default GeneralSettings
