import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// Available accent colors
export const ACCENT_COLORS = {
  sky: {
    name: 'Sky Blue',
    value: '#0ea5e9',
    rgb: '14 165 233',
    shades: {
      50: '#f0f9ff',
      100: '#e0f2fe',
      200: '#bae6fd',
      300: '#7dd3fc',
      400: '#38bdf8',
      500: '#0ea5e9',
      600: '#0284c7',
      700: '#0369a1',
      800: '#075985',
      900: '#0c4a6e',
    }
  },
  violet: {
    name: 'Violet',
    value: '#8b5cf6',
    rgb: '139 92 246',
    shades: {
      50: '#f5f3ff',
      100: '#ede9fe',
      200: '#ddd6fe',
      300: '#c4b5fd',
      400: '#a78bfa',
      500: '#8b5cf6',
      600: '#7c3aed',
      700: '#6d28d9',
      800: '#5b21b6',
      900: '#4c1d95',
    }
  },
  emerald: {
    name: 'Emerald',
    value: '#10b981',
    rgb: '16 185 129',
    shades: {
      50: '#ecfdf5',
      100: '#d1fae5',
      200: '#a7f3d0',
      300: '#6ee7b7',
      400: '#34d399',
      500: '#10b981',
      600: '#059669',
      700: '#047857',
      800: '#065f46',
      900: '#064e3b',
    }
  },
  rose: {
    name: 'Rose',
    value: '#f43f5e',
    rgb: '244 63 94',
    shades: {
      50: '#fff1f2',
      100: '#ffe4e6',
      200: '#fecdd3',
      300: '#fda4af',
      400: '#fb7185',
      500: '#f43f5e',
      600: '#e11d48',
      700: '#be123c',
      800: '#9f1239',
      900: '#881337',
    }
  },
  amber: {
    name: 'Amber',
    value: '#f59e0b',
    rgb: '245 158 11',
    shades: {
      50: '#fffbeb',
      100: '#fef3c7',
      200: '#fde68a',
      300: '#fcd34d',
      400: '#fbbf24',
      500: '#f59e0b',
      600: '#d97706',
      700: '#b45309',
      800: '#92400e',
      900: '#78350f',
    }
  },
  cyan: {
    name: 'Cyan',
    value: '#06b6d4',
    rgb: '6 182 212',
    shades: {
      50: '#ecfeff',
      100: '#cffafe',
      200: '#a5f3fc',
      300: '#67e8f9',
      400: '#22d3ee',
      500: '#06b6d4',
      600: '#0891b2',
      700: '#0e7490',
      800: '#155e75',
      900: '#164e63',
    }
  },
  indigo: {
    name: 'Indigo',
    value: '#6366f1',
    rgb: '99 102 241',
    shades: {
      50: '#eef2ff',
      100: '#e0e7ff',
      200: '#c7d2fe',
      300: '#a5b4fc',
      400: '#818cf8',
      500: '#6366f1',
      600: '#4f46e5',
      700: '#4338ca',
      800: '#3730a3',
      900: '#312e81',
    }
  },
  pink: {
    name: 'Pink',
    value: '#ec4899',
    rgb: '236 72 153',
    shades: {
      50: '#fdf2f8',
      100: '#fce7f3',
      200: '#fbcfe8',
      300: '#f9a8d4',
      400: '#f472b6',
      500: '#ec4899',
      600: '#db2777',
      700: '#be185d',
      800: '#9d174d',
      900: '#831843',
    }
  },
  teal: {
    name: 'Teal',
    value: '#14b8a6',
    rgb: '20 184 166',
    shades: {
      50: '#f0fdfa',
      100: '#ccfbf1',
      200: '#99f6e4',
      300: '#5eead4',
      400: '#2dd4bf',
      500: '#14b8a6',
      600: '#0d9488',
      700: '#0f766e',
      800: '#115e59',
      900: '#134e4a',
    }
  },
  orange: {
    name: 'Orange',
    value: '#f97316',
    rgb: '249 115 22',
    shades: {
      50: '#fff7ed',
      100: '#ffedd5',
      200: '#fed7aa',
      300: '#fdba74',
      400: '#fb923c',
      500: '#f97316',
      600: '#ea580c',
      700: '#c2410c',
      800: '#9a3412',
      900: '#7c2d12',
    }
  },
} as const

export type AccentColorKey = keyof typeof ACCENT_COLORS

// Theme presets
export const THEME_PRESETS = {
  default: {
    name: 'Default',
    description: 'Clean and professional',
    accentColor: 'sky' as AccentColorKey,
    borderRadius: 'md',
    fontScale: 'normal',
  },
  minimal: {
    name: 'Minimal',
    description: 'Simple and elegant',
    accentColor: 'indigo' as AccentColorKey,
    borderRadius: 'sm',
    fontScale: 'normal',
  },
  vibrant: {
    name: 'Vibrant',
    description: 'Bold and colorful',
    accentColor: 'rose' as AccentColorKey,
    borderRadius: 'lg',
    fontScale: 'normal',
  },
  nature: {
    name: 'Nature',
    description: 'Calm and organic',
    accentColor: 'emerald' as AccentColorKey,
    borderRadius: 'xl',
    fontScale: 'normal',
  },
  sunset: {
    name: 'Sunset',
    description: 'Warm and inviting',
    accentColor: 'orange' as AccentColorKey,
    borderRadius: 'md',
    fontScale: 'normal',
  },
  ocean: {
    name: 'Ocean',
    description: 'Cool and refreshing',
    accentColor: 'cyan' as AccentColorKey,
    borderRadius: 'lg',
    fontScale: 'normal',
  },
} as const

export type ThemePresetKey = keyof typeof THEME_PRESETS

export type ThemeMode = 'light' | 'dark' | 'auto'
export type BorderRadius = 'none' | 'sm' | 'md' | 'lg' | 'xl'
export type FontScale = 'small' | 'normal' | 'large'

interface ThemeState {
  // Basic theme
  mode: ThemeMode
  
  // Customization
  accentColor: AccentColorKey
  borderRadius: BorderRadius
  fontScale: FontScale
  
  // Preset
  activePreset: ThemePresetKey | 'custom'
  
  // Actions
  setMode: (mode: ThemeMode) => void
  setAccentColor: (color: AccentColorKey) => void
  setBorderRadius: (radius: BorderRadius) => void
  setFontScale: (scale: FontScale) => void
  applyPreset: (preset: ThemePresetKey) => void
  resetToDefault: () => void
}

// Apply CSS variables to document
const applyAccentColor = (colorKey: AccentColorKey) => {
  const color = ACCENT_COLORS[colorKey]
  const root = document.documentElement
  
  // Set primary color CSS variables
  root.style.setProperty('--color-primary', color.rgb)
  root.style.setProperty('--color-primary-hex', color.value)
  
  // Set all shade variables
  Object.entries(color.shades).forEach(([shade, value]) => {
    root.style.setProperty(`--color-primary-${shade}`, value)
  })
}

const applyBorderRadius = (radius: BorderRadius) => {
  const root = document.documentElement
  const values: Record<BorderRadius, string> = {
    none: '0',
    sm: '0.25rem',
    md: '0.5rem',
    lg: '0.75rem',
    xl: '1rem',
  }
  root.style.setProperty('--radius-base', values[radius])
  root.setAttribute('data-radius', radius)
}

const applyFontScale = (scale: FontScale) => {
  const root = document.documentElement
  const values: Record<FontScale, string> = {
    small: '14px',
    normal: '16px',
    large: '18px',
  }
  root.style.setProperty('--font-size-base', values[scale])
  root.setAttribute('data-font-scale', scale)
}

const applyThemeMode = (mode: ThemeMode) => {
  const root = document.documentElement
  
  if (mode === 'auto') {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    if (prefersDark) {
      root.classList.add('dark')
    } else {
      root.classList.remove('dark')
    }
  } else if (mode === 'dark') {
    root.classList.add('dark')
  } else {
    root.classList.remove('dark')
  }
  
  root.setAttribute('data-theme', mode === 'auto' 
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : mode
  )
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      mode: 'dark',
      accentColor: 'sky',
      borderRadius: 'md',
      fontScale: 'normal',
      activePreset: 'default',

      setMode: (mode) => {
        applyThemeMode(mode)
        set({ mode, activePreset: 'custom' })
      },

      setAccentColor: (accentColor) => {
        applyAccentColor(accentColor)
        set({ accentColor, activePreset: 'custom' })
      },

      setBorderRadius: (borderRadius) => {
        applyBorderRadius(borderRadius)
        set({ borderRadius, activePreset: 'custom' })
      },

      setFontScale: (fontScale) => {
        applyFontScale(fontScale)
        set({ fontScale, activePreset: 'custom' })
      },

      applyPreset: (presetKey) => {
        const preset = THEME_PRESETS[presetKey]
        applyAccentColor(preset.accentColor)
        applyBorderRadius(preset.borderRadius as BorderRadius)
        applyFontScale(preset.fontScale as FontScale)
        set({
          accentColor: preset.accentColor,
          borderRadius: preset.borderRadius as BorderRadius,
          fontScale: preset.fontScale as FontScale,
          activePreset: presetKey,
        })
      },

      resetToDefault: () => {
        const preset = THEME_PRESETS.default
        applyAccentColor(preset.accentColor)
        applyBorderRadius(preset.borderRadius as BorderRadius)
        applyFontScale(preset.fontScale as FontScale)
        applyThemeMode('dark')
        set({
          mode: 'dark',
          accentColor: preset.accentColor,
          borderRadius: preset.borderRadius as BorderRadius,
          fontScale: preset.fontScale as FontScale,
          activePreset: 'default',
        })
      },
    }),
    {
      name: 'easypi-theme',
      onRehydrateStorage: () => (state) => {
        // Apply stored theme on app load
        if (state) {
          applyThemeMode(state.mode)
          applyAccentColor(state.accentColor)
          applyBorderRadius(state.borderRadius)
          applyFontScale(state.fontScale)
        }
      },
    }
  )
)

// Initialize theme on module load
const initializeTheme = () => {
  const stored = localStorage.getItem('easypi-theme')
  if (stored) {
    try {
      const { state } = JSON.parse(stored)
      applyThemeMode(state.mode || 'auto')
      applyAccentColor(state.accentColor || 'sky')
      applyBorderRadius(state.borderRadius || 'md')
      applyFontScale(state.fontScale || 'normal')
    } catch {
      // Use defaults
      applyThemeMode('auto')
      applyAccentColor('sky')
      applyBorderRadius('md')
      applyFontScale('normal')
    }
  }
}

// Listen for system theme changes when in auto mode
if (typeof window !== 'undefined') {
  initializeTheme()
  
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    const state = useThemeStore.getState()
    if (state.mode === 'auto') {
      if (e.matches) {
        document.documentElement.classList.add('dark')
      } else {
        document.documentElement.classList.remove('dark')
      }
    }
  })
}
