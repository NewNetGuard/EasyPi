/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_WS_URL?: string
  readonly VITE_APP_NAME?: string
  readonly VITE_APP_VERSION?: string
  readonly VITE_ENABLE_AI_ASSISTANT?: string
  readonly VITE_ENABLE_MULTI_DEVICE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

// Injected by Vite `define` from package.json version (see vite.config.ts).
declare const __APP_VERSION__: string