import { useEffect } from 'react'
import { useSystemSetupStore } from '../stores/systemSetupStore'

export const useSystemSetup = () => {
  const state = useSystemSetupStore()

  // Initialize on mount (only once)
  useEffect(() => {
    // Check if redundant calls are an issue, but Zustand handles state updates efficiently
    useSystemSetupStore.getState().initialize()
  }, [])

  // Calculate derived state
  const needsSetup = state.permissionStatus
    ? !state.permissionStatus.permissions_ok && !state.setupCompleted
    : false

  return {
    ...state,
    needsSetup
  }
}
