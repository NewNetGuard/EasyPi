import { create } from 'zustand'
import { getPermissionsStatus, PermissionStatus } from '../api/system'

interface SystemSetupState {
    permissionStatus: PermissionStatus | null
    loading: boolean
    error: string | null
    showWizard: boolean
    setupCompleted: boolean

    // Actions
    setShowWizard: (show: boolean) => void
    setSetupCompleted: (completed: boolean) => void
    checkStatus: () => Promise<PermissionStatus | null>
    initialize: () => Promise<void>
    completeSetup: () => void
    skipSetup: () => void
    resetSetup: () => void
}

const SETUP_COMPLETED_KEY = 'easypi_setup_completed'
const SETUP_SKIPPED_KEY = 'easypi_setup_skipped'

export const useSystemSetupStore = create<SystemSetupState>((set, get) => ({
    permissionStatus: null,
    loading: true,
    error: null,
    showWizard: false,
    setupCompleted: false,

    setShowWizard: (show) => set({ showWizard: show }),

    setSetupCompleted: (completed) => set({ setupCompleted: completed }),

    checkStatus: async () => {
        try {
            const status = await getPermissionsStatus()
            set({ permissionStatus: status, error: null })
            return status
        } catch (err: any) {
            set({ error: err.message || 'Failed to check permissions' })
            return null
        }
    },

    initialize: async () => {
        set({ loading: true })

        const completedFlag = localStorage.getItem(SETUP_COMPLETED_KEY)
        const setupSkipped = localStorage.getItem(SETUP_SKIPPED_KEY)

        set({ setupCompleted: !!completedFlag })

        const status = await get().checkStatus()

        if (status) {
            // Show wizard if:
            // 1. Permissions not OK AND
            // 2. Setup was never completed AND
            // 3. Setup was not skipped (or was skipped more than 7 days ago)
            if (!status.permissions_ok && !completedFlag) {
                if (setupSkipped) {
                    const skippedDate = new Date(setupSkipped)
                    const daysSinceSkip = (Date.now() - skippedDate.getTime()) / (1000 * 60 * 60 * 24)
                    // Show wizard again after 7 days if skipped
                    if (daysSinceSkip > 7) {
                        set({ showWizard: true })
                    }
                } else {
                    set({ showWizard: true })
                }
            }
        }

        set({ loading: false })
    },

    completeSetup: () => {
        localStorage.setItem(SETUP_COMPLETED_KEY, new Date().toISOString())
        localStorage.removeItem(SETUP_SKIPPED_KEY)
        set({ setupCompleted: true, showWizard: false })
        get().checkStatus()
    },

    skipSetup: () => {
        localStorage.setItem(SETUP_SKIPPED_KEY, new Date().toISOString())
        set({ showWizard: false })
    },

    resetSetup: () => {
        localStorage.removeItem(SETUP_COMPLETED_KEY)
        localStorage.removeItem(SETUP_SKIPPED_KEY)
        set({ setupCompleted: false })
    }
}))
