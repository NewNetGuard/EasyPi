import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Settings as SettingsIcon, Shield, User, Bell } from 'lucide-react'
import GeneralSettings from './GeneralSettings'
import SecuritySettings from './SecuritySettings'
import UserSettings from './UserSettings'
import PushNotificationSettings from '../notifications/PushNotificationSettings'
import TelegramAlertsCard from '../notifications/TelegramAlertsCard'
import EmailNotificationSettings from '../notifications/EmailNotificationSettings'
import OverviewStat from '../common/OverviewStat'

const SETTINGS_TABS = [
  { id: 'general', label: 'General', icon: SettingsIcon },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'user', label: 'User', icon: User },
]

const Settings = () => {
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState('general')

  useEffect(() => {
    const requestedTab = searchParams.get('tab')
    if (requestedTab && SETTINGS_TABS.some((tab) => tab.id === requestedTab) && requestedTab !== activeTab) {
      setActiveTab(requestedTab)
    }
  }, [activeTab, searchParams])

  const tabMeta = useMemo(
    () => ({
      general: {
        summary: 'Theme, language, timezone, and display preferences.',
        detail: 'Use this section to make EasyPi feel right on your device before you touch anything operational.',
      },
      notifications: {
        summary: 'Push delivery, alerts, and notification preferences.',
        detail: 'Choose what should interrupt you, what should stay quiet, and how EasyPi reaches you.',
      },
      security: {
        summary: 'Password, sessions, 2FA, and account safety controls.',
        detail: 'This is your personal access and session safety area, separate from system-wide Security scans.',
      },
      user: {
        summary: 'Profile, avatar, API token, and session details.',
        detail: 'Review who you are signed in as, where your sessions are active, and what user-level data is exposed.',
      },
    }),
    []
  )

  const activeTabInfo = tabMeta[activeTab as keyof typeof tabMeta] ?? tabMeta.general

  const selectTab = (tabId: string) => {
    setActiveTab(tabId)
    const next = new URLSearchParams(searchParams)
    next.set('tab', tabId)
    setSearchParams(next, { replace: true })
  }

  return (
    <div className="space-y-5 sm:space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <SettingsIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
            Settings
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Personalize EasyPi and control account-level preferences.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="rounded-2xl border border-gray-200 bg-white p-4 shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">
            Current section
          </div>
          <div className="mt-2 text-lg font-semibold text-gray-900 dark:text-white">
            {SETTINGS_TABS.find((tab) => tab.id === activeTab)?.label || 'General'}
          </div>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">{activeTabInfo.summary}</p>
          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{activeTabInfo.detail}</p>
        </div>

        <OverviewStat
          label="Settings focus"
          value={SETTINGS_TABS.find((tab) => tab.id === activeTab)?.label || 'General'}
          hint="Switch tabs below to move between personal, security, and notification controls."
          tone="primary"
          icon={SETTINGS_TABS.find((tab) => tab.id === activeTab)?.icon || SettingsIcon}
        />
      </div>

      <div className="rounded-2xl border border-gray-200 bg-white p-2 shadow-sm dark:border-dark-700 dark:bg-dark-900">
        <nav className="flex gap-2 overflow-x-auto scrollbar-hide">
          {SETTINGS_TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => selectTab(tab.id)}
              className={`relative flex items-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors whitespace-nowrap touch-target ${
                activeTab === tab.id
                  ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
                  : 'text-gray-500 hover:bg-gray-50 hover:text-gray-700 dark:text-gray-400 dark:hover:bg-dark-800 dark:hover:text-gray-300'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      <div>
        {activeTab === 'general' && <GeneralSettings />}
        {activeTab === 'notifications' && (
          <div className="space-y-6">
            <EmailNotificationSettings />
            <PushNotificationSettings />
            <TelegramAlertsCard />
          </div>
        )}
        {activeTab === 'security' && <SecuritySettings />}
        {activeTab === 'user' && <UserSettings />}
      </div>
    </div>
  )
}

export default Settings
