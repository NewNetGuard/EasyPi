import {
  Plug,
  Shield,
  Lock,
  EyeOff,
  Server,
  Globe,
  Activity,
  Wifi,
  Radio,
  Box,
  ShieldCheck,
  Terminal,
  FolderOpen,
  Database,
  Cloud,
  Video,
  ShoppingBag,
  Bot,
  LifeBuoy,
  Users,
  Settings,
  ClipboardList,
  BellRing,
  RotateCcw,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import Card from '../common/Card'

const QuickActions = () => {
  const navigate = useNavigate()

  const sections = [
    { label: 'Setup', icon: Plug, color: 'bg-indigo-500', href: '/setup' },
    { label: 'VPN', icon: Shield, color: 'bg-green-500', href: '/vpn' },
    { label: 'Internet Encryption', icon: Lock, color: 'bg-teal-500', href: '/internet-encryption' },
    { label: 'Stealth', icon: EyeOff, color: 'bg-indigo-500', href: '/stealth' },
    { label: 'Personal DNS', icon: Server, color: 'bg-blue-500', href: '/dns' },
    { label: 'Remote Access', icon: Globe, color: 'bg-cyan-500', href: '/remote-access' },
    { label: 'Monitoring', icon: Activity, color: 'bg-emerald-500', href: '/monitoring' },
    { label: 'Network Toolkit', icon: Wifi, color: 'bg-violet-500', href: '/network' },
    { label: 'Network Activity', icon: Radio, color: 'bg-purple-500', href: '/network-activity' },
    { label: 'Cloud', icon: Box, color: 'bg-sky-500', href: '/picloud' },
    { label: 'Guard Security', icon: ShieldCheck, color: 'bg-orange-500', href: '/guard' },
    { label: 'Terminal', icon: Terminal, color: 'bg-gray-700', href: '/terminal' },
    { label: 'Files', icon: FolderOpen, color: 'bg-amber-500', href: '/files' },
    { label: 'Backup', icon: Database, color: 'bg-teal-500', href: '/backup' },
    { label: 'Security', icon: Cloud, color: 'bg-red-500', href: '/security' },
    { label: 'IP Cameras', icon: Video, color: 'bg-pink-500', href: '/devices' },
    { label: 'Marketplace', icon: ShoppingBag, color: 'bg-fuchsia-500', href: '/marketplace' },
    { label: 'AI Chat', icon: Bot, color: 'bg-gradient-to-r from-blue-500 to-purple-500', href: '/ai' },
    { label: 'Help & Support', icon: LifeBuoy, color: 'bg-lime-500', href: '/help' },
    { label: 'Users', icon: Users, color: 'bg-rose-500', href: '/users' },
    { label: 'Settings', icon: Settings, color: 'bg-slate-500', href: '/settings' },
    { label: 'Jobs', icon: ClipboardList, color: 'bg-yellow-500', href: '/jobs' },
    { label: 'Notifications', icon: BellRing, color: 'bg-red-400', href: '/notifications' },
    { label: 'Rollback', icon: RotateCcw, color: 'bg-stone-500', href: '/rollback' },
  ]

  return (
    <Card title="Quick Navigation">
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
        {sections.map((section) => (
          <button
            key={section.label}
            onClick={() => navigate(section.href)}
            className="flex flex-col items-center gap-2 rounded-lg border border-gray-200 dark:border-dark-700 p-3 transition-all hover:border-primary-500 dark:hover:border-primary-500 hover:bg-primary-50 dark:hover:bg-primary-900/10 hover:shadow-md"
          >
            <div className={`rounded-lg ${section.color} p-2.5 text-white`}>
              <section.icon className="h-5 w-5" />
            </div>
            <span className="text-xs font-medium text-gray-900 dark:text-white text-center leading-tight">
              {section.label}
            </span>
          </button>
        ))}
      </div>
    </Card>
  )
}

export default QuickActions
