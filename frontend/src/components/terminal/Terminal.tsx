import TerminalEmulator from './TerminalEmulator'
import Card from '../common/Card'
import { Terminal as TerminalIcon } from 'lucide-react'

const Terminal = () => {
  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <TerminalIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
            Terminal
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-gray-500 dark:text-gray-400">
            Access your Raspberry Pi terminal directly from the browser
          </p>
        </div>
      </div>

      <Card noPadding>
        <TerminalEmulator />
      </Card>
    </div>
  )
}

export default Terminal