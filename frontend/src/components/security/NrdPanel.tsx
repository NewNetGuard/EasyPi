import { ShieldAlert } from 'lucide-react'
import NrdCard from './NrdCard'
import NrdBlockedList from './NrdBlockedList'

export default function NrdPanel() {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 sm:gap-4">
          <ShieldAlert className="w-10 h-10 sm:w-14 sm:h-14 text-rose-500 shrink-0" />
          <div>
            <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">New-Domain Guard (NRD)</h2>
            <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
              Block domains registered in the last few days — where most phishing/scam lives before it reaches blocklists.
            </p>
          </div>
        </div>
      </div>

      {/* The toggle + feed control */}
      <NrdCard />

      {/* Live list of what NRD blocked, with per-domain Allow */}
      <NrdBlockedList />

      {/* Plain explanation */}
      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 border border-blue-200 dark:border-blue-800 text-sm text-blue-800 dark:text-blue-200">
        <p className="font-medium mb-2">How it works</p>
        <ul className="list-disc pl-5 space-y-1.5 text-blue-700 dark:text-blue-300">
          <li>Scammers register thousands of fresh domains every day for phishing, use them for a day or two, then abandon them — they do damage before any blocklist catches them.</li>
          <li>Sites you actually use (bank, shops, Google) are years old. A domain created 2 days ago is suspicious — the vast majority of freshly-registered domains are spam/phishing/junk.</li>
          <li>Turn it on, choose an age window (≤ 7 / 14 / 30 days), then click <b>“Update feed”</b>. Freshly-registered domains get blocked and show a 🆕 <b>New (NRD)</b> badge in the Query Log.</li>
          <li>If a legitimate brand-new site ever gets blocked, add it to the allowlist (Guard Security → <b>Lists</b>).</li>
        </ul>
      </div>
    </div>
  )
}
