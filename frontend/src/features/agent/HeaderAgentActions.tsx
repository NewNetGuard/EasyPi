import { useMemo } from 'react'
import { useLocation } from 'react-router-dom'
import { Compass, MessageSquare } from 'lucide-react'
import Button from '../../components/common/Button'
import Tooltip from '../../components/common/Tooltip'
import { getAgentSectionConfig, getAgentTabFromLocation } from './api'
import { useAgentPanelStore } from '../../stores/agentPanelStore'

const humanizeTab = (tab?: string) =>
  tab
    ? tab
        .replace(/[-_]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, (letter) => letter.toUpperCase())
    : null

const buildSectionStatusQuestion = (sectionName: string, tab?: string) =>
  tab
    ? `What is the current status of the ${sectionName} section (${tab})?`
    : `What is the current status of the ${sectionName} section?`

/**
 * Compact Ask Agent / Section Status actions for the top Header.
 * Replaces the per-section SectionAgentBar so every page keeps a consistent,
 * lightweight header. The Explain question is still section-aware (derived from
 * the current route + tab), matching the old bar's behaviour.
 */
export default function HeaderAgentActions() {
  const location = useLocation()
  const section = useMemo(
    () => getAgentSectionConfig(location.pathname),
    [location.pathname]
  )
  const activeTab = useMemo(
    () => humanizeTab(getAgentTabFromLocation(location.search, location.hash, location.pathname)),
    [location.hash, location.pathname, location.search]
  )
  const open = useAgentPanelStore((state) => state.open)
  const queueQuestion = useAgentPanelStore((state) => state.queueQuestion)
  // Section config titles are named like "VPN Agent" — strip the internal suffix.
  const sectionName = section.title.replace(/\s+Agent$/i, '')

  return (
    <div className="flex items-center gap-1 sm:gap-2">
      <Tooltip content="Show the current section status" position="bottom">
        <Button
          variant="ghost"
          size="sm"
          onClick={() =>
            queueQuestion(buildSectionStatusQuestion(sectionName, activeTab || undefined), {
              route: section.route,
              tab: getAgentTabFromLocation(location.search, location.hash, location.pathname),
            })
          }
          icon={<Compass className="h-4 w-4 text-sky-600 dark:text-sky-400" />}
        >
          <span className="hidden xl:inline">Section Status</span>
        </Button>
      </Tooltip>
      <Tooltip content="Ask the agent" position="bottom">
        <Button
          variant="ghost"
          size="sm"
          onClick={open}
          icon={<MessageSquare className="h-4 w-4 text-sky-600 dark:text-sky-400" />}
        >
          <span className="hidden lg:inline">Ask Agent</span>
        </Button>
      </Tooltip>
    </div>
  )
}
