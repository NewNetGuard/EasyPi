import { useEffect, useMemo, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Search,
  LifeBuoy,
  Layers,
  AlertTriangle,
  MessageCircle,
  ExternalLink,
  Video,
  Mail,
  ChevronDown,
  ChevronUp,
  FileText
} from 'lucide-react'
import {
  helpSections,
  faqs,
  errorCodes,
  guides,
  quickLinks,
  supportChannels
} from '../data/helpContent'
import { useHelpStore } from '../stores/helpStore'

interface SearchableItem {
  id: string
  type: 'section' | 'faq' | 'guide' | 'error'
  title: string
  description: string
  tags: string[]
  refId?: string
}

const normalize = (value: string) => value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '')

const sectionGuideMap: Record<string, string> = {
  setup: 'guide-setup',
  guard: 'guide-piguard',
  piguard: 'guide-piguard',
  network: 'guide-network',
  'network-activity': 'guide-network-activity',
  backup: 'guide-backup',
  picloud: 'guide-picloud',
  cloud: 'guide-picloud',
  files: 'guide-picloud',
  marketplace: 'guide-services',
  'internet-encryption': 'guide-internet-encryption',
  'personal-dns': 'guide-personal-dns',
  wireguard: 'guide-wireguard',
  vpn: 'guide-wireguard',
  ai: 'guide-ai',
  monitoring: 'guide-monitoring',
  terminal: 'guide-terminal',
  devices: 'guide-cameras',
  settings: 'guide-settings',
  'system-security': 'guide-system-security',
  users: 'guide-users',
  'remote-access': 'guide-remote-access'
}

const levenshtein = (a: string, b: string) => {
  if (a === b) return 0
  const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0))
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      )
    }
  }
  return matrix[a.length][b.length]
}

const fuzzyIncludes = (text: string, query: string) => {
  const words = query.split(/\s+/).filter(Boolean)
  if (!words.length) return false
  return words.every((word) => {
    if (text.includes(word)) return true
    return text.split(/[^a-z0-9]+/).some((token) => token && levenshtein(token, word) <= 1)
  })
}

const Help = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const { logSearch, voteFaq, faqFeedback, logGuideView, recentSearches, guideViews } = useHelpStore()

  const [query, setQuery] = useState('')
  const [faqQuery, setFaqQuery] = useState('')
  const [expandedFaq, setExpandedFaq] = useState<string | null>(null)
  const [expandedGuide, setExpandedGuide] = useState<string | null>(null)
  const [guideSteps, setGuideSteps] = useState<Record<string, number>>({})
  const [highlightedError, setHighlightedError] = useState<string | null>(null)
  const [diagnosticsCopyState, setDiagnosticsCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const errorCode = params.get('error')
    const guideId = params.get('guide')
    
    if (errorCode) {
      setHighlightedError(errorCode)
      setTimeout(() => {
        const el = document.getElementById('errors')
        el?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
    } else if (guideId) {
      setExpandedGuide(guideId)
      setGuideSteps((prev) => (prev[guideId] !== undefined ? prev : { ...prev, [guideId]: 0 }))
      setTimeout(() => {
        const el = document.getElementById('guides')
        el?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
    } else {
      // Reset scroll to top when no params
      window.scrollTo({ top: 0, behavior: 'auto' })
    }
  }, [location.search])

  const searchIndex: SearchableItem[] = useMemo(() => {
    return [
      ...helpSections.map((section) => ({
        id: `section-${section.id}`,
        type: 'section' as const,
        title: section.title,
        description: section.description,
        tags: section.tags,
        refId: section.id
      })),
      ...faqs.map((item) => ({
        id: item.id,
        type: 'faq' as const,
        title: item.question,
        description: item.answer,
        tags: item.tags,
        refId: item.id
      })),
      ...guides.map((guide) => ({
        id: guide.id,
        type: 'guide' as const,
        title: guide.title,
        description: guide.steps.join(' '),
        tags: [guide.sectionId]
      })),
      ...errorCodes.map((error) => ({
        id: error.code,
        type: 'error' as const,
        title: `${error.code} (${error.status})`,
        description: `${error.message} ${error.meaning}`,
        tags: error.causes
      }))
    ]
  }, [])

  const searchResults = useMemo(() => {
    if (!query.trim()) return []
    const normalizedQuery = normalize(query.trim())
    
    const scored = searchIndex.map((item) => {
      const titleNorm = normalize(item.title)
      const descNorm = normalize(item.description)
      const tagsNorm = item.tags.map(t => normalize(t)).join(' ')
      
      let score = 0
      
      // Exact match at start of title (highest priority)
      if (titleNorm.startsWith(normalizedQuery)) {
        score = 1000
      }
      // Word in title starts with query
      else if (titleNorm.split(/\s+/).some(word => word.startsWith(normalizedQuery))) {
        score = 800
      }
      // Title contains query anywhere
      else if (titleNorm.includes(normalizedQuery)) {
        score = 500
      }
      // Description starts with query
      else if (descNorm.startsWith(normalizedQuery)) {
        score = 400
      }
      // Word in description starts with query
      else if (descNorm.split(/\s+/).some(word => word.startsWith(normalizedQuery))) {
        score = 300
      }
      // Description contains query
      else if (descNorm.includes(normalizedQuery)) {
        score = 200
      }
      // Tags match
      else if (tagsNorm.includes(normalizedQuery)) {
        score = 100
      }
      // Fuzzy match as last resort
      else if (fuzzyIncludes(titleNorm + ' ' + descNorm + ' ' + tagsNorm, normalizedQuery)) {
        score = 50
      }
      
      return { item, score }
    })
    
    const filtered = scored.filter(s => s.score > 0)
    filtered.sort((a, b) => b.score - a.score)
    
    return filtered.slice(0, 8).map(s => s.item)
  }, [query, searchIndex])

  useEffect(() => {
    if (query.trim()) {
      const id = setTimeout(() => logSearch(query.trim()), 800)
      return () => clearTimeout(id)
    }
    return
  }, [query, logSearch])

  const filteredFaqs = useMemo(() => {
    const q = faqQuery.trim().toLowerCase()
    if (!q) return faqs
    return faqs.filter((faq) => faq.question.toLowerCase().includes(q) || faq.answer.toLowerCase().includes(q))
  }, [faqQuery])

  const groupedFaqs = useMemo(() => {
    return filteredFaqs.reduce<Record<string, typeof filteredFaqs>>((acc, faq) => {
      acc[faq.sectionId] = acc[faq.sectionId] ? [...acc[faq.sectionId], faq] : [faq]
      return acc
    }, {})
  }, [filteredFaqs])

  const diagnosticPayload = useMemo(() => {
    return JSON.stringify(
      {
        page: location.pathname,
        recentSearchCount: recentSearches.length,
        guideViews
      },
      null,
      2
    )
  }, [location.pathname, recentSearches.length, guideViews])

  const copyDiagnostics = async () => {
    try {
      await navigator.clipboard.writeText(diagnosticPayload)
      setDiagnosticsCopyState('copied')
    } catch {
      setDiagnosticsCopyState('failed')
    }
  }

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <LifeBuoy className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Help &amp; Support</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Search for answers, explore guides, and resolve EasyPi errors — everything in one place.
          </p>
        </div>
      </div>

      {/* Search + quick links */}
      <div className="rounded-2xl border border-gray-200 bg-white p-4 shadow-sm dark:border-dark-700 dark:bg-dark-900">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value.slice(0, 96))}
              maxLength={96}
              type="text"
              placeholder='Search for help, e.g. "wireguard peer qr"'
              className="h-12 w-full rounded-xl border border-gray-200 bg-white pl-12 pr-4 text-sm text-gray-900 placeholder:text-gray-400 focus:border-primary-500 focus:outline-none dark:border-dark-600 dark:bg-dark-800 dark:text-white"
            />
              {searchResults.length > 0 && (
                <div className="absolute left-0 right-0 top-14 z-10 rounded-xl border border-gray-200 bg-white text-gray-900 shadow-xl dark:border-dark-600 dark:bg-dark-800 dark:text-white">
                  {searchResults.map((result) => (
                    <button
                      key={result.id}
                      className="flex w-full flex-col gap-0.5 border-b border-gray-100 px-4 py-3 text-left last:border-none hover:bg-gray-50"
                      onClick={() => {
                        setQuery('')
                        if (result.type === 'guide') {
                          navigate(`/help?guide=${result.id}`)
                        } else if (result.type === 'error') {
                          navigate(`/help?error=${result.id}`)
                        } else if (result.type === 'faq') {
                          setExpandedFaq(result.refId || null)
                          setTimeout(() => {
                            document.getElementById('faq')?.scrollIntoView({ behavior: 'smooth' })
                          }, 100)
                        } else if (result.type === 'section') {
                          const guideId = sectionGuideMap[result.refId || '']
                          if (guideId) {
                            navigate(`/help?guide=${guideId}`)
                          } else {
                            const sectionEl = document.getElementById('sections')
                            sectionEl?.scrollIntoView({ behavior: 'smooth' })
                          }
                        }
                      }}
                    >
                      <span className="text-sm font-semibold">{result.title}</span>
                      <span className="text-xs text-gray-500 line-clamp-2">{result.description}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {quickLinks.map((link) => (
                <button
                  key={link.id}
                  onClick={() => {
                    if (link.target.startsWith('#')) {
                      document.querySelector(link.target)?.scrollIntoView({ behavior: 'smooth' })
                    } else {
                      navigate(link.target)
                    }
                  }}
                  className="rounded-full bg-gray-100 px-4 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-200 dark:hover:bg-dark-700"
                >
                  {link.label}
                </button>
              ))}
            </div>
          </div>
          {recentSearches.length > 0 && (
            <div className="mt-3 text-xs text-gray-500 dark:text-gray-400">
              <p className="font-semibold uppercase tracking-[0.2em] text-gray-400">Recent searches</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {recentSearches.slice(0, 6).map((item) => (
                  <button
                    key={item}
                    onClick={() => setQuery(item)}
                    className="rounded-full border border-gray-200 px-3 py-1 text-gray-600 hover:border-gray-400 dark:border-dark-600 dark:text-gray-300 dark:hover:border-dark-400"
                  >
                    {item}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

      {/* Sections */}
      <section id="sections" className="space-y-4">
        <div className="flex items-center gap-3">
          <Layers className="h-5 w-5 text-primary-500" />
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-primary-500">Browse</p>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Browse by section</h2>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {helpSections.map((section) => (
            <div
              key={section.id}
              className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm hover:-translate-y-0.5 hover:shadow-md dark:border-dark-700 dark:bg-dark-900"
            >
              <p className="text-sm font-semibold text-gray-900 dark:text-white">{section.title}</p>
              <p className="mt-2 text-sm text-gray-500 dark:text-gray-300">{section.description}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-400">
                {section.tags.map((tag) => (
                  <span key={tag} className="rounded-full bg-gray-100 px-2 py-0.5 dark:bg-dark-800">
                    #{tag}
                  </span>
                ))}
              </div>
              <div className="mt-4 flex gap-2">
                <button
                  className="flex-1 rounded-lg border border-gray-200 px-3 py-2 text-xs font-semibold text-gray-700 dark:border-dark-700 dark:text-gray-200"
                  onClick={() => navigate(section.route)}
                >
                  Open section
                </button>
                <button
                  className="flex-1 rounded-lg bg-primary-600 px-3 py-2 text-xs font-semibold text-white"
                  onClick={() => {
                    const guideId = sectionGuideMap[section.id] || 'guide-setup'
                    navigate(`/help?guide=${guideId}`)
                  }}
                >
                  Learn more
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="space-y-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <MessageCircle className="h-5 w-5 text-purple-500" />
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-purple-500">FAQ</p>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Frequently Asked Questions</h2>
            </div>
          </div>
          <div className="relative w-full max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <input
              value={faqQuery}
              onChange={(e) => setFaqQuery(e.target.value.slice(0, 96))}
              maxLength={96}
              type="text"
              placeholder="Search in FAQ"
              className="h-10 w-full rounded-lg border border-gray-300 pl-10 pr-3 text-sm focus:border-primary-500 focus:outline-none dark:border-dark-700 dark:bg-dark-900"
            />
          </div>
        </div>

        <div className="space-y-6">
          {Object.entries(groupedFaqs).map(([sectionId, items]) => {
            const section = helpSections.find((s) => s.id === sectionId)
            return (
              <div key={sectionId} className="rounded-2xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
                <p className="text-sm font-semibold text-gray-900 dark:text-white">{section?.title || sectionId}</p>
                <div className="mt-4 divide-y divide-gray-200 dark:divide-dark-700">
                  {items.map((item) => {
                    const feedback = faqFeedback[item.id] || { up: 0, down: 0 }
                    const isOpen = expandedFaq === item.id
                    return (
                      <div key={item.id}>
                        <button
                          className="flex w-full items-center justify-between py-3 text-left"
                          onClick={() => setExpandedFaq(isOpen ? null : item.id)}
                        >
                          <span className="text-sm font-semibold text-gray-800 dark:text-gray-100">{item.question}</span>
                          {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                        </button>
                        {isOpen && (
                          <div className="pb-4 text-sm text-gray-600 dark:text-gray-300">
                            <p>{item.answer}</p>
                            <div className="mt-3 flex items-center gap-2 text-xs text-gray-400">
                              <span>Was this helpful?</span>
                              <button
                                className="flex items-center gap-1 rounded-full border px-2 py-0.5 text-green-500"
                                onClick={() => voteFaq(item.id, 'up')}
                              >
                                👍 {feedback.up}
                              </button>
                              <button
                                className="flex items-center gap-1 rounded-full border px-2 py-0.5 text-red-500"
                                onClick={() => voteFaq(item.id, 'down')}
                              >
                                👎 {feedback.down}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* Errors */}
      <section id="errors" className="space-y-4">
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-red-500" />
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-red-500">Diagnostics</p>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Common failure references</h2>
            <p className="mt-1 max-w-3xl text-sm text-gray-500 dark:text-gray-400">
              These ERR_* labels are Help search references. The backend itself returns an HTTP status and a plain error detail.
            </p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {errorCodes.map((error) => (
            <div
              key={error.code}
              className={`rounded-2xl border p-5 shadow-sm transition ${
                highlightedError === error.code
                  ? 'border-red-500 bg-red-50'
                  : 'border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-gray-900 dark:text-white">{error.code}</p>
                  <p className="text-xs text-gray-500">HTTP {error.status}</p>
                </div>
                <span className="rounded-full bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-500">{error.message}</span>
              </div>
              <p className="mt-3 text-sm text-gray-600 dark:text-gray-300">{error.meaning}</p>
              <div className="mt-3">
                <p className="text-xs font-semibold uppercase text-gray-400">Causes</p>
                <ul className="ml-4 list-disc text-sm text-gray-600 dark:text-gray-400">
                  {error.causes.map((cause) => (
                    <li key={cause}>{cause}</li>
                  ))}
                </ul>
              </div>
              <div className="mt-3">
                <p className="text-xs font-semibold uppercase text-gray-400">Fix</p>
                <ul className="ml-4 list-disc text-sm text-gray-600 dark:text-gray-300">
                  {error.fixes.map((fix) => (
                    <li key={fix}>{fix}</li>
                  ))}
                </ul>
              </div>
              {error.related && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {error.related.map((path) => (
                    <button
                      key={path}
                      className="rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-600 hover:bg-primary-50 hover:text-primary-500"
                      onClick={() => navigate(path)}
                    >
                      Go to {path}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Guides */}
      <section id="guides" className="space-y-4">
        <div className="flex items-center gap-3">
          <Video className="h-5 w-5 text-green-500" />
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-green-500">Tutorials</p>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">Step-by-step guides</h2>
          </div>
        </div>
        <div className="space-y-4">
          {guides.map((guide) => {
            const isExpanded = expandedGuide === guide.id
            const activeStep = Math.min(guideSteps[guide.id] ?? 0, guide.steps.length - 1)
            const progress = guide.steps.length ? Math.round(((activeStep + 1) / guide.steps.length) * 100) : 0
            return (
              <div key={guide.id} className="rounded-2xl border border-gray-200 bg-white p-6 dark:border-dark-700 dark:bg-dark-900">
                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex-1">
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">{guide.title}</p>
                    <p className="text-xs text-gray-400">Estimated time: {guide.estimatedTime || '10 min'}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-24 rounded-full bg-gray-100">
                      <div className="h-2 rounded-full bg-green-500" style={{ width: `${progress}%` }} />
                    </div>
                    <span className="text-xs text-gray-400">
                      Step {activeStep + 1}/{guide.steps.length}
                    </span>
                  </div>
                  <button
                    className="rounded-full border border-gray-300 px-3 py-1 text-xs font-semibold"
                    onClick={() => {
                      setExpandedGuide(isExpanded ? null : guide.id)
                      setGuideSteps((prev) => (prev[guide.id] !== undefined ? prev : { ...prev, [guide.id]: 0 }))
                      if (!isExpanded) {
                        logGuideView(guide.id)
                      }
                    }}
                  >
                    {isExpanded ? 'Hide steps' : 'View steps'}
                  </button>
                </div>

                {isExpanded && (
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <div>
                      <p className="text-xs font-semibold uppercase text-gray-400">Prerequisites</p>
                      <ul className="mt-2 list-disc space-y-1 pl-4 text-sm text-gray-600 dark:text-gray-300">
                        {guide.prerequisites.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                      <p className="mt-4 text-xs font-semibold uppercase text-gray-400">Interactive steps</p>
                      <div className="mt-2 rounded-xl border border-gray-200 p-4 text-sm dark:border-dark-700">
                        <p className="font-semibold text-gray-800 dark:text-gray-100">Current step</p>
                        <p className="mt-1 text-gray-600 dark:text-gray-300">{guide.steps[activeStep]}</p>
                        <div className="mt-3 flex items-center gap-2 text-xs">
                          <button
                            className="rounded-full border border-gray-200 px-3 py-1 disabled:opacity-50 dark:border-dark-700"
                            onClick={() => setGuideSteps((prev) => ({ ...prev, [guide.id]: Math.max((prev[guide.id] ?? 0) - 1, 0) }))}
                            disabled={activeStep === 0}
                          >
                            Previous
                          </button>
                          <button
                            className="rounded-full border border-gray-200 px-3 py-1 disabled:opacity-50 dark:border-dark-700"
                            onClick={() =>
                              setGuideSteps((prev) => ({
                                ...prev,
                                [guide.id]: Math.min((prev[guide.id] ?? 0) + 1, guide.steps.length - 1)
                              }))
                            }
                            disabled={activeStep === guide.steps.length - 1}
                          >
                            Next
                          </button>
                          <span className="ml-auto text-gray-400">{progress}% complete</span>
                        </div>
                      </div>
                      <ol className="mt-3 space-y-2 text-sm text-gray-600 dark:text-gray-300">
                        {guide.steps.map((step, index) => (
                          <li key={step} className="flex items-center gap-2">
                            <button
                              className={`h-6 w-6 rounded-full text-xs font-semibold ${
                                index === activeStep
                                  ? 'bg-primary-600 text-white'
                                  : 'border border-gray-300 text-gray-500 dark:border-dark-700'
                              }`}
                              onClick={() => setGuideSteps((prev) => ({ ...prev, [guide.id]: index }))}
                            >
                              {index + 1}
                            </button>
                            <span className={index === activeStep ? 'font-semibold text-gray-900 dark:text-white' : ''}>{step}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase text-gray-400">Troubleshooting</p>
                      <ul className="mt-2 list-disc space-y-1 pl-4 text-sm text-gray-600 dark:text-gray-300">
                        {guide.troubleshooting.map((tip) => (
                          <li key={tip}>{tip}</li>
                        ))}
                      </ul>
                      <div className="mt-4 rounded-xl border border-dashed border-gray-300 p-4 text-sm text-gray-500 dark:border-dark-700 dark:text-gray-300">
                        <p>Need visuals? Запланируйте видеогайд и прикрепите ссылку сюда. Пока можно открыть документацию в docs/guides.</p>
                      </div>
                      <div className="mt-4">
                        <button
                          className="w-full rounded-lg border px-3 py-2 text-xs text-gray-600 dark:border-dark-700 dark:text-gray-200"
                          onClick={() => navigate('/help')}
                        >
                          Back to Help
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* Support */}
      <section id="support" className="space-y-4">
        <div className="flex items-start gap-3 sm:items-center">
          <Mail className="h-5 w-5 text-sky-500" />
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-sky-500">Support</p>
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white sm:text-xl">Need more help?</h2>
              <span className="self-start rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 sm:self-auto">
                Coming soon
              </span>
            </div>
          </div>
        </div>
        <div className="space-y-3 sm:space-y-6">
          <div className="rounded-2xl border border-gray-200 bg-white p-4 sm:p-6 dark:border-dark-700 dark:bg-dark-900 overflow-hidden">
            <p className="text-sm font-semibold text-gray-900 dark:text-white">Web support form is not connected yet</p>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-300">
              Open a GitHub issue manually. The local diagnostic summary below contains only this page, error codes, and help counters; it is never uploaded automatically.
            </p>
            <pre className="mt-4 max-h-40 overflow-auto rounded-lg border border-dashed border-gray-300 bg-gray-50 p-3 text-[11px] leading-tight text-gray-600 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-300 break-all">{diagnosticPayload}</pre>
            <button
              type="button"
              className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-50 dark:border-dark-700 dark:text-gray-200"
              onClick={copyDiagnostics}
            >
              <FileText className="h-4 w-4" />
              {diagnosticsCopyState === 'copied'
                ? 'Diagnostics copied'
                : diagnosticsCopyState === 'failed'
                  ? 'Copy failed — select the text above'
                  : 'Copy diagnostics'}
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:gap-4">
            {supportChannels.map((channel) => (
              <div key={channel.id} className="rounded-2xl border border-gray-200 bg-white p-2.5 sm:p-5 dark:border-dark-700 dark:bg-dark-900 overflow-hidden">
                <p className="text-[11px] sm:text-sm font-semibold text-gray-900 dark:text-white truncate">{channel.label}</p>
                <p className="mt-0.5 text-[10px] sm:text-sm text-gray-500 line-clamp-2 break-words">{channel.description}</p>
                <a
                  className="mt-2 sm:mt-3 flex w-full items-center justify-center gap-1 rounded-lg border border-gray-200 px-2 py-1 sm:px-3 sm:py-2 text-[10px] sm:text-xs font-semibold text-gray-700 hover:bg-gray-50 dark:border-dark-700 dark:text-gray-200"
                  href={channel.action}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Contact
                  <ExternalLink className="h-2.5 w-2.5 sm:h-3.5 sm:w-3.5" />
                </a>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}

export default Help
