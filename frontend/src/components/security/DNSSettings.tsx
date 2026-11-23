import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Save, Server, Globe, RefreshCw, CheckCircle, XCircle, Zap, ShieldCheck } from 'lucide-react'
import {
  getDNSRewrites,
  addDNSRewrite,
  deleteDNSRewrite,
  clearDNSCache,
  testUpstreamDNS,
} from '../../api/guardSecurity'
import { securityApi } from '../../api/client'
import { toast } from 'react-hot-toast'

export default function DNSSettings() {
  const [activeTab, setActiveTab] = useState<'upstream' | 'custom' | 'advanced'>('upstream')
  const queryClient = useQueryClient()

  // Upstream DNS servers — the resolver's REAL config (applied live on save).
  const { data: upstreamData } = useQuery({
    queryKey: ['dns-upstream'],
    queryFn: async () => {
      const { data } = await securityApi.get('/dns/upstream')
      return data
    },
    staleTime: 10000,
  })

  // DNS Rewrites (Custom Records)
  const {
    data: rewrites = [],
    isLoading: rewritesLoading,
    isFetching: rewritesFetching,
    refetch: refetchRewrites,
  } = useQuery({
    queryKey: ['dns-rewrites'],
    queryFn: getDNSRewrites,
    staleTime: 10000,
  })

  const [upstream, setUpstream] = useState<{ id: string; address: string }[]>([])
  const [newAddress, setNewAddress] = useState('')

  // Custom DNS record state
  const [newDomain, setNewDomain] = useState('')
  const [newAnswer, setNewAnswer] = useState('')

  // Test upstream state
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; time?: number; error?: string }> | null>(null)
  const [testing, setTesting] = useState(false)

  // Cache clear state
  const [cacheClearing, setCacheClearing] = useState(false)
  const [cacheCleared, setCacheCleared] = useState(false)

  useEffect(() => {
    if (upstreamData?.servers) {
      setUpstream(
        (upstreamData.servers as string[]).map((s, idx) => ({ id: `upstream-${idx}`, address: s })),
      )
    }
  }, [upstreamData])

  const saveUpstreamMutation = useMutation({
    mutationFn: async () => {
      const { data } = await securityApi.put('/dns/upstream', { servers: upstream.map((s) => s.address) })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dns-upstream'] })
      toast.success('Upstream DNS saved — resolver reloaded')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to save upstream DNS'),
  })

  const addRewriteMutation = useMutation({
    mutationFn: ({ domain, answer }: { domain: string; answer: string }) =>
      addDNSRewrite(domain, answer),
    onSuccess: () => {
      refetchRewrites()
      setNewDomain('')
      setNewAnswer('')
    },
  })

  const deleteRewriteMutation = useMutation({
    mutationFn: ({ domain, answer }: { domain: string; answer: string }) =>
      deleteDNSRewrite(domain, answer),
    onSuccess: () => refetchRewrites(),
  })

  const removeUpstream = (id: string) => {
    setUpstream((prev) => prev.filter((s) => s.id !== id))
  }

  const addUpstream = () => {
    if (!newAddress.trim()) return
    setUpstream((prev) => [...prev, { id: crypto.randomUUID(), address: newAddress.trim() }])
    setNewAddress('')
  }

  const handleAddRewrite = () => {
    if (!newDomain.trim() || !newAnswer.trim()) return
    addRewriteMutation.mutate({ domain: newDomain.trim(), answer: newAnswer.trim() })
  }

  const handleTestUpstream = async () => {
    setTesting(true)
    setTestResults(null)
    try {
      const servers = upstream.map((s) => s.address)
      if (servers.length === 0) {
        setTestResults({})
        return
      }
      const result = await testUpstreamDNS(servers)
      const results: Record<string, { success: boolean; time?: number; error?: string }> = {}
      if (result && typeof result === 'object') {
        Object.entries(result).forEach(([server, d]: [string, any]) => {
          if (d && typeof d === 'object') {
            results[server] = { success: Boolean(d.success) && !d.error, time: d.time, error: d.error }
          }
        })
      }
      setTestResults(results)
    } catch (error) {
      console.error('Error testing upstream:', error)
      toast.error('Failed to test upstream servers')
    } finally {
      setTesting(false)
    }
  }

  const handleClearCache = async () => {
    setCacheClearing(true)
    setCacheCleared(false)
    try {
      await clearDNSCache()
      setCacheCleared(true)
      setTimeout(() => setCacheCleared(false), 3000)
    } catch (error) {
      console.error('Error clearing cache:', error)
    } finally {
      setCacheClearing(false)
    }
  }

  const renderUpstream = () => (
    <div className="space-y-4">
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Server className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div className="text-sm text-blue-900 dark:text-blue-100">
            <div className="font-semibold mb-1">Upstream DNS Servers</div>
            <div>
              These are the resolver's real upstream servers (encrypted DoH/DoT URLs, or plain IPs).
              Saving applies them live — the DNS service reloads, which causes a brief (~few seconds) pause.
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Server</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Test Result</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {upstream.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-6 py-8 text-center text-sm text-gray-500 dark:text-gray-400">
                  No upstream servers configured
                </td>
              </tr>
            ) : (
              upstream.map((server) => (
                <tr key={server.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/50">
                  <td className="px-6 py-4">
                    <span className="text-sm font-mono text-gray-900 dark:text-white break-all">{server.address}</span>
                  </td>
                  <td className="px-6 py-4">
                    {testResults && testResults[server.address] ? (
                      testResults[server.address].success ? (
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-green-500" />
                          <span className="text-sm text-green-600 dark:text-green-400">
                            {testResults[server.address].time}ms
                          </span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <XCircle className="w-4 h-4 text-red-500" />
                          <span className="text-sm text-red-600 dark:text-red-400">
                            {testResults[server.address].error || 'Failed'}
                          </span>
                        </div>
                      )
                    ) : (
                      <span className="text-sm text-gray-400">-</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => removeUpstream(server.id)}
                      className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <input
          className="flex-1 px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white text-sm font-mono"
          placeholder="https://dns.quad9.net/dns-query  ·  tls://1.1.1.1:853  ·  9.9.9.9"
          value={newAddress}
          onChange={(e) => setNewAddress(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') addUpstream() }}
        />
        <button
          onClick={addUpstream}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors text-sm"
        >
          <Plus className="w-4 h-4" />
          Add Server
        </button>
      </div>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-4">
        <button
          onClick={handleTestUpstream}
          disabled={testing || upstream.length === 0}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg transition-colors disabled:opacity-50 text-sm"
        >
          <Zap className={`w-4 h-4 ${testing ? 'animate-pulse' : ''}`} />
          {testing ? 'Testing...' : 'Test Upstream Servers'}
        </button>
        <button
          onClick={() => saveUpstreamMutation.mutate()}
          disabled={saveUpstreamMutation.isPending || upstream.length === 0}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors disabled:opacity-50 text-sm"
        >
          <Save className="w-4 h-4" />
          {saveUpstreamMutation.isPending ? 'Saving & reloading...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )

  const renderCustom = () => (
    <div className="space-y-4">
      <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Globe className="w-5 h-5 text-purple-600 dark:text-purple-400 mt-0.5" />
          <div className="text-sm text-purple-900 dark:text-purple-100">
            <div className="font-semibold mb-1">Custom DNS Records (Rewrites)</div>
            <div>Create custom DNS rewrites to redirect domains to specific IP addresses or other domains. Useful for local services or testing.</div>
          </div>
        </div>
      </div>

      {/* Add new rewrite */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Add DNS Rewrite</h3>
        <div className="flex flex-col gap-2 sm:gap-3">
          <input
            type="text"
            placeholder="Domain (e.g. myservice.local)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white text-sm"
          />
          <input
            type="text"
            placeholder="Answer IP or domain (e.g. 192.168.1.100)"
            value={newAnswer}
            onChange={(e) => setNewAnswer(e.target.value)}
            className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white text-sm"
          />
          <button
            onClick={handleAddRewrite}
            disabled={!newDomain.trim() || !newAnswer.trim() || addRewriteMutation.isPending}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2 bg-purple-500 hover:bg-purple-600 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
          >
            <Plus className="w-4 h-4" />
            {addRewriteMutation.isPending ? 'Adding...' : 'Add Rewrite'}
          </button>
        </div>
      </div>

      {/* Rewrites list */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-3 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">
            DNS Rewrites ({rewrites.length})
          </h3>
          <button
            onClick={() => refetchRewrites()}
            disabled={rewritesFetching}
            className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${rewritesFetching ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {rewritesLoading ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2" />
            Loading DNS rewrites...
          </div>
        ) : rewrites.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            <Globe className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No custom DNS records configured</p>
            <p className="text-sm mt-1">Add a rewrite above to get started</p>
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Domain</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Answer</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {rewrites.map((rewrite) => (
                <tr key={rewrite.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/50">
                  <td className="px-6 py-4">
                    <span className="text-sm font-mono text-gray-900 dark:text-white">{rewrite.domain}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm font-mono text-purple-600 dark:text-purple-400">{rewrite.answer}</span>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => deleteRewriteMutation.mutate({ domain: rewrite.domain, answer: rewrite.answer })}
                      disabled={deleteRewriteMutation.isPending}
                      className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )

  const renderAdvanced = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">DNS Cache</h3>
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Clear the DNS cache to force fresh lookups for all domains. Useful after making DNS changes or troubleshooting.
            </p>
            <button
              onClick={handleClearCache}
              disabled={cacheClearing}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-red-500 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              {cacheClearing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Clearing Cache...
                </>
              ) : cacheCleared ? (
                <>
                  <CheckCircle className="w-4 h-4" />
                  Cache Cleared!
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  Clear DNS Cache
                </>
              )}
            </button>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">DNS Security</h3>
          <div className="space-y-3">
            <div className="flex items-center gap-3 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <ShieldCheck className="w-5 h-5 text-green-600 dark:text-green-400 shrink-0" />
              <div>
                <div className="text-sm font-medium text-gray-900 dark:text-white">DNSSEC validation: Active</div>
                <div className="text-xs text-gray-500 dark:text-gray-400">The resolver always validates DNSSEC signatures — no setup needed.</div>
              </div>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Query logging is configured in the <span className="font-medium">Query Log</span> tab.
              IPv6 status is shown in <span className="font-medium">Advanced Settings</span>.
              Encrypted DNS (DoH/DoT) endpoints are configured in <span className="font-medium">Personal DNS</span>.
            </p>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3 sm:gap-4">
          <Globe className="w-10 h-10 sm:w-16 sm:h-16 text-green-600 dark:text-green-400" />
          <div>
            <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">DNS Settings</h2>
            <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
              Configure DNS servers, custom records, and advanced options
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 sm:gap-2 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
        {(['upstream', 'custom', 'advanced'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-3 sm:px-6 py-2 sm:py-3 font-medium transition-colors border-b-2 capitalize text-xs sm:text-base whitespace-nowrap ${
              activeTab === tab
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {tab === 'upstream' ? 'Upstream' : tab === 'custom' ? 'Custom' : 'Advanced'}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'upstream' && renderUpstream()}
      {activeTab === 'custom' && renderCustom()}
      {activeTab === 'advanced' && renderAdvanced()}
    </div>
  )
}
