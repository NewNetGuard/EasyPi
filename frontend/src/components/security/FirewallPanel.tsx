import { useQuery, useMutation } from '@tanstack/react-query'
import { Trash2, RefreshCw, AlertTriangle, Plus, Shield } from 'lucide-react'
import type { FirewallRule, FirewallAction, Protocol } from '../../types/security'
import { getFirewallRules, addFirewallRule, deleteFirewallRule } from '../../api/guardSecurity'
import { useState } from 'react'

export default function FirewallPanel() {
  const [newRule, setNewRule] = useState<{ action: FirewallAction; protocol: Protocol; port: string; source: string }>({
    action: 'ALLOW',
    protocol: 'tcp',
    port: '',
    source: 'any',
  })

  const {
    data,
    isLoading,
    isFetching,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['piguard-firewall-rules'],
    queryFn: getFirewallRules,
    staleTime: 0,
    refetchOnMount: 'always',
    gcTime: 0,
  })

  const rules: FirewallRule[] = Array.isArray(data) ? data : []
  const loading = isLoading || isFetching

  const addMutation = useMutation({
    mutationFn: (ruleData: { action: FirewallAction; protocol: Protocol; port: string; source: string }) =>
      addFirewallRule({
        action: ruleData.action,
        protocol: ruleData.protocol,
        port: ruleData.port || 'any',
        source: ruleData.source || 'any',
        destination: 'any',
        enabled: true,
        name: `${ruleData.action} ${ruleData.port || 'any'}`,
        priority: 0,
      }),
    onSuccess: async () => {
      await refetch()
      setNewRule({ action: 'ALLOW', protocol: 'tcp', port: '', source: 'any' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteFirewallRule(id),
    onSuccess: async () => {
      await refetch()
    },
  })

  const handleAddRule = () => {
    if (!newRule.port.trim()) {
      return // Port is required
    }
    addMutation.mutate({
      action: newRule.action,
      protocol: newRule.protocol,
      port: newRule.port,
      source: newRule.source || 'any',
    })
  }

  const getActionColor = (action: FirewallAction) => {
    switch (action) {
      case 'ALLOW':
        return 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
      case 'DENY':
        return 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
      case 'LIMIT':
        return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300'
      case 'REJECT':
        return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 sm:gap-4">
            <Shield className="w-10 h-10 sm:w-16 sm:h-16 text-red-600 dark:text-red-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">Firewall Rules</h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Manage network firewall rules (UFW)
              </p>
            </div>
          </div>
          <button
            className="flex items-center justify-center gap-2 px-3 sm:px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg transition-colors disabled:opacity-50 text-sm w-full sm:w-auto"
            onClick={() => refetch()}
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Loading...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {isError && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-500">
          <AlertTriangle className="w-4 h-4" />
          <span>Failed to load firewall rules. Ensure backend has access to UFW.</span>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Total Rules</div>
          <div className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white mt-1">{rules.length}</div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Active</div>
          <div className="text-xl sm:text-2xl font-bold text-green-500 mt-1">
            {rules.filter(r => r.enabled).length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">ALLOW Rules</div>
          <div className="text-xl sm:text-2xl font-bold text-blue-500 mt-1">
            {rules.filter(r => r.action === 'ALLOW').length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700">
          <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">DENY Rules</div>
          <div className="text-xl sm:text-2xl font-bold text-red-500 mt-1">
            {rules.filter(r => r.action === 'DENY').length}
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500" />
        </div>
      ) : (
        <>
          {/* Add rule form */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3 sm:p-4 space-y-3">
            <div className="flex flex-col gap-2 sm:gap-3">
              <div className="grid grid-cols-2 sm:flex sm:flex-row gap-2 sm:gap-3">
                <select
                  className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                  value={newRule.action}
                  onChange={(e) => setNewRule((r) => ({ ...r, action: e.target.value as FirewallAction }))}
                >
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                  <option value="LIMIT">LIMIT</option>
                  <option value="REJECT">REJECT</option>
                </select>
                <select
                  className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                  value={newRule.protocol}
                  onChange={(e) => setNewRule((r) => ({ ...r, protocol: e.target.value as Protocol }))}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div className="grid grid-cols-1 sm:flex sm:flex-row gap-2 sm:gap-3">
                <input
                  className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                  placeholder="Port (e.g. 80)"
                  value={newRule.port}
                  onChange={(e) => setNewRule((r) => ({ ...r, port: e.target.value }))}
                />
                <input
                  className="px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white flex-1 text-sm"
                  placeholder="Source (e.g. any or 192.168.1.0/24)"
                  value={newRule.source}
                  onChange={(e) => setNewRule((r) => ({ ...r, source: e.target.value }))}
                />
                <button
                  onClick={handleAddRule}
                  disabled={addMutation.isPending || !newRule.port.trim()}
                  className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors disabled:opacity-50 text-sm"
                >
                  <Plus className="w-4 h-4" />
                  Add Rule
                </button>
              </div>
            </div>
          </div>

          {/* Rules Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Priority
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Action
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Protocol
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Port
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Source
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Hits
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-gray-50 dark:hover:bg-gray-900/50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {rule.priority}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900 dark:text-white">{rule.name}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-3 py-1 text-xs font-semibold rounded-full ${getActionColor(rule.action)}`}>
                          {rule.action}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-900 dark:text-white font-mono">{rule.protocol}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-900 dark:text-white font-mono">{rule.port}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-600 dark:text-gray-400">{rule.source}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {rule.hits.toLocaleString()}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => deleteMutation.mutate(rule.id)}
                            className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-50"
                        disabled={deleteMutation.isPending}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
