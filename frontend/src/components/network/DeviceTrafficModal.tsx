/**
 * Device Traffic Modal
 * 
 * Shows detailed DNS query activity for a specific device in real-time
 */

import { X, Globe, Shield, CheckCircle, XCircle, TrendingUp, Clock } from 'lucide-react';
import { useDeviceTraffic } from '../../hooks/useNetworkActivity';
import { formatDistanceToNow } from 'date-fns';

interface DeviceTrafficModalProps {
  deviceIp: string;
  onClose: () => void;
}

export default function DeviceTrafficModal({ deviceIp, onClose }: DeviceTrafficModalProps) {
  const { data: traffic, isLoading } = useDeviceTraffic(deviceIp, 200);

  if (isLoading || !traffic) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div className="w-full max-w-6xl rounded-2xl border border-gray-200 bg-white p-12 shadow-2xl dark:border-dark-700 dark:bg-dark-900">
          <div className="text-center">
            <div className="mx-auto h-8 w-8 animate-spin rounded-full border-4 border-blue-500 border-t-transparent"></div>
            <p className="mt-4 text-gray-600 dark:text-gray-400">Loading device traffic...</p>
          </div>
        </div>
      </div>
    );
  }

  const blockRate = traffic.totalQueries > 0
    ? ((traffic.blockedQueries / traffic.totalQueries) * 100).toFixed(1)
    : '0.0';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="flex h-[90vh] w-full max-w-6xl flex-col rounded-2xl border border-gray-200 bg-white shadow-2xl dark:border-dark-700 dark:bg-dark-900">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-200 p-6 dark:border-dark-700">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              {traffic.deviceName}
            </h2>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{traffic.device}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-gray-500 transition hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-800"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 border-b border-gray-200 p-6 dark:border-dark-700">
          <div className="rounded-xl bg-blue-50 p-4 dark:bg-blue-900/20">
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Queries</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
              {traffic.totalQueries.toLocaleString()}
            </p>
          </div>

          <div className="rounded-xl bg-red-50 p-4 dark:bg-red-900/20">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-red-600 dark:text-red-400" />
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Blocked</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-red-600 dark:text-red-400">
              {traffic.blockedQueries.toLocaleString()}
            </p>
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{blockRate}% of total</p>
          </div>

          <div className="rounded-xl bg-green-50 p-4 dark:bg-green-900/20">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Allowed</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-green-600 dark:text-green-400">
              {traffic.allowedQueries.toLocaleString()}
            </p>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="grid gap-6 lg:grid-cols-2">
            {/* Top Domains */}
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800">
              <div className="mb-4 flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                <h3 className="font-semibold text-gray-900 dark:text-white">Top Domains</h3>
              </div>
              <div className="space-y-2">
                {traffic.topDomains.slice(0, 10).map((domain, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between rounded-lg bg-white p-3 dark:bg-dark-900"
                  >
                    <div className="flex-1 truncate">
                      <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                        {domain.domain}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {domain.count} queries ({domain.percentage}%)
                      </p>
                    </div>
                    <div className="ml-4 flex items-center gap-2 text-xs">
                      <span className="text-green-600 dark:text-green-400">{domain.allowed}</span>
                      <span className="text-gray-400">/</span>
                      <span className="text-red-600 dark:text-red-400">{domain.blocked}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Blocked */}
            <div className="rounded-xl border border-red-200 bg-red-50 p-4 dark:border-red-900/50 dark:bg-red-900/10">
              <div className="mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-red-600 dark:text-red-400" />
                <h3 className="font-semibold text-gray-900 dark:text-white">Top Blocked</h3>
              </div>
              <div className="space-y-2">
                {traffic.topBlockedDomains.slice(0, 10).map((domain, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between rounded-lg bg-white p-3 dark:bg-dark-900"
                  >
                    <div className="flex-1 truncate">
                      <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                        {domain.domain}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {domain.blocked} blocked
                      </p>
                    </div>
                    <span className="ml-4 text-sm font-bold text-red-600 dark:text-red-400">
                      {domain.percentage}%
                    </span>
                  </div>
                ))}
                {traffic.topBlockedDomains.length === 0 && (
                  <p className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">
                    No blocked domains
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Recent Queries */}
          <div className="mt-6 rounded-xl border border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900">
            <div className="border-b border-gray-200 p-4 dark:border-dark-700">
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-gray-600 dark:text-gray-400" />
                <h3 className="font-semibold text-gray-900 dark:text-white">Live DNS Queries</h3>
              </div>
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Updates every 5 seconds • Showing last 50 queries
              </p>
            </div>
            <div className="max-h-96 overflow-y-auto">
              {traffic.recentQueries.map((query) => (
                <div
                  key={query.id}
                  className="flex items-center justify-between border-b border-gray-100 p-4 last:border-b-0 dark:border-dark-800"
                >
                  <div className="flex items-center gap-3">
                    {query.status === 'blocked' ? (
                      <XCircle className="h-5 w-5 shrink-0 text-red-500" />
                    ) : (
                      <CheckCircle className="h-5 w-5 shrink-0 text-green-500" />
                    )}
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-medium text-gray-900 dark:text-white">
                        {query.domain}
                      </p>
                      <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                        <span>{query.queryType}</span>
                        {query.responseTime && (
                          <>
                            <span>•</span>
                            <span>{query.responseTime}ms</span>
                          </>
                        )}
                        {query.reason && (
                          <>
                            <span>•</span>
                            <span className="text-red-600 dark:text-red-400">{query.reason}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  <span className="shrink-0 text-xs text-gray-400">
                    {formatDistanceToNow(new Date(query.timestamp), { addSuffix: true })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
