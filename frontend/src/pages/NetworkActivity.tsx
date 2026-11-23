/**
 * Network Activity Page
 * 
 * Real-time network monitoring showing all devices and their DNS activity
 * via EasyPi NetProtection.
 */

import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { blockSourceStyle } from '../components/security/blockSourceStyles';
import { Activity, Wifi, Shield, Radio, TrendingUp, AlertCircle, Search, RefreshCw, Ban, Check, Eye, Clock } from 'lucide-react';
import {
  useNetworkDevices,
  useNetworkStats,
  useNetProtectionStatus,
  usePrismActivity
} from '../hooks/useNetworkActivity';
import {
  useNetProtectionFullStatus,
  useNetProtectionDashboard,
  useVerdicts
} from '../hooks/useNetProtection';
import DeviceTrafficModal from '../components/network/DeviceTrafficModal';
import type { Verdict, VerdictType } from '../api/netProtectionApi';

type VerdictFilter = 'all' | 'blocked' | 'allowed' | 'adult';
type VerdictWithSite = Verdict & {
  site: string;
  origin_host?: string;
  adult_likely: boolean;
  source: 'dns' | 'prism';
};


export default function NetworkActivity() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const viewMode: 'devices' | 'verdicts' = searchParams.get('tab') === 'query-log' ? 'verdicts' : 'devices';
  const deviceFilter = searchParams.get('device');
  const setViewMode = (mode: 'devices' | 'verdicts') => {
    const next = new URLSearchParams(searchParams);
    next.set('tab', mode === 'verdicts' ? 'query-log' : 'devices');
    setSearchParams(next, { replace: true });
  };
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('all');
  const [siteFilter, setSiteFilter] = useState<string | null>(null);
  const selectVerdictFilter = (filter: VerdictFilter) => {
    setVerdictFilter(filter);
    setSiteFilter(null);
  };

  // NetProtection hooks
  const { data: netProtectionStatus } = useNetProtectionFullStatus();
  const { data: netProtectionDashboard, isLoading: npDashboardLoading } = useNetProtectionDashboard();
  const {
    data: verdictsResponse,
    isLoading: verdictsLoading,
    isFetching: verdictsRefreshing,
    refetch: refetchVerdicts,
  } = useVerdicts({
    limit: 200,
    include_system: false,
  });
  const {
    data: prismResponse,
    isLoading: prismLoading,
    isFetching: prismRefreshing,
    refetch: refetchPrism,
  } = usePrismActivity(200, viewMode === 'verdicts');

  // Extract verdicts array from response
  const verdicts = verdictsResponse?.data || [];

  // Legacy network hooks
  const { data: devices = [], isLoading: devicesLoading, refetch: refetchDevices } = useNetworkDevices();
  const { data: stats, isLoading: statsLoading } = useNetworkStats();

  // Check if NetProtection is active
  const isNetProtectionActive = netProtectionStatus?.running ?? false;

  // Filter devices by search
  const filteredDevices = devices.filter(device =>
    device.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    device.ip.includes(searchQuery) ||
    device.hostname?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Filter verdicts by search
  const dnsVerdictsWithSite: VerdictWithSite[] = verdicts.map((v) => {
    const domain = normalizeDomain(v.domain);
    const origin = decodeAmpCacheOriginHost(domain);
    const siteHost = origin ?? domain;
    const site = getRegistrableDomain(siteHost) || siteHost || domain || v.domain;
    return {
      ...v,
      site,
      origin_host: origin ?? undefined,
      adult_likely: isLikelyAdultDomain(site) || isLikelyAdultDomain(domain),
      source: 'dns',
    };
  });

  const prismVerdictsWithSite: VerdictWithSite[] = (prismResponse?.data || []).map((event) => {
    const domain = normalizeDomain(event.domain);
    const site = getRegistrableDomain(domain) || domain || event.domain;
    const device = devices.find((item) => item.ip === event.client_ip);
    return {
      flow_id: event.id,
      domain,
      verdict: 'observe',
      confidence: 0,
      evidence: [],
      client_ip: event.client_ip,
      client_name: device?.name,
      time: event.timestamp,
      query_type: event.queryType,
      status: event.status,
      evidence_summary: event.reason,
      site,
      adult_likely: false,
      source: 'prism',
    };
  });

  const activityEntries = [...dnsVerdictsWithSite, ...prismVerdictsWithSite]
    .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());

  const baseVerdicts = activityEntries.filter((v) => {
    if (verdictFilter === 'blocked') return v.source === 'dns' && isBlockedVerdict(v.verdict);
    if (verdictFilter === 'allowed') return v.source === 'dns' && !isBlockedVerdict(v.verdict);
    if (verdictFilter === 'adult') return v.source === 'dns' && v.adult_likely;
    return true;
  });
  const topSiteVerdicts = baseVerdicts.filter((item) => item.source === 'dns');

  const filteredVerdicts = baseVerdicts.filter((v) => {
    if (siteFilter && v.site !== siteFilter) return false;
    if (deviceFilter && v.client_ip !== deviceFilter && v.client_id !== deviceFilter) return false;

    const q = searchQuery.trim().toLowerCase();
    if (!q) return true;

    const hay = [
      v.site,
      v.domain,
      v.client_ip || '',
      v.client_name || '',
      v.client_id || '',
    ].join(' ').toLowerCase();

    return hay.includes(q);
  });

  const clearDeviceFilter = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('device');
    setSearchParams(next, { replace: true });
  };

  if (devicesLoading || statsLoading || npDashboardLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="text-center">
          <RefreshCw className="mx-auto h-8 w-8 animate-spin text-blue-500" />
          <p className="mt-4 text-gray-600 dark:text-gray-400">Loading network data...</p>
        </div>
      </div>
    );
  }

  if (!isNetProtectionActive) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-6 dark:border-red-900/50 dark:bg-red-900/10">
        <div className="flex items-start gap-3">
          <AlertCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
          <div>
            <h3 className="font-semibold text-red-900 dark:text-red-300">DNS Protection Not Running</h3>
            <p className="mt-2 text-sm text-red-700 dark:text-red-400">
              Network activity monitoring requires NetProtection to be enabled. Please enable NetProtection from the Security page.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Use NetProtection stats if available
  const totalQueries = isNetProtectionActive 
    ? (netProtectionDashboard?.totalQueries || 0) 
    : (stats?.totalQueries || 0);
  const blockedQueries = isNetProtectionActive 
    ? (netProtectionDashboard?.blockedToday || 0) 
    : (stats?.blockedQueries || 0);
  const blockRate = isNetProtectionActive 
    ? (netProtectionDashboard?.blockPercentage || 0) 
    : (stats?.blockRate || 0);
  const activeDevicesCount = isNetProtectionActive
    ? devices.filter((d) => (d.requestsCount || 0) > 0).length
    : (stats?.activeDevices || 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <Radio className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Network Activity</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Monitor DNS queries and traffic from devices on your network in real-time
            {isNetProtectionActive && (
              <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-700 dark:bg-green-900/30 dark:text-green-400">
                <Shield className="h-3 w-3" />
                NetProtection Active
              </span>
            )}
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-blue-50 p-3 dark:bg-blue-900/20">
              <Wifi className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Devices</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {activeDevicesCount}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-green-50 p-3 dark:bg-green-900/20">
              <Activity className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Queries</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {totalQueries.toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-red-50 p-3 dark:bg-red-900/20">
              <Shield className="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Blocked</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {blockedQueries.toLocaleString()}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-purple-50 p-3 dark:bg-purple-900/20">
              <TrendingUp className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Block Rate</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {blockRate.toFixed(1)}%
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* View Mode Tabs (NetProtection only) */}
      {isNetProtectionActive && (
        <div className="flex border-b border-gray-200 dark:border-dark-700">
          <button
            onClick={() => setViewMode('devices')}
            className={`px-4 py-2 text-sm font-medium transition ${
              viewMode === 'devices'
                ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
            }`}
          >
            <Wifi className="inline-block h-4 w-4 mr-2" />
            Devices
          </button>
          <button
            onClick={() => setViewMode('verdicts')}
            className={`px-4 py-2 text-sm font-medium transition ${
              viewMode === 'verdicts'
                ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
            }`}
          >
            <Activity className="inline-block h-4 w-4 mr-2" />
            Query Log
          </button>
        </div>
      )}

      {/* Devices List or Verdicts */}
      {viewMode === 'devices' ? (
        <div className="rounded-2xl border border-gray-200 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="border-b border-gray-200 p-6 dark:border-dark-700">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">Network Devices</h2>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  Click on a device to view detailed DNS activity
                </p>
              </div>
              <button
                onClick={() => refetchDevices()}
                className="rounded-lg bg-blue-50 p-2 text-blue-600 transition hover:bg-blue-100 dark:bg-blue-900/20 dark:text-blue-400"
                title="Refresh devices"
              >
                <RefreshCw className="h-5 w-5" />
              </button>
            </div>

            {/* Search */}
            <div className="mt-4 relative">
              <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search devices by name, IP, or hostname..."
              className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-4 text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white dark:placeholder-gray-400"
            />
          </div>
        </div>

        <div className="divide-y divide-gray-200 dark:divide-dark-700">
          {filteredDevices.length === 0 ? (
            <div className="p-12 text-center">
              <Wifi className="mx-auto h-12 w-12 text-gray-400" />
              <p className="mt-4 font-medium text-gray-600 dark:text-gray-400">
                {searchQuery ? 'No devices match your search' : 'No devices detected'}
              </p>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {searchQuery ? 'Try a different search term' : 'Make sure DNS is configured to use NetProtection'}
              </p>
            </div>
          ) : (
            filteredDevices.map((device) => (
              <button
                key={device.id}
                onClick={() => {
                  if (device.ip) setSelectedDevice(device.ip);
                }}
                disabled={!device.ip}
                className={`w-full p-6 text-left transition ${
                  device.ip
                    ? 'hover:bg-gray-50 dark:hover:bg-dark-800'
                    : 'cursor-default'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="rounded-xl bg-blue-50 p-3 dark:bg-blue-900/20">
                      <Wifi className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                    </div>
                    <div>
                      <div className="flex min-w-0 items-center gap-2">
                        <h3 className="truncate font-semibold text-gray-900 dark:text-white">{device.name}</h3>
                      </div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {device.ip
                          ? `${device.ip}${device.hostname ? ` • ${device.hostname}` : ''}`
                          : 'IP and MAC unavailable • DNS activity detected'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-6 text-right">
                    <div>
                      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Queries</p>
                      <p className="text-lg font-bold text-gray-900 dark:text-white">
                        {device.requestsCount.toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Blocked</p>
                      <p className="text-lg font-bold text-red-600 dark:text-red-400">
                        {device.blockedCount.toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Allowed</p>
                      <p className="text-lg font-bold text-green-600 dark:text-green-400">
                        {device.allowedCount.toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>
              </button>
            ))
          )}
        </div>
      </div>
      ) : (
        /* Query Log (Verdicts) */
        <div className="rounded-2xl border border-gray-200 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-900">
          <div className="border-b border-gray-200 p-6 dark:border-dark-700">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">Query Log</h2>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  Real-time DNS verdicts and Prisma DPI TLS/QUIC observations
                </p>
              </div>
              <button
                onClick={() => {
                  void refetchVerdicts();
                  void refetchPrism();
                }}
                disabled={verdictsLoading || prismLoading}
                className="rounded-lg bg-blue-50 p-2 text-blue-600 transition hover:bg-blue-100 dark:bg-blue-900/20 dark:text-blue-400"
                title="Refresh queries"
              >
                <RefreshCw className={`h-5 w-5 ${verdictsRefreshing || prismRefreshing ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {/* Search */}
            <div className="mt-4 relative">
              <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by site, domain, or device..."
                className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-4 text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white dark:placeholder-gray-400"
              />
            </div>

            {/* Filters */}
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <button
                onClick={() => selectVerdictFilter('all')}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  verdictFilter === 'all'
                    ? 'bg-gray-900 text-white dark:bg-white dark:text-gray-900'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
                }`}
              >
                All
              </button>
              <button
                onClick={() => selectVerdictFilter('blocked')}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  verdictFilter === 'blocked'
                    ? 'bg-red-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
                }`}
              >
                Blocked
              </button>
              <button
                onClick={() => selectVerdictFilter('allowed')}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  verdictFilter === 'allowed'
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
                }`}
              >
                Allowed
              </button>
              <button
                onClick={() => selectVerdictFilter('adult')}
                className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                  verdictFilter === 'adult'
                    ? 'bg-amber-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-800 dark:text-gray-300 dark:hover:bg-dark-700'
                }`}
                title="Show adult-like domains (heuristic)"
              >
                Adult
              </button>
              {siteFilter && (
                <button
                  onClick={() => setSiteFilter(null)}
                  className="rounded-full bg-blue-50 px-3 py-1 text-xs font-medium text-blue-700 hover:bg-blue-100 dark:bg-blue-900/20 dark:text-blue-300"
                  title="Clear site filter"
                >
                  Site: <span className="font-mono">{siteFilter}</span> x
                </button>
              )}
              {deviceFilter && (
                <button
                  onClick={clearDeviceFilter}
                  className="rounded-full bg-violet-50 px-3 py-1 text-xs font-medium text-violet-700 hover:bg-violet-100 dark:bg-violet-900/20 dark:text-violet-300"
                  title="Clear device filter"
                >
                  Device: <span className="font-mono">{deviceFilter}</span> x
                </button>
              )}
            </div>
          </div>

          {/* Top Sites */}
          {topSiteVerdicts.length > 0 && !searchQuery.trim() && (
            <div className="border-b border-gray-200 px-6 py-4 dark:border-dark-700">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-gray-900 dark:text-white">Top Sites</p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Derived from DNS hostnames to make visits easier to recognize
                </p>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {getTopSites(topSiteVerdicts, 14).map(({ site, count }) => (
                  <button
                    key={site}
                    onClick={() => setSiteFilter(site)}
                    className="rounded-full border border-gray-200 bg-white px-3 py-1 text-xs text-gray-700 hover:bg-gray-50 dark:border-dark-700 dark:bg-dark-900 dark:text-gray-300 dark:hover:bg-dark-800"
                    title="Filter by site"
                  >
                    <span className="font-mono">{site}</span>
                    <span className="ml-2 text-gray-500 dark:text-gray-400">{count}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="divide-y divide-gray-200 dark:divide-dark-700">
            {filteredVerdicts.length === 0 ? (
              <div className="p-12 text-center">
                <Activity className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-4 font-medium text-gray-600 dark:text-gray-400">
                  {searchQuery || deviceFilter ? 'No activity matches your filters' : 'No activity events yet'}
                </p>
              </div>
            ) : (
              filteredVerdicts.map((verdict) => (
                <VerdictRow key={verdict.flow_id} verdict={verdict} />
              ))
            )}
          </div>
        </div>
      )}

      {/* Device Traffic Modal */}
      {selectedDevice && (
        <DeviceTrafficModal
          deviceIp={selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}
    </div>
  );
}

// Verdict type styling
const verdictStyles: Record<VerdictType, { icon: React.ReactNode; bg: string; text: string }> = {
  allow: {
    icon: <Check className="h-4 w-4" />,
    bg: 'bg-green-100 dark:bg-green-900/30',
    text: 'text-green-600 dark:text-green-400',
  },
  deny: {
    icon: <Ban className="h-4 w-4" />,
    bg: 'bg-red-100 dark:bg-red-900/30',
    text: 'text-red-600 dark:text-red-400',
  },
  redirect: {
    icon: <Shield className="h-4 w-4" />,
    bg: 'bg-amber-100 dark:bg-amber-900/30',
    text: 'text-amber-600 dark:text-amber-400',
  },
  observe: {
    icon: <Eye className="h-4 w-4" />,
    bg: 'bg-blue-100 dark:bg-blue-900/30',
    text: 'text-blue-600 dark:text-blue-400',
  },
};

function isBlockedVerdict(verdict: VerdictType) {
  // In our UI, redirects are also treated as "blocked-ish" outcomes.
  return verdict === 'deny' || verdict === 'redirect';
}

function normalizeDomain(domain: string) {
  return (domain || '').trim().toLowerCase().replace(/\.+$/, '');
}

function decodeAmpCacheOriginHost(host: string): string | null {
  // AMP cache hostnames encode the origin host into the left-most label.
  // Example: www-xvideos3-com.cdn.ampproject.org -> www.xvideos3.com
  const suffix = '.cdn.ampproject.org';
  if (!host.endsWith(suffix)) return null;

  const prefix = host.slice(0, -suffix.length);
  const firstLabel = prefix.split('.').filter(Boolean)[0];
  if (!firstLabel) return null;

  const placeholder = '\0';
  return firstLabel.replace(/--/g, placeholder).replace(/-/g, '.').replace(new RegExp(placeholder, 'g'), '-');
}

const COMMON_TWO_LEVEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'co.nz',
  'org.nz',
  'com.br',
  'com.tr',
  'com.mx',
]);

function getRegistrableDomain(host: string): string {
  const h = normalizeDomain(host);
  if (!h) return '';

  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;

  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');

  if (COMMON_TWO_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) {
    return last3;
  }

  return last2;
}

function isLikelyAdultDomain(host: string): boolean {
  const h = normalizeDomain(host);
  if (!h) return false;

  const tld = h.split('.').pop() || '';
  if (['porn', 'xxx', 'adult', 'sex'].includes(tld)) return true;

  // High-confidence substrings and infra seen in the wild. Used for UI highlighting only.
  const strong = [
    'porn',
    'xnxx',
    'xvideos',
    'xhamster',
    'youporn',
    'redtube',
    'spankbang',
    'chaturbate',
    'stripchat',
    'livejasmin',
    'brazzers',
    'bangbros',
    'realitykings',
    'onlyfans',
    'fansly',
    'manyvids',
    'hentai',
    'nsfw',
    'escort',
    'milf',
    'boobs',
    // EasyPi-specific infra/domains we already block/tag in parental heuristics
    'faphouse',
    'noodlemagazine',
    'xgroovy',
    'xhcdn',
    'ahcdn',
    'flixcdn',
    'pvvstream',
    'fuq',
    'phncdn',
    'xvv1deos',
  ];
  if (strong.some((s) => h.includes(s))) return true;

  // Obfuscated variants (e.g. xvv1deos.com).
  if (/xv+i+deos/.test(h)) return true;
  if (/pornh[uv]b/.test(h)) return true;

  return false;
}

function getTopSites(verdicts: VerdictWithSite[], limit = 12) {
  const counts = new Map<string, number>();
  for (const v of verdicts) {
    counts.set(v.site, (counts.get(v.site) || 0) + 1);
  }

  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([site, count]) => ({ site, count }));
}

// Verdict Row Component
function VerdictRow({ verdict }: { verdict: VerdictWithSite }) {
  const style = verdictStyles[verdict.verdict];
  const timestamp = new Date(verdict.time).toLocaleTimeString();

  return (
    <div className="p-4 hover:bg-gray-50 dark:hover:bg-dark-800 transition">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className={`rounded-lg p-2 ${style.bg}`}>
            <span className={style.text}>{style.icon}</span>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white truncate">
                {verdict.site}
              </span>
              <span className={`flex-shrink-0 rounded px-2 py-0.5 text-xs font-medium ${
                verdict.source === 'prism'
                  ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                  : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'
              }`}>
                {verdict.source === 'prism' ? 'Prisma DPI' : 'DNS'}
              </span>
              {verdict.adult_likely && (
                <span className="flex-shrink-0 rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
                  Adult
                </span>
              )}
              {isBlockedVerdict(verdict.verdict) && verdict.block_source ? (
                <span
                  className={`flex-shrink-0 inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full ${blockSourceStyle(verdict.block_source_key).color}`}
                  title={verdict.evidence && verdict.evidence.length > 0 ? verdict.evidence[0].source : undefined}
                >
                  {blockSourceStyle(verdict.block_source_key).emoji} {verdict.block_source}
                </span>
              ) : verdict.evidence && verdict.evidence.length > 0 ? (
                <span className="flex-shrink-0 px-2 py-0.5 text-xs rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                  {verdict.evidence[0].source}
                </span>
              ) : null}
            </div>
            <div className="mt-1 font-mono text-xs text-gray-500 dark:text-gray-400 truncate">
              {verdict.domain}
              {verdict.origin_host && (
                <span className="ml-2 text-gray-400 dark:text-gray-500">(origin: {verdict.origin_host})</span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-xs text-gray-500 dark:text-gray-400">
              {verdict.source === 'dns' && (
                <>
                  <span>Confidence: {verdict.confidence}%</span>
                  <span>•</span>
                </>
              )}
              <span>
                {verdict.client_name || verdict.client_ip || verdict.client_id || 'unknown device'}
              </span>
              {verdict.response_time_ms !== undefined && verdict.response_time_ms !== null && (
                <>
                  <span>•</span>
                  <span>{verdict.response_time_ms}ms</span>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 text-right flex-shrink-0">
          <span className={`px-2 py-1 rounded text-xs font-medium ${style.bg} ${style.text}`}>
            {verdict.verdict.toUpperCase()}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {timestamp}
          </span>
        </div>
      </div>
    </div>
  );
}
