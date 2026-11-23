/**
 * Heuristics Dashboard Component
 * 
 * Displays:
 * - Heuristics statistics (DGA, Homoglyph, etc.)
 * - Shadow mode domains for review
 * - Security alerts
 * - Domain analysis tool
 */
import React, { useEffect, useState } from 'react';
import { toast } from 'react-hot-toast';
import {
  Brain,
  AlertTriangle,
  Shield,
  Ban,
  Check,
  Clock,
  Search,
  RefreshCw,
  ChevronRight,
  AlertCircle,
  Fingerprint,
  Globe,
  Activity,
  TrendingUp,
  ArrowLeft,
  Eye,
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../api/client';
import MlSelfLearningCard from './security/MlSelfLearningCard';

// Types
interface HeuristicsStats {
  enabled: boolean;
  total_analyzed: number;
  blocked_by_heuristics: number;
  observed_domains: number;
  dga_detections: number;
  homoglyph_detections: number;
  first_seen_new: number;
  device_anomalies: number;
  thresholds: { observe: number; block: number };
  last_updated: string;
}

interface Alert {
  id: string;
  timestamp: string;
  alert_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  domain: string;
  score: number;
  hit_count: number;
  reason: string;
  categories?: string[];
  state: 'blocked' | 'allowed' | 'force_blocked' | 'observing';
  acknowledged: boolean;
}

interface ObservingDomain {
  domain: string;
  score: number;
  hit_count: number;
  timestamp: string;
  reasons: string[];
  state: 'observing' | 'allowed' | 'force_blocked';
}

// Threat-class alert types: the dangerous, non-advertising detections that
// surface in the focused "Alerts" tab (a subset of everything in "Blocked").
const THREAT_TYPES = ['dns_rebinding', 'cname_cloak', 'homoglyph_attack', 'dga_attack', 'malware'];

const SEVERITY_COLORS: Record<string, string> = {
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
};

interface DomainAnalysis {
  domain: string;
  total_score: number;
  verdict: 'allow' | 'observe' | 'block';
  signals: Array<{
    signal_type: string;
    score: number;
    confidence: number;
    reason: string;
  }>;
  is_new_domain: boolean;
  in_shadow_mode: boolean;
  dga_analysis?: {
    is_suspicious: boolean;
    entropy: number;
    score: number;
  };
  homoglyph_analysis?: {
    is_suspicious: boolean;
    target_brand?: string;
    confidence: number;
  };
}

interface HeuristicsConfig {
  enabled: boolean;
  observe_threshold: number;
  block_threshold: number;
  detectors: {
    dga: boolean;
    homoglyph: boolean;
    first_seen: boolean;
    domain_analysis: boolean;
    device_anomaly: boolean;
    asn_cluster: boolean;
    shadow_mode: boolean;
  };
  tuning: {
    dga_threshold: number;
    homoglyph_threshold: number;
    first_seen_days: number;
    shadow_expire_days: number;
    shadow_promote_hits: number;
  };
  performance: {
    quick_mode_ms: number;
    persist_signals: boolean;
    max_signals_per_domain: number;
  };
}

// API calls
const fetchHeuristicsStats = async (): Promise<HeuristicsStats> => {
  const { data } = await apiClient.get('/dns/heuristics/stats');
  return data;
};

const fetchAlerts = async (params: { limit?: number; severity?: string }) => {
  const { data } = await apiClient.get('/dns/heuristics/alerts', { params });
  return data;
};

const fetchObserving = async () => {
  const { data } = await apiClient.get('/dns/heuristics/observing', { params: { limit: 200 } });
  return data;
};

const analyzeDomain = async (domain: string): Promise<DomainAnalysis> => {
  const { data } = await apiClient.get(`/dns/heuristics/analyze/${domain}`);
  return data;
};

const fetchHeuristicsConfig = async (): Promise<HeuristicsConfig> => {
  const { data } = await apiClient.get('/dns/heuristics/config');
  return data;
};

const saveHeuristicsConfig = async (config: HeuristicsConfig) => {
  const { data } = await apiClient.put('/dns/heuristics/config', config);
  return data;
};

// Allow / block a domain the AI engine flagged. Both lists apply live in the
// resolver (signal-file reload), so the effect is immediate.
const allowDomain = async (domain: string, wasForceBlocked: boolean) => {
  if (wasForceBlocked) {
    await apiClient.delete(`/netprotection/blacklist/${encodeURIComponent(domain)}`).catch(() => {});
  }
  await apiClient.post('/netprotection/whitelist', { domain, comment: 'Allowed from AI Engine' });
};

const blockDomain = async (domain: string, wasAllowed: boolean) => {
  if (wasAllowed) {
    await apiClient.delete(`/netprotection/whitelist/${encodeURIComponent(domain)}`).catch(() => {});
  }
  await apiClient.post('/netprotection/blacklist', { domain, comment: 'Blocked from AI Engine' });
};

// Main Component
interface HeuristicsDashboardProps {
  onBack?: () => void;
}

export default function HeuristicsDashboard({ onBack }: HeuristicsDashboardProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'blocked' | 'observing' | 'analyze' | 'config'>('overview');
  const [threatsOnly, setThreatsOnly] = useState(false);  // Blocked tab: All vs Threats-only
  const [searchDomain, setSearchDomain] = useState('');
  const [analysisResult, setAnalysisResult] = useState<DomainAnalysis | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [configDraft, setConfigDraft] = useState<HeuristicsConfig | null>(null);
  const [isSavingConfig, setIsSavingConfig] = useState(false);
  const [actioningDomain, setActioningDomain] = useState<string | null>(null);

  // Queries
  const { data: stats, isFetching: statsFetching, refetch: refetchStats } = useQuery({
    queryKey: ['heuristicsStats'],
    queryFn: fetchHeuristicsStats,
    refetchInterval: 30000,
  });

  const { data: alertsData, isLoading: alertsLoading, isFetching: alertsFetching, refetch: refetchAlerts } = useQuery({
    queryKey: ['heuristicsAlerts'],
    queryFn: () => fetchAlerts({ limit: 50 }),
    refetchInterval: 30000,
  });

  const { data: observingData, isLoading: observingLoading, isFetching: observingFetching, refetch: refetchObserving } = useQuery({
    queryKey: ['heuristicsObserving'],
    queryFn: fetchObserving,
    refetchInterval: 30000,
  });

  const { data: configData, refetch: refetchConfig } = useQuery({
    queryKey: ['heuristicsConfig'],
    queryFn: fetchHeuristicsConfig,
  });

  const isRefreshing = statsFetching || alertsFetching || observingFetching;

  const handleRefresh = async () => {
    await Promise.all([refetchStats(), refetchAlerts(), refetchObserving()]);
  };

  // Derived views shared by the Blocked / Alerts / Observing tabs.
  const scoreToSeverity = (score: number): Alert['severity'] =>
    score >= 70 ? 'critical' : score >= 50 ? 'high' : score >= 35 ? 'medium' : 'low';

  const allAlerts: Alert[] = alertsData?.alerts || [];
  const threatAlerts = allAlerts.filter((a) => THREAT_TYPES.includes(a.alert_type));
  const observingAsAlerts: Alert[] = (observingData?.domains || []).map((d: ObservingDomain) => ({
    id: d.domain,
    domain: d.domain,
    timestamp: d.timestamp,
    alert_type: 'observing',
    severity: scoreToSeverity(d.score),
    score: d.score,
    hit_count: d.hit_count,
    reason: d.reasons && d.reasons.length ? d.reasons.join(' · ') : 'Flagged — under observation',
    categories: [],
    state: d.state,
    acknowledged: d.state !== 'observing',
  }));

  useEffect(() => {
    if (configData) {
      setConfigDraft(configData);
    }
  }, [configData]);

  const handleAnalyzeDomain = async () => {
    if (!searchDomain.trim()) return;
    
    setIsAnalyzing(true);
    try {
      const result = await analyzeDomain(searchDomain.trim());
      setAnalysisResult(result);
    } catch (error) {
      toast.error('Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAllow = async (alert: Alert) => {
    setActioningDomain(alert.domain);
    try {
      await allowDomain(alert.domain, alert.state === 'force_blocked');
      const wasBlocked = alert.state === 'blocked' || alert.state === 'force_blocked';
      toast.success(wasBlocked ? `${alert.domain} restored — no longer blocked` : `${alert.domain} allowed`);
      refetchAlerts();
      refetchObserving();
      refetchStats();
    } catch {
      toast.error('Failed to allow domain');
    } finally {
      setActioningDomain(null);
    }
  };

  const handleBlock = async (alert: Alert) => {
    setActioningDomain(alert.domain);
    try {
      await blockDomain(alert.domain, alert.state === 'allowed');
      toast.success(`${alert.domain} blocked`);
      refetchAlerts();
      refetchObserving();
      refetchStats();
    } catch {
      toast.error('Failed to block domain');
    } finally {
      setActioningDomain(null);
    }
  };

  const handleSaveConfig = async () => {
    if (!configDraft) return;
    if (configDraft.observe_threshold >= configDraft.block_threshold) {
      toast.error('Observe threshold must be lower than block threshold');
      return;
    }

    setIsSavingConfig(true);
    try {
      await saveHeuristicsConfig(configDraft);
      toast.success('Heuristics settings updated');
      refetchConfig();
      refetchStats();
    } catch (error) {
      toast.error('Failed to save heuristics settings');
    } finally {
      setIsSavingConfig(false);
    }
  };

  const verdictColors = {
    allow: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    observe: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    block: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 sm:p-6 border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            {onBack && (
              <button
                onClick={onBack}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                title="Back to NetProtection"
              >
                <ArrowLeft className="w-5 h-5 text-gray-600 dark:text-gray-400" />
              </button>
            )}
            <Brain className="w-10 h-10 sm:w-16 sm:h-16 text-purple-600 dark:text-purple-400" />
            <div>
              <h2 className="text-lg sm:text-2xl font-bold text-gray-900 dark:text-white">
                Heuristics Engine
              </h2>
              <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-1">
                Machine-learning + heuristic threat detection
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
              stats?.enabled 
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
            }`}>
              {stats?.enabled ? 'Active' : 'Disabled'}
            </span>
            <button
              onClick={() => void handleRefresh()}
              disabled={isRefreshing}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
              title="Refresh"
            >
              <RefreshCw className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Self-learning model: live status, quality metrics, retrain-on-my-data */}
      <MlSelfLearningCard />

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-200 dark:border-gray-700">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'blocked', label: 'Blocked', icon: Ban, badge: alertsData?.unacknowledged },
          { id: 'observing', label: 'Observing', icon: Eye },
          { id: 'analyze', label: 'Analyze', icon: Search },
          { id: 'config', label: 'Config', icon: Shield },
        ].map(({ id, label, icon: Icon, badge }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id as any)}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === id
                ? 'border-purple-500 text-purple-600 dark:text-purple-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
            {badge !== undefined && badge > 0 && (
              <span className="px-2 py-0.5 text-xs font-medium bg-red-500 text-white rounded-full">
                {badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-2 gap-2 sm:gap-4">
            <StatCard
              icon={<Brain className="w-5 h-5 text-purple-500" />}
              label="Analyzed"
              value={stats?.total_analyzed?.toLocaleString() || '0'}
            />
            <StatCard
              icon={<Ban className="w-5 h-5 text-red-500" />}
              label="Blocked"
              value={stats?.blocked_by_heuristics?.toLocaleString() || '0'}
              highlight
              onClick={() => setActiveTab('blocked')}
            />
            <StatCard
              icon={<Eye className="w-5 h-5 text-yellow-500" />}
              label="Observing"
              value={(observingData?.total ?? stats?.observed_domains)?.toLocaleString() || '0'}
              onClick={() => setActiveTab('observing')}
            />
            <StatCard
              icon={<AlertTriangle className="w-5 h-5 text-orange-500" />}
              label="Threats"
              value={threatAlerts.length.toString()}
              onClick={() => { setThreatsOnly(true); setActiveTab('blocked'); }}
            />
          </div>

          {/* Detection Types */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
              <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4 flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-purple-500" />
                Detection Types
              </h3>
              
              <div className="space-y-4">
                <DetectionRow
                  label="DGA Domains"
                  description="Algorithmically generated domains"
                  count={stats?.dga_detections || 0}
                  color="red"
                />
                <DetectionRow
                  label="Homoglyph Attacks"
                  description="Brand impersonation (g00gle, paypa1)"
                  count={stats?.homoglyph_detections || 0}
                  color="orange"
                />
                <DetectionRow
                  label="New Domains"
                  description="First seen in last 7 days"
                  count={stats?.first_seen_new || 0}
                  color="blue"
                />
                <DetectionRow
                  label="Device Anomalies"
                  description="Traffic spikes from devices"
                  count={stats?.device_anomalies || 0}
                  color="yellow"
                />
              </div>
            </div>

            {/* Thresholds */}
            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
              <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-blue-500" />
                Score Thresholds
              </h3>
              
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between mb-2">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Risk Score</span>
                    <span className="text-sm text-gray-500">0 - 100</span>
                  </div>
                  <div className="relative h-8 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                    {/* Allow zone */}
                    <div 
                      className="absolute left-0 h-full bg-green-500/30"
                      style={{ width: `${stats?.thresholds?.observe || 30}%` }}
                    />
                    {/* Observe zone */}
                    <div 
                      className="absolute h-full bg-yellow-500/30"
                      style={{ 
                        left: `${stats?.thresholds?.observe || 30}%`,
                        width: `${(stats?.thresholds?.block || 70) - (stats?.thresholds?.observe || 30)}%`
                      }}
                    />
                    {/* Block zone */}
                    <div 
                      className="absolute right-0 h-full bg-red-500/30"
                      style={{ width: `${100 - (stats?.thresholds?.block || 70)}%` }}
                    />
                    
                    {/* Labels */}
                    <div className="absolute inset-0 flex items-center justify-between px-4 text-xs font-medium">
                      <span className="text-green-700 dark:text-green-400">Allow</span>
                      <span className="text-yellow-700 dark:text-yellow-400">Observe</span>
                      <span className="text-red-700 dark:text-red-400">Block</span>
                    </div>
                  </div>
                  <div className="flex justify-between mt-2 text-xs text-gray-500">
                    <span>0</span>
                    <span>{stats?.thresholds?.observe || 30}</span>
                    <span>{stats?.thresholds?.block || 70}</span>
                    <span>100</span>
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                      &lt;{stats?.thresholds?.observe || 30}
                    </div>
                    <div className="text-xs text-green-600/70">Allow</div>
                  </div>
                  <div className="p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20">
                    <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {stats?.thresholds?.observe || 30}-{stats?.thresholds?.block || 70}
                    </div>
                    <div className="text-xs text-yellow-600/70">Observe</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-50 dark:bg-red-900/20">
                    <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                      &gt;{stats?.thresholds?.block || 70}
                    </div>
                    <div className="text-xs text-red-600/70">Block</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'blocked' && (() => {
        const rows = threatsOnly ? threatAlerts : allAlerts;
        return (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <Ban className="w-5 h-5 text-red-500" />
                Blocked by AI Engine
              </h3>
              {/* All / Threats-only filter — replaces the old separate Alerts tab */}
              <div className="flex items-center gap-1 p-0.5 rounded-lg bg-gray-100 dark:bg-gray-700">
                <button
                  onClick={() => setThreatsOnly(false)}
                  className={`px-3 py-1 text-sm rounded-md transition-colors ${
                    !threatsOnly ? 'bg-white dark:bg-gray-800 shadow-sm text-gray-900 dark:text-white font-medium' : 'text-gray-500'
                  }`}
                >
                  All{allAlerts.length ? ` (${allAlerts.length})` : ''}
                </button>
                <button
                  onClick={() => setThreatsOnly(true)}
                  className={`flex items-center gap-1 px-3 py-1 text-sm rounded-md transition-colors ${
                    threatsOnly ? 'bg-white dark:bg-gray-800 shadow-sm text-orange-600 dark:text-orange-400 font-medium' : 'text-gray-500'
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Threats{threatAlerts.length ? ` (${threatAlerts.length})` : ''}
                </button>
              </div>
            </div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              {threatsOnly
                ? 'The dangerous ones only — malware, brand spoofing, DGA, DNS rebinding, CNAME-cloaked trackers.'
                : <>Domains the engine blocked on its own (not from the ad blocklist). If it caught something by mistake, hit <strong>Restore</strong> to unblock it.</>}
            </p>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {alertsLoading ? (
              <div className="p-8 text-center text-gray-500">Loading...</div>
            ) : rows.length > 0 ? (
              rows.map((alert) => (
                <AlertRow key={alert.id} alert={alert} actioningDomain={actioningDomain} onAllow={handleAllow} onBlock={handleBlock} />
              ))
            ) : (
              <div className="p-8 text-center text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p>{threatsOnly ? 'No active threats' : 'Nothing blocked by the engine yet'}</p>
                <p className="text-sm mt-1">{threatsOnly ? 'Only routine ad/tracker blocks right now.' : "The AI engine hasn't flagged any domains on its own."}</p>
              </div>
            )}
          </div>
        </div>
        );
      })()}

      {activeTab === 'observing' && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Eye className="w-5 h-5 text-yellow-500" />
              Under Observation
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Suspicious domains the engine is watching but not blocking yet. If you know the domain:
              <strong>Allow</strong> if it's fine, or <strong>Block</strong> if it's bad. Both apply live.
            </p>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {observingLoading ? (
              <div className="p-8 text-center text-gray-500">Loading...</div>
            ) : observingAsAlerts.length > 0 ? (
              observingAsAlerts.map((alert) => (
                <AlertRow key={alert.id} alert={alert} actioningDomain={actioningDomain} onAllow={handleAllow} onBlock={handleBlock} />
              ))
            ) : (
              <div className="p-8 text-center text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p>Nothing under observation</p>
                <p className="text-sm mt-1">No borderline domains being watched right now.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'analyze' && (
        <div className="space-y-6">
          {/* Search Box */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-3 sm:mb-4 flex items-center gap-2">
              <Search className="w-5 h-5 text-blue-500" />
              Analyze Domain
            </h3>
            
            <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
              <input
                type="text"
                value={searchDomain}
                onChange={(e) => setSearchDomain(e.target.value)}
                placeholder="Enter domain to analyze (e.g., g00gle.com)"
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                onKeyDown={(e) => e.key === 'Enter' && handleAnalyzeDomain()}
              />
              <button
                onClick={handleAnalyzeDomain}
                disabled={isAnalyzing || !searchDomain.trim()}
                className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
              >
                {isAnalyzing ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                Analyze
              </button>
            </div>
          </div>

          {/* Analysis Result */}
          {analysisResult && (
            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 sm:mb-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Analysis: <code>{analysisResult.domain}</code>
                  </h3>
                </div>
                <span className={`px-4 py-1.5 text-sm font-medium rounded-full ${verdictColors[analysisResult.verdict]}`}>
                  {analysisResult.verdict.toUpperCase()}
                </span>
              </div>

              {/* Score */}
              <div className="mb-6">
                <div className="flex justify-between mb-2">
                  <span className="text-sm text-gray-600 dark:text-gray-400">Risk Score</span>
                  <span className="font-bold text-gray-900 dark:text-white">{(analysisResult.total_score ?? 0).toFixed(1)}</span>
                </div>
                <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all ${
                      analysisResult.total_score >= 70 ? 'bg-red-500' :
                      analysisResult.total_score >= 30 ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${Math.min(analysisResult.total_score, 100)}%` }}
                  />
                </div>
              </div>

              {/* Analysis Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                {/* DGA Analysis */}
                {analysisResult.dga_analysis && (
                  <div className="p-4 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <h4 className="font-medium text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-red-500" />
                      DGA Analysis
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500">Suspicious:</span>
                        <span className={analysisResult.dga_analysis.is_suspicious ? 'text-red-600' : 'text-green-600'}>
                          {analysisResult.dga_analysis.is_suspicious ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {analysisResult.dga_analysis.entropy !== undefined && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Entropy:</span>
                          <span>{analysisResult.dga_analysis.entropy.toFixed(2)}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-gray-500">Score:</span>
                        <span>{((analysisResult.dga_analysis.score ?? 0) * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Homoglyph Analysis */}
                {analysisResult.homoglyph_analysis && (
                  <div className="p-4 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <h4 className="font-medium text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-orange-500" />
                      Homoglyph Analysis
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500">Impersonation:</span>
                        <span className={analysisResult.homoglyph_analysis.is_suspicious ? 'text-red-600' : 'text-green-600'}>
                          {analysisResult.homoglyph_analysis.is_suspicious ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {analysisResult.homoglyph_analysis.target_brand && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Target Brand:</span>
                          <span className="text-red-600 font-medium">{analysisResult.homoglyph_analysis.target_brand}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-gray-500">Confidence:</span>
                        <span>{((analysisResult.homoglyph_analysis.confidence ?? 0) * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Signals */}
              {analysisResult.signals.length > 0 && (
                <div className="mt-6">
                  <h4 className="font-medium text-gray-900 dark:text-white mb-3">Detected Signals</h4>
                  <div className="space-y-2">
                    {analysisResult.signals.map((signal, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                        <div>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {signal.signal_type}
                          </span>
                          <span className="text-sm text-gray-500 ml-2">{signal.reason}</span>
                        </div>
                        <span className="font-mono text-sm">{(signal.score ?? 0).toFixed(1)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'config' && configDraft && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
              <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Core Settings
              </h3>
              <div className="space-y-4">
                <label className="flex items-center justify-between gap-4">
                  <span className="text-sm text-gray-700 dark:text-gray-300">Enable heuristics engine</span>
                  <input
                    type="checkbox"
                    checked={configDraft.enabled}
                    onChange={(e) => setConfigDraft({ ...configDraft, enabled: e.target.checked })}
                    className="h-4 w-4"
                  />
                </label>
                <ConfigNumberField
                  label="Observe threshold"
                  value={configDraft.observe_threshold}
                  onChange={(value) => setConfigDraft({ ...configDraft, observe_threshold: value })}
                />
                <ConfigNumberField
                  label="Block threshold"
                  value={configDraft.block_threshold}
                  onChange={(value) => setConfigDraft({ ...configDraft, block_threshold: value })}
                />
                <ConfigNumberField
                  label="DGA threshold"
                  value={configDraft.tuning.dga_threshold}
                  step={0.05}
                  onChange={(value) => setConfigDraft({
                    ...configDraft,
                    tuning: { ...configDraft.tuning, dga_threshold: value },
                  })}
                />
                <ConfigNumberField
                  label="Homoglyph threshold"
                  value={configDraft.tuning.homoglyph_threshold}
                  step={0.05}
                  onChange={(value) => setConfigDraft({
                    ...configDraft,
                    tuning: { ...configDraft.tuning, homoglyph_threshold: value },
                  })}
                />
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-xl p-4 sm:p-6 shadow-sm">
              <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Detectors & Retention
              </h3>
              <div className="space-y-4">
                {[
                  ['dga', 'DGA detection'],
                  ['homoglyph', 'Homoglyph detection'],
                  ['first_seen', 'First-seen tracking'],
                  ['domain_analysis', 'Domain structure analysis'],
                  ['device_anomaly', 'Device anomaly detection'],
                  ['shadow_mode', 'Shadow mode'],
                ].map(([key, label]) => (
                  <label key={key} className="flex items-center justify-between gap-4">
                    <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
                    <input
                      type="checkbox"
                      checked={(configDraft.detectors as any)[key]}
                      onChange={(e) => setConfigDraft({
                        ...configDraft,
                        detectors: {
                          ...configDraft.detectors,
                          [key]: e.target.checked,
                        },
                      })}
                      className="h-4 w-4"
                    />
                  </label>
                ))}
                <ConfigNumberField
                  label="New-domain days"
                  value={configDraft.tuning.first_seen_days}
                  onChange={(value) => setConfigDraft({
                    ...configDraft,
                    tuning: { ...configDraft.tuning, first_seen_days: value },
                  })}
                />
                <ConfigNumberField
                  label="Shadow expire days"
                  value={configDraft.tuning.shadow_expire_days}
                  onChange={(value) => setConfigDraft({
                    ...configDraft,
                    tuning: { ...configDraft.tuning, shadow_expire_days: value },
                  })}
                />
                <ConfigNumberField
                  label="Shadow promote hits"
                  value={configDraft.tuning.shadow_promote_hits}
                  onChange={(value) => setConfigDraft({
                    ...configDraft,
                    tuning: { ...configDraft.tuning, shadow_promote_hits: value },
                  })}
                />
              </div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3">
            <button
              onClick={() => configData && setConfigDraft(configData)}
              className="px-4 py-2 rounded-lg border border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-300"
            >
              Reset
            </button>
            <button
              onClick={handleSaveConfig}
              disabled={isSavingConfig}
              className="px-5 py-2 rounded-lg bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50"
            >
              {isSavingConfig ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper Components

// One row in the Blocked / Alerts / Observing lists. Allow and Block apply live.
function AlertRow({ alert, actioningDomain, onAllow, onBlock }: {
  alert: Alert;
  actioningDomain: string | null;
  onAllow: (a: Alert) => void;
  onBlock: (a: Alert) => void;
}) {
  const busy = actioningDomain === alert.domain;
  return (
    <div className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3 min-w-0">
          <div className={`p-2 rounded-lg flex-shrink-0 ${
            alert.severity === 'critical' ? 'bg-red-100 dark:bg-red-900/30' :
            alert.severity === 'high' ? 'bg-orange-100 dark:bg-orange-900/30' :
            alert.severity === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900/30' :
            'bg-blue-100 dark:bg-blue-900/30'
          }`}>
            <AlertCircle className={`w-5 h-5 ${
              alert.severity === 'critical' ? 'text-red-600' :
              alert.severity === 'high' ? 'text-orange-600' :
              alert.severity === 'medium' ? 'text-yellow-600' :
              'text-blue-600'
            }`} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-gray-900 dark:text-white">
                {alert.alert_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
              </span>
              <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${SEVERITY_COLORS[alert.severity]}`}>
                {alert.severity}
              </span>
              <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                score {alert.score}
              </span>
              {alert.state === 'observing' && (
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400">
                  Watching
                </span>
              )}
              {alert.state === 'allowed' && (
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                  Allowed
                </span>
              )}
              {alert.state === 'force_blocked' && (
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                  Blocked permanently
                </span>
              )}
            </div>
            <code className="block mt-1 text-sm text-gray-700 dark:text-gray-300 break-all">
              {alert.domain}
            </code>
            {alert.reason && (
              <p className="mt-1 text-xs text-gray-500 break-words">{alert.reason}</p>
            )}
            <div className="mt-1 text-xs text-gray-400">
              {alert.hit_count.toLocaleString()} hits{alert.timestamp ? ` · last ${new Date(alert.timestamp).toLocaleString()}` : ''}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0 pl-11 sm:pl-0">
          {(alert.state === 'blocked' || alert.state === 'force_blocked') ? (
            // Already blocked — the only sensible action is to restore (unblock) it.
            <button
              onClick={() => onAllow(alert)}
              disabled={busy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-green-300 text-green-700 hover:bg-green-50 disabled:opacity-50 dark:border-green-800 dark:text-green-400 dark:hover:bg-green-900/20"
            >
              {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              Restore
            </button>
          ) : (
            // Not blocked yet (observing / allowed) — you decide its fate.
            <>
              {alert.state !== 'allowed' && (
                <button
                  onClick={() => onAllow(alert)}
                  disabled={busy}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-green-300 text-green-700 hover:bg-green-50 disabled:opacity-50 dark:border-green-800 dark:text-green-400 dark:hover:bg-green-900/20"
                >
                  {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                  Allow
                </button>
              )}
              <button
                onClick={() => onBlock(alert)}
                disabled={busy}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-red-300 text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-900/20"
              >
                {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Ban className="w-4 h-4" />}
                Block
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, trend, highlight, onClick }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  trend?: string;
  highlight?: boolean;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-xl ${
        highlight
          ? 'bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-900/30'
          : 'bg-white dark:bg-gray-800'
      } shadow-sm ${onClick ? 'cursor-pointer transition-colors hover:ring-2 hover:ring-purple-300 dark:hover:ring-purple-700' : ''}`}>
      <div className="flex items-center justify-between mb-2">
        {icon}
        {trend && (
          <span className="text-xs text-green-600 dark:text-green-400">{trend}</span>
        )}
      </div>
      <div className={`text-2xl font-bold ${
        highlight ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white'
      }`}>
        {value}
      </div>
      <div className="text-sm text-gray-500 dark:text-gray-400">{label}</div>
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) {
  const colors: Record<string, string> = {
    yellow: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600',
    red: 'bg-red-50 dark:bg-red-900/20 text-red-600',
    green: 'bg-green-50 dark:bg-green-900/20 text-green-600',
    purple: 'bg-purple-50 dark:bg-purple-900/20 text-purple-600',
  };
  
  return (
    <div className={`p-3 rounded-lg ${colors[color]}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs opacity-75">{label}</div>
    </div>
  );
}

function DetectionRow({ label, description, count, color }: {
  label: string;
  description: string;
  count: number;
  color: string;
}) {
  const colors: Record<string, string> = {
    red: 'bg-red-500',
    orange: 'bg-orange-500',
    blue: 'bg-blue-500',
    yellow: 'bg-yellow-500',
  };
  
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${colors[color]}`} />
        <div>
          <div className="text-sm font-medium text-gray-900 dark:text-white">{label}</div>
          <div className="text-xs text-gray-500">{description}</div>
        </div>
      </div>
      <span className="text-lg font-bold text-gray-900 dark:text-white">{count}</span>
    </div>
  );
}

function ConfigNumberField({
  label,
  value,
  onChange,
  step = 1,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
  step?: number;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm text-gray-700 dark:text-gray-300">{label}</span>
      <input
        type="number"
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
      />
    </label>
  );
}
