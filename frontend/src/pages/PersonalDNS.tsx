/**
 * Personal DNS Server Page
 * 
 * Deploy encrypted DNS server (NetProtection) to user's VPS.
 * Style: Help hero gradient + RemoteAccess visual diagrams
 */

import { useCallback, useState, useEffect, useRef } from 'react';
import { toast } from 'react-hot-toast';
import { copyToClipboard as copyToClipboardUtil } from '../utils/clipboard';
import ActionPreviewPanel from '../features/actions/ActionPreviewPanel';
import useActionPreview from '../features/actions/useActionPreview';
import {
  Globe,
  Shield,
  Lock,
  Server,
  CheckCircle,
  AlertCircle,
  Loader2,
  Key,
  Eye,
  EyeOff,
  Copy,
  ExternalLink,
  ArrowRight,
  Smartphone,
  Wifi,
  Settings,
  Download,
  AlertTriangle,
  Lightbulb,
  QrCode,
  Trash2,
  HelpCircle,
} from 'lucide-react';
import QRCode from 'qrcode';
import api from '../api/client';

interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'high' | 'medium' | 'info';
}

interface DeployResult {
  success: boolean;
  message: string;
  dns_ipv4?: string;
  doh_url?: string;
  dot_url?: string;
  admin_panel?: string;
  wireguard_installed?: boolean;
  wireguard_config?: string;
  vpn_dns?: string;
  warnings?: string[];
  recommendations?: Recommendation[];
  dns_port?: string;
  ssh_user?: string;
  ssh_port?: number;
  domain?: string;
}

interface SSHHostKeyInfo {
  host: string;
  port: number;
  key_type: string;
  fingerprint: string;
  bits: number;
  trust_status: 'unknown' | 'trusted' | 'changed';
  trusted_fingerprint?: string | null;
}

const apiErrorMessage = (error: unknown, fallback: string): string => {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;
  return error instanceof Error && error.message ? error.message : fallback;
};

// Legacy builds persisted WireGuard client private keys under this key.
const STORAGE_KEY = 'easypi_dns_deployment';
const LEGACY_DIRECT_DNS_WARNING = 'Public port 53 is blocked because no direct-DNS client IP was approved';

const PersonalDNS = () => {
  const [showModal, setShowModal] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [deploymentHidden, setDeploymentHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);
  const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'restricted' | 'unknown'>('unknown');
  const [statusDetails, setStatusDetails] = useState<string[]>([]);
  const [isCleaningUp, setIsCleaningUp] = useState(false);
  const [cleanupResult, setCleanupResult] = useState<{
    success: boolean;
    disk_usage?: { total: string; used: string; available: string; percent: string };
  } | null>(null);
  const [deploymentHistory, setDeploymentHistory] = useState<DeployResult[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [sshHostKey, setSshHostKey] = useState<SSHHostKeyInfo | null>(null);
  const [isInspectingHostKey, setIsInspectingHostKey] = useState(false);
  const [isTrustingHostKey, setIsTrustingHostKey] = useState(false);
  const [sshAuthStatus, setSshAuthStatus] = useState<'untested' | 'checking' | 'success' | 'failed'>('untested');
  const deployResultRef = useRef<HTMLDivElement>(null);
  const statusCheckIdRef = useRef(0);

  const checkServerStatus = useCallback(async (ip: string, _dnsPort?: string, notify = false) => {
    const checkId = ++statusCheckIdRef.current;
    setIsCheckingStatus(true);
    try {
      const response = await api.get(`/dns/status/${ip}`, { timeout: 18000 });
      if (checkId !== statusCheckIdRef.current) return;
      const nextStatus = response.data?.state === 'online'
        ? 'online'
        : response.data?.state === 'offline'
          ? 'offline'
          : 'restricted';
      setServerStatus(nextStatus);
      setStatusDetails(Array.isArray(response.data?.details) ? response.data.details : []);
      if (notify && nextStatus === 'online') toast.success('Personal DNS is online');
      if (notify && nextStatus === 'offline') toast.error('Encrypted DNS health check failed');
      if (notify && nextStatus === 'restricted') toast('Status is restricted; use VPS management for a definitive check');
    } catch (err: unknown) {
      if (checkId !== statusCheckIdRef.current) return;
      setServerStatus('offline');
      setStatusDetails([apiErrorMessage(err, 'Status check failed')]);
      if (notify) toast.error(apiErrorMessage(err, 'Status check failed'));
    } finally {
      if (checkId === statusCheckIdRef.current) setIsCheckingStatus(false);
    }
  }, []);

  const loadDeploymentHistory = useCallback(async (selectLatest = true) => {
    setIsLoadingHistory(true);
    try {
      const response = await api.get('/dns/deploys');
      if (response.data && Array.isArray(response.data)) {
        setDeploymentHistory(response.data);
        // Set most recent deployment as active
        if (selectLatest && response.data.length > 0) {
          setDeployResult(response.data[0]);
          setDeploymentHidden(false);
          if (response.data[0].dns_ipv4) {
            checkServerStatus(response.data[0].dns_ipv4, response.data[0].dns_port);
          }
        } else if (selectLatest && response.data.length === 0) {
          statusCheckIdRef.current += 1;
          setDeployResult(null);
          setDeploymentHidden(true);
          setServerStatus('unknown');
          setStatusDetails([]);
        }
      }
    } catch (e) {
      console.error('Failed to load deployment history:', e);
    } finally {
      setIsLoadingHistory(false);
    }
  }, [checkServerStatus]);

  useEffect(() => {
    localStorage.removeItem(STORAGE_KEY);
    void loadDeploymentHistory();
  }, [loadDeploymentHistory]);

  // Clear saved deployment
  const clearDeployment = () => {
    statusCheckIdRef.current += 1;
    setDeployResult(null);
    setDeploymentHidden(true);
    setServerStatus('unknown');
    setStatusDetails([]);
    setQrCodeUrl(null);
    setCleanupResult(null);
  };

  const openManage = (deployment: DeployResult | null = deployResult) => {
    if (deployment) {
      setFormData(previous => ({
        ...previous,
        vps_ip: deployment.dns_ipv4 || previous.vps_ip,
        ssh_user: deployment.ssh_user || previous.ssh_user || 'root',
        ssh_port: String(deployment.ssh_port || previous.ssh_port || 22),
        domain: deployment.domain || previous.domain,
      }));
    }
    setError(null);
    setShowModal(true);
  };

  // Remove only resources managed by Personal DNS; other VPS services are preserved.
  const handleCleanup = async () => {
    if (!formData.vps_ip && !deployResult?.dns_ipv4) {
      toast.error('No VPS IP available');
      return;
    }
    if (formData.auth_method === 'password' && !formData.ssh_password) {
      toast.error('Enter the VPS SSH password again to remove Personal DNS');
      return;
    }
    if (formData.auth_method === 'key' && !formData.ssh_key) {
      toast.error('Enter the VPS SSH private key again to remove Personal DNS');
      return;
    }
    if (!window.confirm('Remove Personal DNS from this VPS? Chameleon and other VPS services will be preserved.')) {
      return;
    }

    const vpsIp = formData.vps_ip || deployResult?.dns_ipv4 || '';

    setIsCleaningUp(true);
    setCleanupResult(null);

    try {
      const response = await api.post('/dns/cleanup', {
        vps_ip: vpsIp,
        ssh_user: formData.ssh_user || 'root',
        ssh_port: parseInt(formData.ssh_port) || 22,
        ssh_password: formData.auth_method === 'password' ? formData.ssh_password : undefined,
        ssh_key: formData.auth_method === 'key' ? formData.ssh_key : undefined,
      }, {
        timeout: 180000  // 3 minutes
      });

      setCleanupResult({
        success: response.data.success,
        disk_usage: response.data.details?.disk_usage
      });
      statusCheckIdRef.current += 1;
      setDeployResult(null);
      setDeploymentHidden(true);
      setServerStatus('unknown');
      setStatusDetails([]);
      setShowModal(false);
      await loadDeploymentHistory(true);
      toast.success('Personal DNS removed; other VPS services were preserved');
    } catch (err: unknown) {
      toast.error(apiErrorMessage(err, 'Cleanup failed'));
    } finally {
      setIsCleaningUp(false);
    }
  };

  // Generate QR code when wireguard config is available
  useEffect(() => {
    if (deployResult?.wireguard_config) {
      QRCode.toDataURL(deployResult.wireguard_config, {
        width: 200,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' }
      }).then(setQrCodeUrl).catch(console.error);
    }
  }, [deployResult?.wireguard_config]);

  // Scroll to deployment result when it appears
  useEffect(() => {
    if (deployResult && !deploymentHidden) {
      setTimeout(() => {
        deployResultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 300);
    }
  }, [deployResult, deploymentHidden]);

  const [formData, setFormData] = useState({
    vps_ip: '',
    ssh_user: 'root',
    ssh_port: '22',
    auth_method: 'password' as 'password' | 'key',
    ssh_password: '',
    ssh_key: '',
    domain: '',
    duckdns_token: '',
    certificate_email: '',
    allowed_client_ips: ''
  });
  const dnsDeployPreviewQuery = useActionPreview(
    'dns.deploy',
    formData.vps_ip.trim() || 'remote-vps',
    showModal && !isDeploying
  );

  useEffect(() => {
    setSshHostKey(null);
    setSshAuthStatus('untested');
    setError(null);
  }, [formData.vps_ip, formData.ssh_port]);

  useEffect(() => {
    setSshAuthStatus('untested');
  }, [formData.ssh_user, formData.auth_method, formData.ssh_password, formData.ssh_key]);

  const copyToClipboard = async (text: string, field: string) => {
    const success = await copyToClipboardUtil(text);
    if (success) {
      setCopiedField(field);
      toast.success('Copied!');
      setTimeout(() => setCopiedField(null), 2000);
    } else {
      toast.error('Failed to copy');
    }
  };

  const inspectSSHIdentity = async (showSuccessToast = true): Promise<SSHHostKeyInfo | null> => {
    const host = formData.vps_ip.trim();
    const port = Number.parseInt(formData.ssh_port, 10);
    if (!host) {
      const message = 'Please enter the VPS IP address first';
      setError(message);
      toast.error(message);
      return null;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      const message = 'SSH port must be between 1 and 65535';
      setError(message);
      toast.error(message);
      return null;
    }

    setIsInspectingHostKey(true);
    setError(null);
    try {
      const response = await api.post<SSHHostKeyInfo>('/dns/ssh/host-key', {
        vps_ip: host,
        ssh_port: port,
      }, { timeout: 30000 });
      const identity = response.data;
      setSshHostKey(identity);
      if (identity.trust_status === 'changed') {
        setError('SSH host key changed. Deployment is blocked until you verify the VPS through its provider console.');
        toast.error('SSH host identity changed — deployment blocked');
      } else if (identity.trust_status === 'unknown') {
        toast('Compare the SSH fingerprint with your VPS provider before trusting it.', { icon: '🔐' });
      } else if (showSuccessToast) {
        toast.success('VPS host key is trusted; SSH credentials were not tested');
      }
      return identity;
    } catch (err: unknown) {
      const message = apiErrorMessage(err, 'Could not inspect the VPS SSH identity');
      setSshHostKey(null);
      setError(message);
      toast.error(message);
      return null;
    } finally {
      setIsInspectingHostKey(false);
    }
  };

  const trustSSHIdentity = async () => {
    if (!sshHostKey || sshHostKey.trust_status !== 'unknown') return;
    setIsTrustingHostKey(true);
    setError(null);
    try {
      const response = await api.post<SSHHostKeyInfo>('/dns/ssh/trust-host-key', {
        vps_ip: formData.vps_ip.trim(),
        ssh_port: Number.parseInt(formData.ssh_port, 10),
        expected_fingerprint: sshHostKey.fingerprint,
      }, { timeout: 30000 });
      setSshHostKey(response.data);
      toast.success('SSH host key trusted for this IP and port');
    } catch (err: unknown) {
      const message = apiErrorMessage(err, 'SSH host key was not trusted');
      setError(message);
      toast.error(message);
      await inspectSSHIdentity(false);
    } finally {
      setIsTrustingHostKey(false);
    }
  };

  const checkSSHCredentials = async () => {
    if (sshHostKey?.trust_status !== 'trusted') {
      const message = 'Trust the VPS host key before testing SSH credentials';
      setError(message);
      toast.error(message);
      return;
    }
    if (formData.auth_method === 'password' && !formData.ssh_password) {
      toast.error('Please enter SSH password');
      return;
    }
    if (formData.auth_method === 'key' && !formData.ssh_key) {
      toast.error('Please enter SSH private key');
      return;
    }

    setSshAuthStatus('checking');
    setError(null);
    try {
      await api.post('/dns/ssh/check-credentials', {
        vps_ip: formData.vps_ip.trim(),
        ssh_user: formData.ssh_user,
        ssh_port: Number.parseInt(formData.ssh_port, 10),
        ssh_password: formData.auth_method === 'password' ? formData.ssh_password : undefined,
        ssh_key: formData.auth_method === 'key' ? formData.ssh_key : undefined,
      }, { timeout: 90000 });
      setSshAuthStatus('success');
      toast.success('SSH login successful');
    } catch (err: unknown) {
      const message = apiErrorMessage(err, 'SSH login failed');
      setSshAuthStatus('failed');
      setError(message);
      toast.error(message);
    }
  };

  const handleDeploy = async () => {
    if (!formData.vps_ip) {
      toast.error('Please enter VPS IP address');
      return;
    }
    if (formData.auth_method === 'password' && !formData.ssh_password) {
      toast.error('Please enter SSH password');
      return;
    }
    if (formData.auth_method === 'key' && !formData.ssh_key) {
      toast.error('Please enter SSH private key');
      return;
    }

    const identity = await inspectSSHIdentity(false);
    if (!identity || identity.trust_status !== 'trusted') {
      if (identity?.trust_status === 'unknown') {
        setError('Verify the fingerprint with your VPS provider and trust this host key before deployment.');
      }
      return;
    }

    setIsDeploying(true);
    setError(null);

    try {
      const response = await api.post('/dns/deploy', {
        vps_ip: formData.vps_ip,
        ssh_user: formData.ssh_user,
        ssh_port: parseInt(formData.ssh_port),
        ssh_password: formData.auth_method === 'password' ? formData.ssh_password : undefined,
        ssh_key: formData.auth_method === 'key' ? formData.ssh_key : undefined,
        domain: formData.domain || undefined,
        duckdns_token: formData.duckdns_token || undefined,
        certificate_email: formData.certificate_email || undefined,
        allowed_client_ips: formData.allowed_client_ips
          .split(/[\s,;]+/)
          .map(value => value.trim())
          .filter(Boolean)
      }, {
        timeout: 1500000  // 25 minutes for deployment with WireGuard
      });

      setDeployResult(response.data);
      setFormData(previous => ({
        ...previous,
        ssh_password: '',
        ssh_key: '',
        duckdns_token: '',
      }));
      setDeploymentHidden(false);
      setShowModal(false);
      if (response.data?.dns_ipv4) {
        checkServerStatus(response.data.dns_ipv4, response.data.dns_port);
      }
      // Reload deployment history from database
      await loadDeploymentHistory(false);
      toast.success('DNS Server deployed successfully!');
    } catch (err: unknown) {
      const errorMessage = apiErrorMessage(err, 'Deployment failed');
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setIsDeploying(false);
    }
  };

  const visibleWarnings = deployResult?.warnings?.filter(
    warning => warning !== LEGACY_DIRECT_DNS_WARNING
  ) ?? [];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/30">
          <Server className="h-6 w-6 text-primary-600 dark:text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Personal DNS Server</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Deploy your own encrypted DNS server with ad-blocking on any VPS — full control, no logs, no trackers.
          </p>
        </div>
      </div>

      {/* Deployment History Button */}
      {deploymentHistory.length > 0 && (
        <div className="flex justify-between items-center">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-dark-800 border border-gray-200 dark:border-dark-600 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
          >
            <Settings className="w-4 h-4" />
            <span className="font-medium">Deployment History ({deploymentHistory.length})</span>
            <ArrowRight className={`w-4 h-4 transition-transform ${showHistory ? 'rotate-90' : ''}`} />
          </button>
        </div>
      )}

      {/* Deployment History List */}
      {showHistory && deploymentHistory.length > 0 && (
        <div className="bg-white dark:bg-dark-800 border border-gray-200 dark:border-dark-600 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Previous Deployments</h3>
          <div className="space-y-3">
            {deploymentHistory.map((deployment, index) => (
              <div
                key={index}
                className={`p-4 border rounded-lg cursor-pointer transition-all ${deployResult === deployment
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-dark-600 hover:border-gray-300 dark:hover:border-dark-500'
                  }`}
                onClick={() => {
                  setDeployResult(deployment);
                  setDeploymentHidden(false);
                  if (deployment.dns_ipv4) {
                    checkServerStatus(deployment.dns_ipv4, deployment.dns_port);
                  }
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Server className="w-5 h-5 text-gray-400" />
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">{deployment.dns_ipv4}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {deployment.message}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {deployment.wireguard_installed && (
                      <span className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs rounded">
                        WireGuard
                      </span>
                    )}
                    {deployment.doh_url && (
                      <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs rounded">
                        DoH
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Deploy Result - if success */}
      {deployResult && deployResult.success && !deploymentHidden && (
        <div ref={deployResultRef} className={`border rounded-xl p-6 ${serverStatus === 'online'
          ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
          : serverStatus === 'offline'
            ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
            : 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
          }`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center ${serverStatus === 'online' ? 'bg-green-500' : serverStatus === 'offline' ? 'bg-yellow-500' : 'bg-blue-500'
                }`}>
                {serverStatus === 'offline' ? (
                  <AlertTriangle className="w-6 h-6 text-white" />
                ) : serverStatus === 'online' ? (
                  <CheckCircle className="w-6 h-6 text-white" />
                ) : (
                  <Server className="w-6 h-6 text-white" />
                )}
              </div>
              <div>
                <h3 className={`font-semibold ${serverStatus === 'online'
                  ? 'text-green-800 dark:text-green-200'
                  : serverStatus === 'offline'
                    ? 'text-yellow-800 dark:text-yellow-200'
                    : 'text-blue-800 dark:text-blue-200'
                  }`}>
                  {serverStatus === 'online'
                    ? 'Personal DNS Online'
                    : serverStatus === 'offline'
                      ? 'Encrypted DNS Health Check Failed'
                      : serverStatus === 'restricted'
                        ? 'Status Requires VPS Access'
                        : 'Personal DNS Deployed'}
                </h3>
                <div className="flex items-center gap-2">
                  <p className={`text-sm ${serverStatus === 'online'
                    ? 'text-green-700 dark:text-green-300'
                    : serverStatus === 'offline'
                      ? 'text-yellow-700 dark:text-yellow-300'
                      : 'text-blue-700 dark:text-blue-300'
                    }`}>
                    {serverStatus === 'offline'
                      ? 'Neither DoT nor DoH returned a valid encrypted DNS response.'
                      : serverStatus === 'online'
                        ? 'A real encrypted DNS query completed successfully.'
                        : serverStatus === 'restricted'
                          ? 'Public DNS is restricted and no encrypted domain is available for a remote probe.'
                          : 'Use Check Status to run an encrypted DNS health probe.'
                    }
                  </p>
                  {isCheckingStatus && (
                    <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                  )}
                </div>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => deployResult.dns_ipv4 && checkServerStatus(deployResult.dns_ipv4, deployResult.dns_port, true)}
                disabled={isCheckingStatus}
                className="px-3 py-1.5 text-sm bg-white dark:bg-dark-700 border border-gray-200 dark:border-dark-600 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-600 flex items-center gap-1"
              >
                {isCheckingStatus ? <Loader2 className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />}
                Check Status
              </button>
              <button
                onClick={() => openManage()}
                className="px-3 py-1.5 text-sm bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50 flex items-center gap-1"
                title="Open Personal DNS settings"
              >
                <Settings className="w-4 h-4" />
                Manage
              </button>
              <button
                onClick={() => {
                  openManage();
                  toast('Enter the VPS SSH credential, then click Remove Personal DNS');
                }}
                className="px-3 py-1.5 text-sm bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50 flex items-center gap-1"
                title="Open the safe Personal DNS removal controls"
              >
                <Trash2 className="w-4 h-4" />
                Remove
              </button>
              <button
                onClick={clearDeployment}
                className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-dark-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-dark-600"
                title="Dismiss this card without changing the VPS"
              >
                Dismiss
              </button>
            </div>
          </div>

          {serverStatus === 'offline' && (
            <div className="mb-4 p-3 bg-yellow-100 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700 rounded-lg">
              <p className="text-sm text-yellow-800 dark:text-yellow-200">
                <strong>Possible reasons:</strong>
              </p>
              <ul className="text-sm text-yellow-700 dark:text-yellow-300 mt-1 list-disc list-inside">
                <li>Server is rebooting or shut down</li>
                <li>NetProtection service stopped</li>
                <li>DoT/DoH certificate or nginx routing failed</li>
                <li>Ports 8443 and 853 are blocked upstream</li>
              </ul>
            </div>
          )}

          {statusDetails.length > 0 && (
            <div className="mb-4 rounded-lg border border-gray-200 dark:border-dark-700 bg-white/70 dark:bg-dark-900/30 p-3">
              <ul className="text-xs text-gray-600 dark:text-gray-300 space-y-1">
                {statusDetails.map((detail, index) => <li key={index}>• {detail}</li>)}
              </ul>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {deployResult.dns_ipv4 && (
              <div className="bg-white dark:bg-dark-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">
                  {deployResult.dns_port === '53' ? 'Direct DNS IPv4' : 'VPS IPv4 (public DNS restricted)'}
                </p>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-gray-900 dark:text-white">{deployResult.dns_ipv4}</p>
                  <button onClick={() => copyToClipboard(deployResult.dns_ipv4!, 'dns_ipv4')} className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded">
                    {copiedField === 'dns_ipv4' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
                  </button>
                </div>
              </div>
            )}
            {deployResult.vpn_dns && (
              <div className="bg-white dark:bg-dark-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">VPN DNS (Encrypted)</p>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-gray-900 dark:text-white">{deployResult.vpn_dns}</p>
                  <button onClick={() => copyToClipboard(deployResult.vpn_dns!, 'vpn_dns')} className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded">
                    {copiedField === 'vpn_dns' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
                  </button>
                </div>
              </div>
            )}
            {deployResult.doh_url && (
              <div className="bg-white dark:bg-dark-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">DoH URL</p>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-gray-900 dark:text-white text-sm truncate mr-2">{deployResult.doh_url}</p>
                  <button onClick={() => copyToClipboard(deployResult.doh_url!, 'doh_url')} className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded flex-shrink-0">
                    {copiedField === 'doh_url' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
                  </button>
                </div>
              </div>
            )}
            {deployResult.dot_url && (
              <div className="bg-white dark:bg-dark-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">DoT</p>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-gray-900 dark:text-white">{deployResult.dot_url}</p>
                  <button onClick={() => copyToClipboard(deployResult.dot_url!, 'dot_url')} className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded">
                    {copiedField === 'dot_url' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
                  </button>
                </div>
              </div>
            )}
            {deployResult.admin_panel && (
              <div className="bg-white dark:bg-dark-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Admin Panel</p>
                <div className="flex items-center justify-between">
                  <p className="font-mono text-gray-900 dark:text-white text-sm truncate mr-2">{deployResult.admin_panel}</p>
                  <div className="flex gap-1 flex-shrink-0">
                    <button onClick={() => copyToClipboard(deployResult.admin_panel!, 'admin_panel')} className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded">
                      {copiedField === 'admin_panel' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4 text-gray-400" />}
                    </button>
                    <a href={deployResult.admin_panel} target="_blank" rel="noopener noreferrer" className="p-1.5 hover:bg-gray-100 dark:hover:bg-dark-700 rounded">
                      <ExternalLink className="w-4 h-4 text-gray-400" />
                    </a>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Connection Methods Comparison Table */}
          <div className="mt-6 bg-white dark:bg-dark-800 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 dark:text-white mb-4 flex items-center gap-2">
              📊 Connection Methods Comparison
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-dark-600">
                    <th className="text-left py-2 px-3 font-medium text-gray-700 dark:text-gray-300">Method</th>
                    <th className="text-center py-2 px-3 font-medium text-gray-700 dark:text-gray-300">Need App?</th>
                    <th className="text-center py-2 px-3 font-medium text-gray-700 dark:text-gray-300">Change DNS?</th>
                    <th className="text-center py-2 px-3 font-medium text-gray-700 dark:text-gray-300">Encrypted?</th>
                    <th className="text-center py-2 px-3 font-medium text-gray-700 dark:text-gray-300">Blocks Ads?</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-dark-700">
                  <tr className="bg-green-50 dark:bg-green-900/20">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">🔐</span>
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">WireGuard VPN</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">Recommended</p>
                        </div>
                      </div>
                    </td>
                    <td className="text-center py-3 px-3"><span className="text-green-600">WireGuard app</span></td>
                    <td className="text-center py-3 px-3"><span className="text-green-600">❌ Auto</span></td>
                    <td className="text-center py-3 px-3"><span className="text-green-600">✅ Full</span></td>
                    <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                  </tr>
                  {deployResult.doh_url && (
                    <tr>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          <span className="text-lg">🔗</span>
                          <div>
                            <p className="font-medium text-gray-900 dark:text-white">DoH (DNS-over-HTTPS)</p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Browser/System</p>
                          </div>
                        </div>
                      </td>
                      <td className="text-center py-3 px-3"><span className="text-gray-600 dark:text-gray-400">❌ No</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600 dark:text-green-400">✅ Yes</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                    </tr>
                  )}
                  {deployResult.dot_url && (
                    <tr>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          <span className="text-lg">🔒</span>
                          <div>
                            <p className="font-medium text-gray-900 dark:text-white">DoT (DNS-over-TLS)</p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Android 9+ / iOS 14+</p>
                          </div>
                        </div>
                      </td>
                      <td className="text-center py-3 px-3"><span className="text-gray-600 dark:text-gray-400">❌ No</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600 dark:text-green-400">✅ Yes</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                      <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                    </tr>
                  )}
                  {deployResult.dns_port === '53' && <tr>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">📡</span>
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">Plain DNS</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">Any device</p>
                        </div>
                      </div>
                    </td>
                    <td className="text-center py-3 px-3"><span className="text-gray-600 dark:text-gray-400">❌ No</span></td>
                    <td className="text-center py-3 px-3"><span className="text-green-600 dark:text-green-400">✅ Yes</span></td>
                    <td className="text-center py-3 px-3"><span className="text-red-600">❌ No</span></td>
                    <td className="text-center py-3 px-3"><span className="text-green-600">✅ Yes</span></td>
                  </tr>}
                </tbody>
              </table>
            </div>
          </div>

          {/* WireGuard Config */}
          {deployResult.wireguard_config && (
            <div className="mt-4 bg-white dark:bg-dark-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">🔒 WireGuard VPN Config</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">Use this config to connect via encrypted VPN</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => copyToClipboard(deployResult.wireguard_config!, 'wg_config')}
                    className="px-3 py-1.5 bg-gray-100 dark:bg-dark-700 hover:bg-gray-200 dark:hover:bg-dark-600 rounded-lg text-sm flex items-center gap-1"
                  >
                    {copiedField === 'wg_config' ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                    Copy
                  </button>
                  <button
                    onClick={() => {
                      const blob = new Blob([deployResult.wireguard_config!], { type: 'text/plain' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'wg-dns-client.conf';
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="px-3 py-1.5 bg-primary-500 hover:bg-primary-600 text-white rounded-lg text-sm flex items-center gap-1"
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                </div>
              </div>

              {/* Config and QR Code side by side */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Config file:</p>
                  <pre className="bg-gray-50 dark:bg-dark-900 rounded-lg p-3 text-xs font-mono text-gray-800 dark:text-gray-200 overflow-x-auto h-48 overflow-y-auto">
                    {deployResult.wireguard_config}
                  </pre>
                </div>
                <div className="flex flex-col items-center justify-center">
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">📱 Scan with WireGuard app:</p>
                  {qrCodeUrl ? (
                    <div className="bg-white p-3 rounded-lg shadow-sm">
                      <img src={qrCodeUrl} alt="WireGuard QR Code" className="w-48 h-48" />
                    </div>
                  ) : (
                    <div className="w-48 h-48 bg-gray-100 dark:bg-dark-700 rounded-lg flex items-center justify-center">
                      <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
                    </div>
                  )}
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 text-center">
                    Open WireGuard app → "+" → "Scan from QR code"
                  </p>
                </div>
              </div>

              {/* Step-by-step instructions */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                <p className="font-medium text-blue-800 dark:text-blue-200 mb-3">📋 How to connect (step by step):</p>
                <div className="space-y-3">
                  <div className="flex gap-3">
                    <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0">1</div>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">Download WireGuard app</p>
                      <div className="flex flex-wrap gap-2 mt-1">
                        <a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-gray-100 dark:bg-dark-700 rounded hover:bg-gray-200 dark:hover:bg-dark-600 flex items-center gap-1">
                          🍎 iPhone/iPad
                        </a>
                        <a href="https://play.google.com/store/apps/details?id=com.wireguard.android" target="_blank" rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-gray-100 dark:bg-dark-700 rounded hover:bg-gray-200 dark:hover:bg-dark-600 flex items-center gap-1">
                          🤖 Android
                        </a>
                        <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-gray-100 dark:bg-dark-700 rounded hover:bg-gray-200 dark:hover:bg-dark-600 flex items-center gap-1">
                          💻 Windows/Mac/Linux
                        </a>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-3">
                    <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0">2</div>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">Add the config file</p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        <span className="font-medium">Phone:</span> Click "Download" above → Open file → "Open in WireGuard"<br />
                        <span className="font-medium">PC:</span> Click "Download" above → Open WireGuard → "Import tunnel(s) from file"
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-3">
                    <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0">3</div>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">Connect!</p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Toggle the switch ON. All your internet traffic is now encrypted and ads are blocked!
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mt-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <p className="text-sm text-green-800 dark:text-green-200">
                    ✅ <span className="font-medium">Done!</span> When connected, your DNS is <code className="bg-green-100 dark:bg-green-900 px-1 rounded">10.66.66.1</code> —
                    all requests go through encrypted VPN to your NetProtection server.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Warnings */}
          {visibleWarnings.length > 0 && (
            <div className="mt-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                <p className="font-medium text-yellow-800 dark:text-yellow-200">Warnings</p>
              </div>
              <ul className="space-y-1">
                {visibleWarnings.map((warning, idx) => (
                  <li key={idx} className="text-sm text-yellow-700 dark:text-yellow-300 flex items-start gap-2">
                    <span>•</span>
                    <span>{warning}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {deployResult.recommendations && deployResult.recommendations.length > 0 && (
            <div className="mt-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Lightbulb className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <p className="font-medium text-blue-800 dark:text-blue-200">Recommendations</p>
              </div>
              <div className="space-y-3">
                {deployResult.recommendations.map((rec) => (
                  <div
                    key={rec.id}
                    className={`p-3 rounded-lg border ${rec.priority === 'high'
                      ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                      : rec.priority === 'medium'
                        ? 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800'
                        : 'bg-gray-50 dark:bg-dark-800 border-gray-200 dark:border-dark-700'
                      }`}
                  >
                    <div className="flex items-start gap-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${rec.priority === 'high'
                        ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300'
                        : rec.priority === 'medium'
                          ? 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300'
                          : 'bg-gray-100 dark:bg-dark-700 text-gray-600 dark:text-gray-400'
                        }`}>
                        {rec.priority === 'high' ? 'Important' : rec.priority === 'medium' ? 'Recommended' : 'Tip'}
                      </span>
                    </div>
                    <p className="font-medium text-gray-900 dark:text-white mt-2">{rec.title}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{rec.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Visual Diagrams Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* WireGuard VPN + DNS Diagram */}
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
          <div className="flex items-center gap-2 mb-3">
            <Wifi className="w-5 h-5 text-blue-500" />
            <h3 className="font-semibold text-gray-900 dark:text-white">🔐 VPN + DNS</h3>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Connect via WireGuard VPN — all DNS traffic encrypted inside VPN tunnel. No domain required.
          </p>

          {/* Visual Flow */}
          <div className="flex items-center justify-between gap-1 p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">📱</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">Device</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🔒</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">WireGuard</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🛡️</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">NetProtection</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🌍</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">Internet</span>
            </div>
          </div>
        </div>

        {/* Encrypted DNS Diagram */}
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
          <div className="flex items-center gap-2 mb-3">
            <Lock className="w-5 h-5 text-primary-500" />
            <h3 className="font-semibold text-gray-900 dark:text-white">🔗 DoH / DoT</h3>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Use DNS-over-HTTPS or DNS-over-TLS with your domain. Works with any device without VPN.
          </p>

          {/* Visual Flow */}
          <div className="flex items-center justify-between gap-1 p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">📱</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">Device</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🔒</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">HTTPS</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🛡️</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">NetProtection</span>
            </div>
            <ArrowRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-xl mb-1">🌍</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">Internet</span>
            </div>
          </div>
        </div>

        {/* Ad Blocking Diagram */}
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-red-500" />
            <h3 className="font-semibold text-gray-900 dark:text-white">🛡️ Ad & Tracker Blocking</h3>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Block ads, trackers, malware domains at DNS level.
            Works without browser extensions on devices configured to use this DNS service.
          </p>

          {/* Visual Flow */}
          <div className="flex items-center justify-between gap-2 p-4 bg-gray-50 dark:bg-dark-900 rounded-lg">
            <div className="flex flex-col items-center text-center">
              <span className="text-2xl mb-1">📺</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">Ad Request</span>
            </div>
            <ArrowRight className="w-5 h-5 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center">
              <span className="text-2xl mb-1">🛡️</span>
              <span className="text-xs text-gray-600 dark:text-gray-400">NetProtection</span>
            </div>
            <ArrowRight className="w-5 h-5 text-gray-400 flex-shrink-0" />
            <div className="flex flex-col items-center text-center bg-red-100 dark:bg-red-900/30 rounded-lg px-3 py-2">
              <span className="text-2xl mb-1">❌</span>
              <span className="text-xs text-red-600 dark:text-red-400 font-medium">Blocked</span>
            </div>
          </div>
        </div>
      </div>

      {/* Deploy Button Card */}
      <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Deploy to Remote VPS</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Install NetProtection on a remote server via SSH (for external DNS access)
            </p>
          </div>
          <button
            onClick={() => openManage(null)}
            className="px-6 py-3 bg-gray-500 hover:bg-gray-600 text-white rounded-xl font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            <Settings className="w-5 h-5" />
            Configure & Deploy
          </button>
        </div>
      </div>

      {/* How to Use Section */}
      <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 overflow-hidden">
        <div className="p-6 border-b border-gray-200 dark:border-dark-700">
          <h3 className="font-semibold text-gray-900 dark:text-white">⚙️ How to Use Personal DNS</h3>
        </div>
        <div className="p-6 bg-gray-50 dark:bg-dark-900">
          <div className="space-y-4 text-sm text-gray-600 dark:text-gray-400">
            <div className="flex items-start gap-3">
              <span className="w-6 h-6 bg-primary-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">1</span>
              <p>Click "Configure & Deploy" and enter your VPS credentials</p>
            </div>
            <div className="flex items-start gap-3">
              <span className="w-6 h-6 bg-primary-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">2</span>
              <p>Wait for automatic installation (~2-5 minutes)</p>
            </div>
            <div className="flex items-start gap-3">
              <span className="w-6 h-6 bg-primary-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">3</span>
              <p>Copy DNS addresses and configure your devices:
                <br />• <strong>Android Private DNS:</strong> use the DoT hostname
                <br />• <strong>iPhone:</strong> use WireGuard or an installed DoH profile
                <br />• <strong>Browser:</strong> Settings → Privacy → DNS over HTTPS → Custom
                <br />• <strong>Computer/router:</strong> use the VPS IP only when its public source IP is allowlisted
              </p>
            </div>
            <div className="flex items-start gap-3">
              <span className="w-6 h-6 bg-primary-500 text-white rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0">4</span>
              <p>Return to EasyPi to check status, manage access or remove Personal DNS</p>
            </div>
          </div>
        </div>
      </div>

      {/* Requirements */}
      <div className="bg-white dark:bg-dark-800 rounded-xl border border-gray-200 dark:border-dark-700 p-6">
        <h3 className="font-semibold text-gray-900 dark:text-white mb-4">📋 Requirements</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <CheckCircle className="w-4 h-4 text-green-500" />
            VPS with a supported Ubuntu or Debian release
          </div>
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <CheckCircle className="w-4 h-4 text-green-500" />
            Root or sudo access via SSH
          </div>
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <CheckCircle className="w-4 h-4 text-green-500" />
            Ports 80/TCP, 853/TCP, 8443/TCP and 51820/UDP reachable
          </div>
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <CheckCircle className="w-4 h-4 text-green-500" />
            Separate domain for trusted DoH/DoT TLS
          </div>
        </div>
      </div>

      {/* Deploy Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-dark-800 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200 dark:border-dark-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Deploy DNS Server</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Enter your VPS credentials</p>
            </div>

            {isDeploying ? (
              <div className="p-8">
                <div className="flex flex-col items-center">
                  <Loader2 className="w-12 h-12 text-primary-500 animate-spin mb-4" />
                  <p className="text-center text-gray-700 dark:text-gray-300 mb-2">
                    Deploying and validating the DNS server on the VPS...
                  </p>
                  <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-2">
                    This can take up to 25 minutes. The remote installer reports only its final result, so no stage or percentage is inferred.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-6 space-y-4">
                {/* VPS IP */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    VPS IP Address <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={formData.vps_ip}
                    onChange={(e) => setFormData({ ...formData, vps_ip: e.target.value })}
                    placeholder="123.45.67.89"
                    className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                </div>

                {/* SSH User & Port */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">SSH User</label>
                    <input
                      type="text"
                      value={formData.ssh_user}
                      onChange={(e) => setFormData({ ...formData, ssh_user: e.target.value })}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">SSH Port</label>
                    <input
                      type="text"
                      value={formData.ssh_port}
                      onChange={(e) => setFormData({ ...formData, ssh_port: e.target.value })}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                </div>

                {/* Auth Method */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Authentication</label>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setFormData({ ...formData, auth_method: 'password' })}
                      className={`flex-1 py-2 px-4 rounded-lg border transition-colors ${formData.auth_method === 'password'
                        ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                        : 'border-gray-300 dark:border-dark-600 text-gray-600 dark:text-gray-400'
                        }`}
                    >
                      Password
                    </button>
                    <button
                      type="button"
                      onClick={() => setFormData({ ...formData, auth_method: 'key' })}
                      className={`flex-1 py-2 px-4 rounded-lg border transition-colors ${formData.auth_method === 'key'
                        ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                        : 'border-gray-300 dark:border-dark-600 text-gray-600 dark:text-gray-400'
                        }`}
                    >
                      SSH Key
                    </button>
                  </div>
                </div>

                {/* Password or Key */}
                {formData.auth_method === 'password' ? (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      SSH Password <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={formData.ssh_password}
                        onChange={(e) => setFormData({ ...formData, ssh_password: e.target.value })}
                        className="w-full px-4 py-2 pr-10 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Private Key <span className="text-red-500">*</span>
                    </label>
                    <textarea
                      value={formData.ssh_key}
                      onChange={(e) => setFormData({ ...formData, ssh_key: e.target.value })}
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                      rows={4}
                      className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 font-mono text-xs"
                    />
                  </div>
                )}

                {/* Domain */}
                <div className="space-y-3 rounded-lg border border-blue-200 dark:border-blue-900 bg-blue-50/60 dark:bg-blue-950/20 p-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Separate DNS domain <span className="text-gray-400 font-normal">(optional, for DoH / DoT)</span>
                  </label>
                  <input
                    type="text"
                    value={formData.domain}
                    onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                    placeholder="mydns.duckdns.org"
                    className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                  <p className="text-xs text-blue-700 dark:text-blue-300">
                    Use a hostname different from Chameleon. Both names may point to the same VPS. Chameleon keeps HTTPS port 443; Personal DNS uses DoH on 8443 and standard Android Private DNS (DoT) on 853.
                  </p>
                  <a
                    href="https://www.duckdns.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 dark:text-blue-300 hover:underline"
                  >
                    Get a separate DuckDNS name and token <ExternalLink className="w-3 h-3" />
                  </a>
                  {formData.domain.toLowerCase().endsWith('.duckdns.org') && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        DuckDNS token <span className="text-gray-400 font-normal">(needed only to update the DNS record automatically)</span>
                      </label>
                      <input
                        type="password"
                        autoComplete="off"
                        value={formData.duckdns_token}
                        onChange={(e) => setFormData({ ...formData, duckdns_token: e.target.value })}
                        placeholder="DuckDNS token"
                        className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                      />
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                        The token is used for this deployment request only and is cleared from the browser form after success.
                      </p>
                    </div>
                  )}
                  {formData.domain && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Certificate email <span className="text-gray-400 font-normal">(optional)</span>
                      </label>
                      <input
                        type="email"
                        value={formData.certificate_email}
                        onChange={(e) => setFormData({ ...formData, certificate_email: e.target.value })}
                        placeholder={`admin@${formData.domain || 'example.com'}`}
                        className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                      />
                    </div>
                  )}
                </div>

                <div className="rounded-lg border border-amber-200 dark:border-amber-900 bg-amber-50/60 dark:bg-amber-950/20 p-4">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Direct DNS — allowed computer public IPs <span className="text-gray-400 font-normal">(optional)</span>
                  </label>
                  <textarea
                    value={formData.allowed_client_ips}
                    onChange={(e) => setFormData({ ...formData, allowed_client_ips: e.target.value })}
                    placeholder="203.0.113.10"
                    rows={2}
                    className="w-full px-4 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 font-mono text-sm"
                  />
                  <p className="mt-1 text-xs text-amber-800 dark:text-amber-300">
                    Only these public IPv4 addresses may use plain TCP/UDP DNS on port 53. Leave empty to block public DNS and use WireGuard or DoH/DoT only.
                  </p>
                </div>

                {/* Error */}
                {error && (
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <div className="flex items-center gap-2 text-red-700 dark:text-red-300 text-sm">
                      <AlertCircle className="w-4 h-4" />
                      {error}
                    </div>
                  </div>
                )}
              </div>
            )}

            {!isDeploying && (
              <div className="p-6 border-t border-gray-200 dark:border-dark-700 space-y-4">
                <ActionPreviewPanel
                  preview={dnsDeployPreviewQuery.data}
                  isLoading={dnsDeployPreviewQuery.isLoading || dnsDeployPreviewQuery.isFetching}
                  errorMessage={dnsDeployPreviewQuery.error instanceof Error ? dnsDeployPreviewQuery.error.message : null}
                />

                <div className="rounded-lg border border-gray-200 dark:border-dark-700 p-4 space-y-3" data-testid="dns-ssh-identity">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 text-sm font-medium text-gray-900 dark:text-white">
                        <Shield className="w-4 h-4 text-sky-600" />
                        SSH server identity
                      </div>
                      <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                        This checks only the VPS host key. It does not test the username, password or private key.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => inspectSSHIdentity()}
                      disabled={isInspectingHostKey || isTrustingHostKey || !formData.vps_ip}
                      className="inline-flex shrink-0 items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg border border-sky-300 dark:border-sky-800 text-sky-700 dark:text-sky-300 hover:bg-sky-50 dark:hover:bg-sky-900/20 disabled:opacity-50"
                    >
                      {isInspectingHostKey ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                      Check server key
                    </button>
                  </div>

                  {sshHostKey && (
                    <div className={`rounded-lg border p-3 text-xs ${
                      sshHostKey.trust_status === 'trusted'
                        ? 'border-green-300 bg-green-50 text-green-900 dark:border-green-800 dark:bg-green-900/20 dark:text-green-200'
                        : sshHostKey.trust_status === 'changed'
                          ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200'
                          : 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200'
                    }`} data-testid={`dns-ssh-identity-${sshHostKey.trust_status}`}>
                      <div className="flex items-center gap-2 font-semibold">
                        {sshHostKey.trust_status === 'trusted' && <CheckCircle className="w-4 h-4" />}
                        {sshHostKey.trust_status === 'changed' && <AlertTriangle className="w-4 h-4" />}
                        {sshHostKey.trust_status === 'unknown' && <AlertCircle className="w-4 h-4" />}
                        {sshHostKey.trust_status === 'trusted'
                          ? 'Trusted VPS host key'
                          : sshHostKey.trust_status === 'changed'
                            ? 'SSH HOST KEY CHANGED — DEPLOYMENT BLOCKED'
                            : 'New SSH identity — verification required'}
                      </div>
                      <div className="mt-2 space-y-1">
                        <p>Endpoint: <span className="font-mono">{sshHostKey.host}:{sshHostKey.port}</span></p>
                        <p>Key: <span className="font-mono">{sshHostKey.key_type}{sshHostKey.bits ? ` · ${sshHostKey.bits} bits` : ''}</span></p>
                        <p className="break-all">Fingerprint: <span className="font-mono font-semibold" data-testid="dns-ssh-fingerprint">{sshHostKey.fingerprint}</span></p>
                        {sshHostKey.trust_status === 'changed' && sshHostKey.trusted_fingerprint && (
                          <p className="break-all">Previously trusted: <span className="font-mono">{sshHostKey.trusted_fingerprint}</span></p>
                        )}
                      </div>
                      {sshHostKey.trust_status === 'unknown' && (
                        <div className="mt-3 space-y-2">
                          <p>
                            Compare this SHA-256 fingerprint with the VPS provider console. Trust it only when they match exactly.
                          </p>
                          <button
                            type="button"
                            onClick={trustSSHIdentity}
                            disabled={isTrustingHostKey || isInspectingHostKey}
                            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-medium disabled:opacity-50"
                            data-testid="dns-trust-host-key"
                          >
                            {isTrustingHostKey ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                            I verified it — trust this key
                          </button>
                        </div>
                      )}
                      {sshHostKey.trust_status === 'trusted' && (
                        <div className="mt-3 border-t border-green-300/70 dark:border-green-800 pt-3 space-y-2">
                          <div className={`flex items-center gap-2 font-medium ${
                            sshAuthStatus === 'success'
                              ? 'text-green-700 dark:text-green-300'
                              : sshAuthStatus === 'failed'
                                ? 'text-red-700 dark:text-red-300'
                                : 'text-gray-700 dark:text-gray-300'
                          }`} data-testid={`dns-ssh-auth-${sshAuthStatus}`}>
                            {sshAuthStatus === 'checking' && <Loader2 className="w-4 h-4 animate-spin" />}
                            {sshAuthStatus === 'success' && <CheckCircle className="w-4 h-4" />}
                            {sshAuthStatus === 'failed' && <AlertCircle className="w-4 h-4" />}
                            {sshAuthStatus === 'success'
                              ? 'SSH login verified'
                              : sshAuthStatus === 'failed'
                                ? 'SSH login failed'
                                : sshAuthStatus === 'checking'
                                  ? 'Testing SSH login...'
                                  : 'SSH login not tested'}
                          </div>
                          <button
                            type="button"
                            onClick={checkSSHCredentials}
                            disabled={sshAuthStatus === 'checking' || (formData.auth_method === 'password' ? !formData.ssh_password : !formData.ssh_key)}
                            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-green-400 dark:border-green-700 text-green-800 dark:text-green-200 hover:bg-green-100 dark:hover:bg-green-900/30 disabled:opacity-50"
                            data-testid="dns-check-ssh-credentials"
                          >
                            {sshAuthStatus === 'checking' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                            Test SSH login
                          </button>
                        </div>
                      )}
                      {sshHostKey.trust_status === 'changed' && (
                        <p className="mt-3 font-medium">
                          Do not continue. Check the VPS provider console or investigate a possible server rebuild or MITM attack.
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {/* Cleanup Result */}
                {cleanupResult && cleanupResult.success && (
                  <div className="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                    <div className="flex items-center gap-2 mb-1">
                      <Trash2 className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                      <span className="text-sm font-medium text-blue-800 dark:text-blue-200">Cleanup Completed</span>
                    </div>
                    {cleanupResult.disk_usage && (
                      <div className="text-sm text-blue-700 dark:text-blue-300">
                        <span className="font-medium">Disk: </span>
                        {cleanupResult.disk_usage.used} / {cleanupResult.disk_usage.total} ({cleanupResult.disk_usage.percent} used)
                        <span className="mx-2">•</span>
                        <span className="text-green-600 dark:text-green-400">{cleanupResult.disk_usage.available} free</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Cleanup Server Button */}
                <div className="space-y-2">
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    SSH credentials are never stored. Enter the VPS password or private key above again before removal.
                  </p>
                  <div className="flex items-center gap-2">
                  <button
                    onClick={handleCleanup}
                    disabled={isCleaningUp}
                    className="flex items-center gap-2 px-4 py-2 text-sm bg-gray-100 dark:bg-dark-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {isCleaningUp ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                    Remove Personal DNS
                  </button>
                  <div className="relative group">
                    <HelpCircle className="w-4 h-4 text-gray-400 cursor-help" />
                    <div className="absolute left-6 bottom-0 w-64 p-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                      Removes only the Personal DNS container, firewall rules and managed nginx route. Chameleon, Docker and system logs are preserved.
                    </div>
                  </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowModal(false)}
                    className="flex-1 py-2 px-4 border border-gray-300 dark:border-dark-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDeploy}
                    disabled={isInspectingHostKey || isTrustingHostKey || !formData.vps_ip || (formData.auth_method === 'password' ? !formData.ssh_password : !formData.ssh_key)}
                    className="flex-1 py-2 px-4 bg-primary-500 hover:bg-primary-600 disabled:bg-gray-400 text-white rounded-lg font-medium flex items-center justify-center gap-2 transition-colors"
                  >
                    {isInspectingHostKey ? <Loader2 className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />}
                    Deploy
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default PersonalDNS;
