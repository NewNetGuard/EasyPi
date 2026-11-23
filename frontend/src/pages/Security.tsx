/**
 * Security Page
 * 
 * Security scanning, vulnerability fixes, and firewall management.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, RefreshCw, Lock, FileText } from 'lucide-react';
import { toast } from 'react-hot-toast';
import Modal from '../components/common/Modal';
import ActionPreviewPanel from '../features/actions/ActionPreviewPanel';
import useActionPreview from '../features/actions/useActionPreview';
import type { ActionPreviewId } from '../api/actionPreview';
import {
  runSecurityScan,
  fixDefaultPassword,
  fixSshRootLogin,
  startOutdatedPackagesFix,
  getOutdatedPackagesFixStatus,
  fixFirewall,
  fixPasswordAuth,
  fixFilesystemReadonly,
  cancelFix,
  getAuditLogs,
  SecurityScanResponse,
  SecurityIssue,
  PasswordChangeRequest,
  AuditLogEntry
} from '../api/security';

const UPDATE_JOB_STORAGE_KEY = 'easypi_security_update_job';
const UPDATE_JOB_GRACE_MS = 2 * 60 * 1000;
const UPDATE_JOB_ERROR_GRACE_MS = 10 * 60 * 1000;
const UPDATE_JOB_MAX_ERRORS = 10;
const FIXABLE_ISSUE_IDS = new Set([
  'default_password',
  'outdated_packages',
  'firewall_inactive',
  'ssh_root_login',
  'password_auth_enabled',
  'filesystem_readonly',
]);

const ACTION_PREVIEW_BY_ISSUE: Partial<Record<string, ActionPreviewId>> = {
  outdated_packages: 'security.fix_outdated_packages',
  firewall_inactive: 'security.fix_firewall',
  ssh_root_login: 'security.fix_ssh_root_login',
  password_auth_enabled: 'security.fix_password_auth',
  filesystem_readonly: 'security.fix_filesystem_readonly',
};

type StoredUpdateJob = { jobId: string; startedAt: number };

const readStoredUpdateJob = (): StoredUpdateJob | null => {
  const raw = localStorage.getItem(UPDATE_JOB_STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.jobId === 'string') {
      return {
        jobId: parsed.jobId,
        startedAt: typeof parsed.startedAt === 'number' ? parsed.startedAt : Date.now(),
      };
    }
  } catch {
    // fallthrough
  }
  return { jobId: raw, startedAt: Date.now() };
};

const writeStoredUpdateJob = (jobId: string, startedAt: number) => {
  localStorage.setItem(UPDATE_JOB_STORAGE_KEY, JSON.stringify({ jobId, startedAt }));
};

const reloadSecurityPage = (delayMs: number = 1500) => {
  window.setTimeout(() => {
    window.location.reload();
  }, delayMs);
};

export default function Security() {
  const [scanData, setScanData] = useState<SecurityScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [fixingIssue, setFixingIssue] = useState<string | null>(null);
  const [fixProgress, setFixProgress] = useState(0);
  const [_showCancelButton, setShowCancelButton] = useState(false);
  const [showRebootModal, setShowRebootModal] = useState(false);
  const [rebootSeconds, setRebootSeconds] = useState(60);
  const [pendingPreviewIssueId, setPendingPreviewIssueId] = useState<string | null>(null);
  const [updateJobId, setUpdateJobId] = useState<string | null>(null);
  const [updateJobStartedAt, setUpdateJobStartedAt] = useState<number | null>(null);
  const [updateStatusMessage, setUpdateStatusMessage] = useState<string | null>(null);
  const [updateProgressReported, setUpdateProgressReported] = useState(false);
  const [updatePollErrors, setUpdatePollErrors] = useState(0);
  const updatePollRef = useRef<number | null>(null);
  const pollRequestInFlightRef = useRef(false);
  const pollUpdateStatusRef = useRef<(jobId: string) => Promise<void>>(async () => {});

  const isWithinUpdateGrace = useCallback((windowMs: number) => {
    if (!updateJobStartedAt) return false;
    return Date.now() - updateJobStartedAt < windowMs;
  }, [updateJobStartedAt]);
  
  // Password change modal
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordData, setPasswordData] = useState<PasswordChangeRequest>({
    username: 'sb',
    new_password: ''
  });

  // Audit logs
  const [showAuditLogsModal, setShowAuditLogsModal] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const previewActionId = pendingPreviewIssueId ? ACTION_PREVIEW_BY_ISSUE[pendingPreviewIssueId] ?? null : null;
  const fixPreviewQuery = useActionPreview(previewActionId, pendingPreviewIssueId, Boolean(previewActionId));

  // Load audit logs
  const loadAuditLogs = useCallback(async () => {
    setLoadingLogs(true);
    try {
      const response = await getAuditLogs(50);
      setAuditLogs(response.logs);
    } catch (error: any) {
      console.error('Failed to load audit logs:', error);
      // Don't show error toast - logs might not be available on all systems
    } finally {
      setLoadingLogs(false);
    }
  }, []);

  useEffect(() => {
    if (!showRebootModal) return;
    setRebootSeconds(60);
    const timer = setInterval(() => {
      setRebootSeconds(prev => {
        if (prev <= 1) {
          clearInterval(timer);
          window.location.reload();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [showRebootModal]);

  const scanSecurityData = useCallback(async (showSuccessToast: boolean) => {
    const scan = await runSecurityScan();
    setScanData(scan);
    const allIssues = [...scan.critical, ...scan.warnings];
    const missingFixes = allIssues.filter((issue) => issue.fixable && !FIXABLE_ISSUE_IDS.has(issue.id));
    if (missingFixes.length > 0) {
      console.warn('Security issues without fix handlers:', missingFixes.map((issue) => issue.id));
    }
    if (showSuccessToast) {
      toast.success('Security scan completed');
    }
  }, []);

  const handleScan = useCallback(async () => {
    setScanning(true);
    try {
      await scanSecurityData(true);
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Scan failed');
    } finally {
      setScanning(false);
    }
  }, [scanSecurityData]);

  const stopUpdatePolling = useCallback(() => {
    if (updatePollRef.current) {
      window.clearInterval(updatePollRef.current);
      updatePollRef.current = null;
    }
    pollRequestInFlightRef.current = false;
  }, []);

  const finalizeUpdate = useCallback(async (status: 'success' | 'error', message?: string) => {
    stopUpdatePolling();
    localStorage.removeItem(UPDATE_JOB_STORAGE_KEY);
    setUpdateJobId(null);
    setUpdateJobStartedAt(null);
    setUpdateStatusMessage(null);
    setUpdateProgressReported(false);
    setUpdatePollErrors(0);
    setShowCancelButton(false);
    setFixingIssue(null);
    if (status === 'success') {
      setFixProgress(100);
      toast.success(message || 'Packages updated successfully');
      reloadSecurityPage();
    } else {
      setFixProgress(0);
      toast.error(message || 'Package update failed');
    }
  }, [stopUpdatePolling]);

  const pollUpdateStatus = useCallback(async (jobId: string) => {
    try {
      const status = await getOutdatedPackagesFixStatus(jobId);
      setUpdatePollErrors(0);
      if (status.message) {
        setUpdateStatusMessage(status.message);
      }

      if (status.status === 'running') {
        if (typeof status.progress === 'number') {
          setUpdateProgressReported(true);
          setFixProgress(prev => Math.max(prev, Math.min(status.progress ?? 0, 99)));
        }
        return;
      }

      if (status.status === 'success') {
        await finalizeUpdate('success', status.message);
        return;
      }

      if (status.status === 'error') {
        if (isWithinUpdateGrace(UPDATE_JOB_ERROR_GRACE_MS)) {
          setUpdateStatusMessage(status.message || 'Update is starting...');
          return;
        }
        await finalizeUpdate('error', status.message);
        return;
      }

      // idle or unknown
      if (isWithinUpdateGrace(UPDATE_JOB_GRACE_MS)) {
        setUpdateStatusMessage(status.message || 'Starting package update...');
        return;
      }

      await finalizeUpdate('error', status.message || 'No update job running');
    } catch (error: any) {
      const httpStatus = error?.response?.status;
      // A server-side system update must NOT be aborted just because the
      // browser's short-lived (30 min) access token expired mid-upgrade. The
      // axios interceptor refreshes the session and the next poll reconnects;
      // the apt job keeps running on the server (its state is persisted), so
      // treat auth blips (401/403) as a transient reconnect, never a failure.
      if (httpStatus === 401 || httpStatus === 403) {
        setUpdateStatusMessage('Reconnecting (refreshing session)…');
        return;
      }
      setUpdatePollErrors(prev => {
        const next = prev + 1;
        if (isWithinUpdateGrace(UPDATE_JOB_ERROR_GRACE_MS) || next < UPDATE_JOB_MAX_ERRORS) {
          setUpdateStatusMessage('Connection lost. Retrying...');
          return next;
        }
        void finalizeUpdate('error', error?.response?.data?.detail || 'Failed to check update status');
        return next;
      });
    }
  }, [finalizeUpdate, isWithinUpdateGrace]);

  useEffect(() => {
    pollUpdateStatusRef.current = pollUpdateStatus;
  }, [pollUpdateStatus]);

  const startUpdatePolling = useCallback((jobId: string) => {
    stopUpdatePolling();
    setUpdatePollErrors(0);
    setUpdateJobStartedAt(prev => prev ?? Date.now());

    const runPoll = () => {
      if (pollRequestInFlightRef.current) {
        return;
      }
      pollRequestInFlightRef.current = true;
      void pollUpdateStatusRef.current(jobId).finally(() => {
        pollRequestInFlightRef.current = false;
      });
    };

    runPoll();
    updatePollRef.current = window.setInterval(runPoll, 4000);
  }, [stopUpdatePolling]);

  useEffect(() => {
    const storedJob = readStoredUpdateJob();
    if (storedJob && storedJob.jobId !== updateJobId) {
      setUpdateJobId(storedJob.jobId);
      setUpdateJobStartedAt(storedJob.startedAt);
      setFixingIssue('outdated_packages');
      setFixProgress(0);
      setUpdateProgressReported(false);
    }
  }, [updateJobId]);

  useEffect(() => {
    if (!updateJobId) {
      stopUpdatePolling();
      return;
    }
    startUpdatePolling(updateJobId);
    return () => stopUpdatePolling();
  }, [startUpdatePolling, stopUpdatePolling, updateJobId]);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      await scanSecurityData(false);
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to load security data');
    } finally {
      setLoading(false);
    }
  }, [scanSecurityData]);

  useEffect(() => {
    void loadData();
    void loadAuditLogs();
  }, [loadAuditLogs, loadData]);

  const executeFix = async (issueId: string) => {
    setFixingIssue(issueId);
    setFixProgress(0);
    setUpdateProgressReported(false);
    
    // Show cancel button and progress for package updates
    if (issueId === 'outdated_packages') {
      setShowCancelButton(true);

      try {
        const response = await startOutdatedPackagesFix();

        if (response.status === 'success' && response.job_id) {
          const startedAt = Date.now();
          setUpdateJobId(response.job_id);
          setUpdateJobStartedAt(startedAt);
          setUpdateStatusMessage(response.message || 'Package update started');
          writeStoredUpdateJob(response.job_id, startedAt);
          toast.success(response.message || 'Package update started');
          return;
        }

        if (response.status === 'error' && response.job_id) {
          const startedAt = Date.now();
          setUpdateJobId(response.job_id);
          setUpdateJobStartedAt(startedAt);
          setUpdateStatusMessage(response.message || 'Package update already running');
          writeStoredUpdateJob(response.job_id, startedAt);
          toast.error(response.message || 'Package update already running');
          return;
        }

        toast.error(response.message || 'Failed to start update');
        setUpdateStatusMessage(null);
        setFixingIssue(null);
        setFixProgress(0);
        setShowCancelButton(false);
      } catch (error: any) {
        toast.error(error.response?.data?.detail || 'Failed to start update');
        setUpdateStatusMessage(null);
        setFixingIssue(null);
        setFixProgress(0);
        setShowCancelButton(false);
      }
      return;
    }
    
    try {
      let response;
      
      switch (issueId) {
        case 'firewall_inactive':
          response = await fixFirewall();
          break;
        case 'ssh_root_login':
          response = await fixSshRootLogin();
          break;
        case 'password_auth_enabled':
          response = await fixPasswordAuth();
          break;
        case 'filesystem_readonly':
          response = await fixFilesystemReadonly();
          break;
        default:
          toast.error('Fix is not available for this issue in this version');
          console.warn('Fix handler missing for issue:', issueId);
          return;
      }
      
      if (response.status === 'success') {
        toast.success(response.message);
        if (issueId === 'filesystem_readonly') {
          setShowRebootModal(true);
        } else {
          reloadSecurityPage();
        }
      } else {
        toast.error(response.message);
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Fix failed');
    } finally {
      setFixingIssue(null);
    }
  };

  const handleFix = (issueId: string) => {
    if (issueId === 'default_password') {
      setShowPasswordModal(true);
      return;
    }

    if (ACTION_PREVIEW_BY_ISSUE[issueId]) {
      setPendingPreviewIssueId(issueId);
      return;
    }

    void executeFix(issueId);
  };

  const handleConfirmPreviewFix = () => {
    if (!pendingPreviewIssueId) return;
    const issueId = pendingPreviewIssueId;
    setPendingPreviewIssueId(null);
    void executeFix(issueId);
  };

  const _handleCancelFix = async () => {
    if (!fixingIssue) return;
    
    try {
      await cancelFix(fixingIssue);
      toast.success('Operation cancelled');
      setFixingIssue(null);
      setShowCancelButton(false);
      setFixProgress(0);
    } catch (error: any) {
      toast.error('Failed to cancel operation');
    }
  };

  const handlePasswordChange = async () => {
    if (!passwordData.new_password || passwordData.new_password.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }

    setFixingIssue('default_password');
    try {
      const response = await fixDefaultPassword(passwordData);
      if (response.status === 'success') {
        toast.success(response.message);
        setShowPasswordModal(false);
        setPasswordData({ username: 'sb', new_password: '' });
        reloadSecurityPage();
      } else {
        toast.error(response.message);
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Password change failed');
    } finally {
      setFixingIssue(null);
    }
  };

  const renderIssue = (issue: SecurityIssue) => {
    const isFixing = fixingIssue === issue.id;
    const badgeColor = issue.status === 'critical' ? 'bg-red-500/10 text-red-700 dark:text-red-400' : 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400';
    const iconColor = issue.status === 'critical' ? 'text-red-500 dark:text-red-400' : 'text-yellow-500 dark:text-yellow-400';
    const canFix = issue.fixable;

    return (
      <div key={issue.id} className="flex items-start gap-4 rounded-2xl border border-gray-200 bg-white p-5 shadow-sm dark:border-dark-700 dark:bg-dark-900">
        <div className={`mt-1 ${iconColor}`}>
          {issue.status === 'critical' ? (
            <AlertTriangle className="h-5 w-5" />
          ) : (
            <Shield className="h-5 w-5" />
          )}
        </div>
        
        <div className="flex-1">
          <div className="mb-1 flex items-center gap-2">
            <h3 className="font-semibold text-gray-900 dark:text-white">{issue.message}</h3>
            <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${badgeColor}`}>
              {issue.status}
            </span>
          </div>
          {issue.details && (
            <p className="text-sm text-gray-600 dark:text-gray-400">{issue.details}</p>
          )}
          
          {/* Progress bar for active fix */}
          {isFixing && issue.id === 'outdated_packages' && updateProgressReported && (
            <div className="mt-3">
              <div className="mb-1 flex items-center justify-between text-xs text-gray-600 dark:text-gray-400">
                <span>{updateStatusMessage || 'Updating packages...'}</span>
                <span>{fixProgress}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-gray-200 dark:bg-dark-700">
                <div 
                  className="h-2 rounded-full bg-blue-600 transition-all duration-300"
                  style={{ width: `${fixProgress}%` }}
                />
              </div>
            </div>
          )}
        </div>

        <div className="flex gap-2">
          {canFix && !isFixing && (
            <button
              onClick={() => handleFix(issue.id)}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
            >
              Fix
            </button>
          )}
          
          {isFixing && (
            <button
              disabled
              className="rounded-lg bg-gray-400 px-4 py-2 text-sm font-semibold text-white"
            >
              Fixing...
            </button>
          )}
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="mx-auto h-16 w-16 animate-spin rounded-full border-4 border-blue-600 border-t-transparent"></div>
          <p className="mt-4 text-lg font-semibold text-gray-900 dark:text-white">Loading Security Dashboard...</p>
          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Running system security scan</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Security</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">System security monitoring and hardening</p>
          </div>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:bg-gray-400"
        >
          <RefreshCw className={`h-4 w-4 ${scanning ? 'animate-spin' : ''}`} />
          {scanning ? 'Scanning...' : 'Run Security Scan'}
        </button>
      </div>

      {updateJobId && (
        <div className="rounded-2xl border border-blue-200 bg-gradient-to-br from-blue-50 to-white p-5 shadow-sm dark:border-blue-900/40 dark:from-blue-900/10 dark:to-dark-900">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-blue-700 dark:text-blue-300">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Package update in progress
          </div>
          <div className="mb-1 flex items-center justify-between text-xs text-gray-600 dark:text-gray-400">
            <span>{updateStatusMessage || 'Updating packages...'}</span>
            {updateProgressReported && <span>{fixProgress}%</span>}
          </div>
          {updateProgressReported && (
            <div className="h-2 w-full rounded-full bg-gray-200 dark:bg-dark-700">
              <div
                className="h-2 rounded-full bg-blue-600 transition-all duration-300"
                style={{ width: `${fixProgress}%` }}
              />
            </div>
          )}
        </div>
      )}

      {/* Status Cards */}
      {scanData && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-red-200 bg-gradient-to-br from-red-50 to-white p-6 shadow-sm dark:border-red-900/50 dark:from-red-900/10 dark:to-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-red-600 dark:text-red-400">Critical Issues</p>
                <p className="mt-1 text-3xl font-bold text-red-600 dark:text-red-400">{scanData.critical.length}</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-100 dark:bg-red-900/20">
                <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-yellow-200 bg-gradient-to-br from-yellow-50 to-white p-6 shadow-sm dark:border-yellow-900/50 dark:from-yellow-900/10 dark:to-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-yellow-600 dark:text-yellow-400">Warnings</p>
                <p className="mt-1 text-3xl font-bold text-yellow-600 dark:text-yellow-400">{scanData.warnings.length}</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-yellow-100 dark:bg-yellow-900/20">
                <Shield className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-green-200 bg-gradient-to-br from-green-50 to-white p-6 shadow-sm dark:border-green-900/50 dark:from-green-900/10 dark:to-dark-900">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-green-600 dark:text-green-400">Passed</p>
                <p className="mt-1 text-3xl font-bold text-green-600 dark:text-green-400">{scanData.passed.length}</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-green-100 dark:bg-green-900/20">
                <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Issues */}
      {scanData && (
        <div className="space-y-6">
          {scanData.critical.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-red-500 mb-4">Critical Issues</h2>
              <div className="space-y-3">
                {scanData.critical.map(renderIssue)}
              </div>
            </div>
          )}

          {scanData.warnings.length > 0 && (
            <div>
              <h2 className="text-xl font-bold text-yellow-500 mb-4">Warnings</h2>
              <div className="space-y-3">
                {scanData.warnings.map(renderIssue)}
              </div>
            </div>
          )}

          {scanData.critical.length === 0 && scanData.warnings.length === 0 && (
            <div className="rounded-2xl border border-green-200 bg-gradient-to-br from-green-50 to-white p-12 text-center shadow-sm dark:border-green-900/50 dark:from-green-900/10 dark:to-dark-900">
              <CheckCircle className="mx-auto h-16 w-16 text-green-500 dark:text-green-400" />
              <h3 className="mt-4 text-2xl font-bold text-green-600 dark:text-green-400">All Clear!</h3>
              <p className="mt-2 text-gray-600 dark:text-gray-400">No security issues detected. Your system is secure.</p>
            </div>
          )}
        </div>
      )}

      {/* Audit Logs Section */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm dark:border-dark-700 dark:bg-dark-900">
        <div className="flex items-center justify-between border-b border-gray-200 p-6 dark:border-dark-700">
          <div className="flex items-center gap-3">
            <FileText className="h-6 w-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Audit Logs</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">Recent security events and access logs from your system</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={loadAuditLogs}
              disabled={loadingLogs}
              className="rounded-lg bg-gray-100 px-3 py-2 text-sm font-semibold text-gray-600 transition hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-400 dark:hover:bg-dark-600"
            >
              <RefreshCw className={`h-4 w-4 ${loadingLogs ? 'animate-spin' : ''}`} />
            </button>
            <button 
              onClick={() => setShowAuditLogsModal(true)}
              className="rounded-lg bg-blue-50 px-4 py-2 text-sm font-semibold text-blue-600 transition hover:bg-blue-100 dark:bg-blue-900/20 dark:text-blue-400"
            >
              View All Logs
            </button>
          </div>
        </div>

        <div className="p-6">
          <div className="space-y-3">
            {/* Real audit log entries */}
            {loadingLogs ? (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin text-gray-400" />
              </div>
            ) : auditLogs.length > 0 ? (
              auditLogs.slice(0, 5).map((log, index) => (
                <div 
                  key={index} 
                  className={`flex items-start gap-4 rounded-lg border p-4 ${
                    log.type === 'warning' 
                      ? 'border-yellow-200 bg-yellow-50 dark:border-yellow-900/50 dark:bg-yellow-900/10' 
                      : log.type === 'error'
                      ? 'border-red-200 bg-red-50 dark:border-red-900/50 dark:bg-red-900/10'
                      : 'border-gray-200 dark:border-dark-700'
                  }`}
                >
                  <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                    log.type === 'success' ? 'bg-green-50 dark:bg-green-900/20' :
                    log.type === 'warning' ? 'bg-yellow-100 dark:bg-yellow-900/20' :
                    log.type === 'error' ? 'bg-red-100 dark:bg-red-900/20' :
                    'bg-blue-50 dark:bg-blue-900/20'
                  }`}>
                    {log.type === 'success' ? (
                      <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                    ) : log.type === 'warning' ? (
                      <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                    ) : log.type === 'error' ? (
                      <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
                    ) : (
                      <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-gray-900 dark:text-white">{log.title}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400 truncate">{log.details}</p>
                    <p className="text-xs text-gray-400">{log.timestamp} • {log.source}</p>
                  </div>
                </div>
              ))
            ) : (
              <div className="rounded-lg border border-dashed border-gray-300 p-8 text-center dark:border-dark-700">
                <FileText className="mx-auto h-8 w-8 text-gray-300 dark:text-gray-600" />
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  No audit logs available
                </p>
                <p className="text-xs text-gray-400 dark:text-gray-500">
                  Logs are read from <code className="rounded bg-gray-100 px-1 dark:bg-dark-800">/var/log/auth.log</code>
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Password Change Modal */}
      {showPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl dark:border-dark-700 dark:bg-dark-900">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 dark:bg-blue-900/20">
                <Lock className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">Change Password</h3>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="mb-2 block text-sm font-semibold text-gray-700 dark:text-gray-300">Username</label>
                <input
                  type="text"
                  value={passwordData.username}
                  onChange={(e) => setPasswordData({ ...passwordData, username: e.target.value })}
                  className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
              </div>

              <div>
                <label className="mb-2 block text-sm font-semibold text-gray-700 dark:text-gray-300">New Password</label>
                <input
                  type="password"
                  value={passwordData.new_password}
                  onChange={(e) => setPasswordData({ ...passwordData, new_password: e.target.value })}
                  placeholder="At least 8 characters"
                  className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
              </div>
            </div>

            <div className="mt-6 flex gap-3">
              <button
                onClick={() => {
                  setShowPasswordModal(false);
                  setPasswordData({ username: 'sb', new_password: '' });
                }}
                className="flex-1 rounded-lg bg-gray-200 px-4 py-2 font-semibold text-gray-900 transition hover:bg-gray-300 dark:bg-dark-700 dark:text-white dark:hover:bg-dark-600"
              >
                Cancel
              </button>
              <button
                onClick={handlePasswordChange}
                disabled={fixingIssue === 'default_password'}
                className="flex-1 rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700 disabled:bg-gray-400"
              >
                {fixingIssue === 'default_password' ? 'Changing...' : 'Change Password'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reboot Scheduled Modal */}
      {showRebootModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl dark:border-dark-700 dark:bg-dark-900">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-yellow-50 dark:bg-yellow-900/20">
                <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white">Filesystem Check Scheduled</h3>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              The device will reboot to run filesystem check (fsck). This page will refresh after reboot.
            </p>
            <div className="mt-4 rounded-lg bg-gray-50 px-4 py-3 text-sm text-gray-700 dark:bg-dark-800 dark:text-gray-300">
              Rebooting in ~{rebootSeconds}s…
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setShowRebootModal(false)}
                className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600"
              >
                Hide
              </button>
              <button
                onClick={() => window.location.reload()}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
              >
                Refresh Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Audit Logs Modal */}
      {showAuditLogsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-4xl rounded-2xl border border-gray-200 bg-white shadow-2xl dark:border-dark-700 dark:bg-dark-900 max-h-[90vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between border-b border-gray-200 p-6 dark:border-dark-700">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 dark:bg-blue-900/20">
                  <FileText className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">Security Audit Logs</h3>
              </div>
              <button
                onClick={() => setShowAuditLogsModal(false)}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                ✕
              </button>
            </div>
            
            <div className="overflow-y-auto p-6">
              <div className="mb-4 flex gap-3">
                <input
                  type="text"
                  placeholder="Search logs..."
                  className="flex-1 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white"
                />
                <select className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-dark-700 dark:bg-dark-800 dark:text-white">
                  <option>All Events</option>
                  <option>Login Attempts</option>
                  <option>Security Scans</option>
                  <option>Configuration Changes</option>
                  <option>Failed Attempts</option>
                </select>
              </div>

              <div className="space-y-3">
                {/* Real audit log entries */}
                {loadingLogs ? (
                  <div className="flex items-center justify-center py-12">
                    <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
                  </div>
                ) : auditLogs.length > 0 ? (
                  auditLogs.map((log, index) => (
                    <div 
                      key={index} 
                      className={`flex items-start gap-4 rounded-lg border p-4 ${
                        log.type === 'warning' 
                          ? 'border-yellow-200 bg-yellow-50 dark:border-yellow-900/50 dark:bg-yellow-900/10' 
                          : log.type === 'error'
                          ? 'border-red-200 bg-red-50 dark:border-red-900/50 dark:bg-red-900/10'
                          : 'border-gray-200 dark:border-dark-700'
                      }`}
                    >
                      <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                        log.type === 'success' ? 'bg-green-50 dark:bg-green-900/20' :
                        log.type === 'warning' ? 'bg-yellow-100 dark:bg-yellow-900/20' :
                        log.type === 'error' ? 'bg-red-100 dark:bg-red-900/20' :
                        'bg-blue-50 dark:bg-blue-900/20'
                      }`}>
                        {log.type === 'success' ? (
                          <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                        ) : log.type === 'warning' ? (
                          <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                        ) : log.type === 'error' ? (
                          <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
                        ) : (
                          <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-semibold text-gray-900 dark:text-white">{log.title}</p>
                        <p className="text-sm text-gray-600 dark:text-gray-400">{log.details}</p>
                        <p className="text-xs text-gray-400">{log.timestamp} • {log.source}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-lg border border-dashed border-gray-300 p-12 text-center dark:border-dark-700">
                    <FileText className="mx-auto h-12 w-12 text-gray-300 dark:text-gray-600" />
                    <p className="mt-4 text-gray-500 dark:text-gray-400">
                      No audit logs available
                    </p>
                    <p className="text-sm text-gray-400 dark:text-gray-500">
                      System logs will appear here when available
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="border-t border-gray-200 p-4 dark:border-dark-700">
              <button
                onClick={() => {
                  loadAuditLogs();
                  toast.success('Logs refreshed');
                }}
                disabled={loadingLogs}
                className="w-full rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition hover:bg-blue-700 disabled:bg-gray-400"
              >
                {loadingLogs ? 'Loading...' : 'Refresh Logs'}
              </button>
            </div>
          </div>
        </div>
      )}

      <Modal
        isOpen={Boolean(pendingPreviewIssueId)}
        onClose={() => setPendingPreviewIssueId(null)}
        title="Action Preview"
        footer={
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setPendingPreviewIssueId(null)}
              className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirmPreviewFix}
              disabled={fixPreviewQuery.isLoading || fixPreviewQuery.isFetching}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:bg-gray-400"
            >
              Continue Fix
            </button>
          </div>
        }
      >
        <ActionPreviewPanel
          preview={fixPreviewQuery.data}
          isLoading={fixPreviewQuery.isLoading || fixPreviewQuery.isFetching}
          errorMessage={fixPreviewQuery.error instanceof Error ? fixPreviewQuery.error.message : null}
        />
      </Modal>
    </div>
  );
}
