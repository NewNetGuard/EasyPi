import { aiApi } from '../../api/ai'
import type {
  AgentSectionConfig,
  AgentSectionId,
  AgentSuggestion,
  DiagnosticActionRequest,
  DiagnosticActionResponse,
  DiagnosticExplainRequest,
  DiagnosticExplainResponse,
} from './types'

const createSuggestion = (
  id: string,
  label: string,
  question: string,
  extras: Partial<AgentSuggestion> = {}
): AgentSuggestion => ({
  id,
  label,
  question,
  ...extras,
})

const SECTION_CONFIGS: Record<AgentSectionId, AgentSectionConfig> = {
  dashboard: {
    id: 'dashboard',
    route: 'dashboard',
    title: 'Dashboard Agent',
    subtitle: 'Cross-system health and incident triage',
    intro: 'Ask about red cards, system health, and what to inspect first.',
    placeholder: 'Ask why a dashboard card is red or what to open first...',
    suggestions: [
      createSuggestion('dash-health', 'Overall health', 'What is the biggest problem on the dashboard right now?'),
      createSuggestion('dash-first', 'Where to start', 'Which dashboard card should I open first?'),
      createSuggestion('dash-security', 'Security card', 'Why is the security card red on the dashboard?'),
      createSuggestion('dash-backup', 'Backup card', 'Why is the backup card red on the dashboard?'),
      createSuggestion('dash-camera', 'Camera card', 'Why is the cameras card warning on the dashboard?'),
      createSuggestion('dash-remote', 'Remote card', 'Why is the remote access card red on the dashboard?'),
      createSuggestion('dash-vpn', 'VPN card', 'Why is the VPN card red on the dashboard?'),
      createSuggestion('dash-guard', 'Guard card', 'Why is the Guard Security card red on the dashboard?'),
    ],
  },
  monitoring: {
    id: 'monitoring',
    route: 'monitoring',
    title: 'Monitoring Agent',
    subtitle: 'CPU, RAM, disk, temperature, and service spikes',
    intro: 'Use this when system metrics spike or Monitoring looks degraded.',
    placeholder: 'Ask why CPU, RAM, disk, or temperature is elevated...',
    suggestions: [
      createSuggestion('mon-cpu', 'CPU spike', 'Why is CPU usage high in Monitoring?'),
      createSuggestion('mon-ram', 'RAM spike', 'Why is RAM usage high in Monitoring?'),
      createSuggestion('mon-disk', 'Disk pressure', 'Why is disk usage high in Monitoring?'),
      createSuggestion('mon-temp', 'Temperature', 'Why is temperature elevated in Monitoring?'),
      createSuggestion('mon-service', 'Hottest service', 'Which service caused the current CPU spike?'),
      createSuggestion('mon-trend', 'Trend', 'Is this monitoring spike transient or persistent?'),
      createSuggestion('mon-summary', 'Why degraded', 'Why is the Monitoring page degraded?'),
      createSuggestion('mon-yesterday', 'Since yesterday', 'What changed since yesterday in Monitoring?'),
    ],
  },
  'guard-security': {
    id: 'guard-security',
    route: 'guard-security',
    title: 'Guard Agent',
    subtitle: 'NetProtection, policies, shadow mode, and parental controls',
    intro: 'Ask why protection blocked, observed, or allowed a device or domain.',
    placeholder: 'Ask why a domain, client, list, or rule behaved this way...',
    suggestions: [
      createSuggestion('guard-domain', 'Blocked domain', 'Why was this domain blocked by Guard Security?'),
      createSuggestion('guard-quarantine', 'Quarantined device', 'Why is this device quarantined?'),
      createSuggestion('guard-stale', 'DNS stale', 'Why is this device marked DNS stale?'),
      createSuggestion('guard-shadow', 'Shadow mode', 'Why is this domain only observed in Shadow Mode?'),
      createSuggestion('guard-lists', 'List update', 'Why did the latest list update fail?'),
      createSuggestion('guard-upstream', 'Upstream DNS', 'Why is encrypted DNS or upstream resolution broken?'),
      createSuggestion('guard-rules', 'Profile or schedule', 'Why did this Guard profile or schedule not apply?'),
      createSuggestion('guard-stats', 'Protection status', 'Why does Guard Security show zero stats or inactive protection?'),
    ],
  },
  'personal-dns': {
    id: 'personal-dns',
    route: 'personal-dns',
    title: 'Personal DNS Agent',
    subtitle: 'VPS deploy, DoH/DoT, certificates, and public DNS reachability',
    intro: 'Ask about deploy failures, certificates, upstream resolvers, and public reachability.',
    placeholder: 'Ask why Personal DNS deploy, TLS, or public resolution failed...',
    suggestions: [
      createSuggestion('dns-deploy', 'Deploy failed', 'Why did Personal DNS deployment fail?'),
      createSuggestion('dns-doh', 'DoH or DoT', 'Why is DoH or DoT unreachable right now?'),
      createSuggestion('dns-cert', 'Certificate', 'Why is the Personal DNS certificate invalid?'),
      createSuggestion('dns-public', 'Public DNS', 'Why does public DNS not resolve through the server?'),
      createSuggestion('dns-upstream', 'Upstream', 'Why is the upstream resolver failing?'),
      createSuggestion('dns-firewall', 'Firewall', 'Why is the firewall blocking Personal DNS reachability?'),
      createSuggestion('dns-cleanup', 'Cleanup', 'Why did Personal DNS cleanup fail?'),
      createSuggestion('dns-status', 'Current status', 'What is the current status of the Personal DNS VPS?'),
    ],
  },
  'file-manager': {
    id: 'file-manager',
    route: 'file-manager',
    title: 'File Manager Agent',
    subtitle: 'Safe paths, preview, search, upload, and write access',
    intro: 'Ask about failed uploads, denied paths, preview issues, and broad file searches.',
    placeholder: 'Ask why file access, preview, upload, or save failed...',
    suggestions: [
      createSuggestion('files-upload', 'Upload failed', 'Why did file upload fail?'),
      createSuggestion('files-download', 'Download failed', 'Why did file download fail?'),
      createSuggestion('files-preview', 'Preview unavailable', 'Why is file preview unavailable?'),
      createSuggestion('files-access', 'Access denied', 'Why is File Manager access denied?'),
      createSuggestion('files-search', 'Search', 'Search logs'),
      createSuggestion('files-save', 'Save failed', 'Why did file save fail?'),
      createSuggestion('files-sudo', 'Needs sudo', 'Why would editing a file require sudo?'),
      createSuggestion('files-disk', 'Disk pressure', 'Why is disk usage high in File Manager?'),
    ],
  },
  help: {
    id: 'help',
    route: 'help',
    title: 'Help Agent',
    subtitle: 'Guides, FAQs, and troubleshooting references',
    intro: 'Ask which guide to read next or what a Help reference means.',
    placeholder: 'Ask what a Help reference means or which guide matches your problem...',
    suggestions: [
      createSuggestion('help-error', 'Help reference', 'What does the ERR_PERMISSION_DENIED Help reference mean?'),
      createSuggestion('help-backup-error', 'Backup reference', 'What does the ERR_BACKUP_NOT_FOUND Help reference mean?'),
      createSuggestion('help-remote', 'Remote Access guide', 'Which guide matches my remote access problem?'),
      createSuggestion('help-guard', 'Guard guide', 'Which guide matches Guard Security?'),
      createSuggestion('help-setup', 'Setup guide', 'Which guide matches Setup permissions?'),
      createSuggestion('help-ai', 'AI guide', 'How do I work with the AI assistant?'),
      createSuggestion('help-start', 'Where to start', 'Where should I start for monitoring?'),
      createSuggestion('help-next', 'Read next', 'What should I read next about remote access?'),
    ],
  },
  'ip-cameras': {
    id: 'ip-cameras',
    route: 'ip-cameras',
    title: 'Camera Agent',
    subtitle: 'Connectivity, live view, recording, snapshots, and storage',
    intro: 'Ask why a camera is offline, why recording failed, or why storage looks unhealthy.',
    placeholder: 'Ask why a camera, stream, clip, snapshot, or storage action failed...',
    suggestions: [
      createSuggestion('cam-offline', 'Camera offline', 'Why is this camera offline?'),
      createSuggestion('cam-live', 'Live view', 'Why is live view black for this camera?'),
      createSuggestion('cam-record', 'Recording', 'Why did recording not start for this camera?'),
      createSuggestion('cam-clip', 'Missing clip', 'Why is a recording clip missing?'),
      createSuggestion('cam-snapshot', 'Snapshot', 'Why did snapshot export fail?'),
      createSuggestion('cam-storage', 'Storage full', 'Why is camera storage full or under pressure?'),
      createSuggestion('cam-onboard', 'Onboarding', 'Why is camera onboarding incomplete?'),
      createSuggestion('cam-stream', 'Stream pipeline', 'Why is the stream not ready for this camera?'),
    ],
  },
  'network-activity': {
    id: 'network-activity',
    route: 'network-activity',
    title: 'Network Activity Agent',
    subtitle: 'Client traffic, top talkers, blocked domains, and empty graphs',
    intro: 'Ask who generated traffic, why a device is missing, or why graphs look empty.',
    placeholder: 'Ask who generated traffic or why Network Activity looks empty...',
    suggestions: [
      createSuggestion('na-device', 'Missing device', 'Why is this device not visible in Network Activity?'),
      createSuggestion('na-blocked', 'Blocked domains', 'Why did blocked domains spike today?'),
      createSuggestion('na-top', 'Top talker', 'Who generated the most traffic right now?'),
      createSuggestion('na-graphs', 'Empty graphs', 'Why are Network Activity graphs empty?'),
      createSuggestion('na-live', 'Live queries', 'Why are live queries empty?'),
      createSuggestion('na-domain', 'Top blocked domain', 'Which blocked domain is affecting this device most?'),
      createSuggestion('na-attribution', 'Traffic owner', 'Who generated this traffic flow?'),
      createSuggestion('na-spike', 'Sudden spike', 'Why did Network Activity suddenly spike?'),
    ],
  },
  'network-toolkit': {
    id: 'network-toolkit',
    route: 'network-toolkit',
    title: 'Network Toolkit Agent',
    subtitle: 'Scanners, alerts, traffic graphs, and connectivity tools',
    intro: 'Ask about LAN scan results, port risk, speed tests, and active connections.',
    placeholder: 'Ask why a scan, alert, or traffic tool returned this result...',
    suggestions: [
      createSuggestion('nt-host', 'Host not found', 'Why was this host not discovered by LAN Scanner?'),
      createSuggestion('nt-port', 'Port risk', 'Is this open port dangerous?'),
      createSuggestion('nt-speed', 'Speed drop', 'Why did internet speed drop in Speed Test?'),
      createSuggestion('nt-traffic', 'Traffic graph', 'Why did throughput drop in the traffic graph?'),
      createSuggestion('nt-alert', 'Port alert', 'Why did this port alert fire?'),
      createSuggestion('nt-conn', 'Connection owner', 'Which process owns this active connection?'),
      createSuggestion('nt-arp', 'ARP change', 'Why did the ARP scanner show changed entries?'),
      createSuggestion('nt-gateway', 'Gateway fix', 'Why does gateway mode still look broken?'),
    ],
  },
  'remote-access': {
    id: 'remote-access',
    route: 'remote-access',
    title: 'Remote Access Agent',
    subtitle: 'Tailscale runtime, peers, subnet routing, and funnel',
    intro: 'Ask why Tailscale is offline, why peers cannot reach LAN, or why routes are missing.',
    placeholder: 'Ask why remote access, peers, routes, or funnel is not working...',
    suggestions: [
      createSuggestion('ra-offline', 'Tailscale offline', 'Why is Tailscale offline?'),
      createSuggestion('ra-login', 'Login required', 'Why is Tailscale login still required?'),
      createSuggestion('ra-subnet', 'Subnet router', 'Why is the subnet router not working?'),
      createSuggestion('ra-peer', 'Peer cannot reach LAN', 'Why can a peer not reach the LAN?'),
      createSuggestion('ra-routes', 'Advertised routes', 'Why are advertised routes missing?'),
      createSuggestion('ra-funnel', 'Funnel', 'Why is Tailscale funnel unavailable?'),
      createSuggestion('ra-service', 'Runtime', 'Why is remote access unhealthy on the dashboard?'),
      createSuggestion('ra-networks', 'Local networks', 'Why are local networks missing from Remote Access?'),
    ],
  },
  security: {
    id: 'security',
    route: 'security',
    title: 'Security Agent',
    subtitle: 'Scan findings, safe fixes, audit logs, and reboot requirements',
    intro: 'Ask which security issue matters most and why a fix did or did not apply.',
    placeholder: 'Ask why Security is warning, what to fix first, or why a fix failed...',
    suggestions: [
      createSuggestion('sec-scan', 'Scan failed', 'Why did the security scan fail?'),
      createSuggestion('sec-critical', 'Critical issue', 'What is the top critical security issue right now?'),
      createSuggestion('sec-safe', 'Safe fix', 'What is the safest security fix to run first?'),
      createSuggestion('sec-reboot', 'Needs reboot', 'Why does this security issue require a reboot?'),
      createSuggestion('sec-firewall', 'Firewall fix', 'Why did the firewall fix not apply?'),
      createSuggestion('sec-password', 'Password auth', 'Why does password authentication remain enabled?'),
      createSuggestion('sec-audit', 'Audit log', 'Why is the audit log showing suspicious entries?'),
      createSuggestion('sec-state', 'Still degraded', 'Why does the security page still show issues after fixes?'),
    ],
  },
  settings: {
    id: 'settings',
    route: 'settings',
    title: 'Settings Agent',
    subtitle: 'General, notifications, security, and user-profile state',
    intro: 'Ask why a setting did not apply or why account-related settings look incomplete.',
    placeholder: 'Ask why a setting, notification, or user preference did not apply...',
    suggestions: [
      createSuggestion('set-timezone', 'Timezone', 'Why did the timezone setting not apply?', { tab: 'general' }),
      createSuggestion('set-theme', 'Theme', 'Why does theme change only in this browser?', { tab: 'general' }),
      createSuggestion('set-notify', 'Notifications', 'Why are notifications not arriving by email?', { tab: 'notifications' }),
      createSuggestion('set-quiet', 'Quiet hours', 'Why are notifications silent during quiet hours?', { tab: 'notifications' }),
      createSuggestion('set-2fa', '2FA', 'Why is two-factor authentication disabled for this account?', { tab: 'security' }),
      createSuggestion('set-backup-codes', 'Backup codes', 'Why are there no backup codes left for this account?', { tab: 'security' }),
      createSuggestion('set-avatar', 'Avatar', 'Why is no avatar configured for this user profile?', { tab: 'user' }),
      createSuggestion('set-api-token', 'API token', 'Why is no API token configured in settings?', { tab: 'security' }),
    ],
  },
  setup: {
    id: 'setup',
    route: 'setup',
    title: 'Setup Agent',
    subtitle: 'Permissions, EasyPi group access, DNS self-config, and maintenance actions',
    intro: 'Ask why setup is incomplete, permissions are missing, or DNS self-config failed.',
    placeholder: 'Ask why Setup still shows incomplete permissions or DNS state...',
    suggestions: [
      createSuggestion('setup-perm', 'Permissions', 'Why are EasyPi permissions incomplete?'),
      createSuggestion('setup-relogin', 'Needs relogin', 'Why does the current session still need relogin for EasyPi group access?'),
      createSuggestion('setup-group', 'Missing group', 'Why is the EasyPi group missing?'),
      createSuggestion('setup-dns', 'Pi DNS', 'Why is system DNS not pinned on the Pi?'),
      createSuggestion('setup-update', 'Update capability', 'Why can update capability be unavailable from Setup?'),
      createSuggestion('setup-restart', 'Restart capability', 'Why can restart services be unavailable from Setup?'),
      createSuggestion('setup-install', 'Installation state', 'Why does Setup say EasyPi is not installed?'),
      createSuggestion('setup-maint', 'Maintenance blocked', 'Why can update or restart require relogin first?'),
    ],
  },
  'system-backup': {
    id: 'system-backup',
    route: 'system-backup',
    title: 'Backup Agent',
    subtitle: 'Backup jobs, restore safety, missing archives, and cancellations',
    intro: 'Ask why a backup failed, why restore is blocked, or why a file is missing.',
    placeholder: 'Ask why backup, restore, download, or cancellation failed...',
    suggestions: [
      createSuggestion('backup-failed', 'Backup failed', 'Why did the latest backup fail?'),
      createSuggestion('backup-restore', 'Restore blocked', 'Why is restore blocked for this backup?'),
      createSuggestion('backup-download', 'Download invalid', 'Why is the backup download invalid?'),
      createSuggestion('backup-cancel', 'Cancel did nothing', 'Why did cancel do nothing for the running backup?'),
      createSuggestion('backup-missing', 'Archive missing', 'Why is the backup archive file missing?'),
      createSuggestion('backup-running', 'Still running', 'Why is the backup status still running?'),
      createSuggestion('backup-history', 'No history', 'Why is backup history empty in EasyPi?'),
      createSuggestion('backup-completed', 'No completed restore point', 'Why is there no completed backup to restore?'),
    ],
  },
  jobs: {
    id: 'jobs',
    route: 'jobs',
    title: 'Jobs Agent',
    subtitle: 'Installer jobs, background work, and backup progress',
    intro: 'Ask why a job is still running, which task failed, or what background work needs attention.',
    placeholder: 'Ask why a background job is stuck or what failed most recently...',
    suggestions: [
      createSuggestion('jobs-running', 'Still running', 'Why is this job still running?'),
      createSuggestion('jobs-failed', 'Latest failure', 'Which background job failed most recently?'),
      createSuggestion('jobs-ai', 'AI install', 'Why is AI installation still running?'),
      createSuggestion('jobs-backup', 'Backup failed', 'Why did the latest backup job fail?'),
      createSuggestion('jobs-security', 'Package update', 'Why is the package update still running?'),
      createSuggestion('jobs-remote', 'Tailscale install', 'Why is the Tailscale install job still pending?'),
      createSuggestion('jobs-vpn', 'WireGuard install', 'Why did the WireGuard install job fail?'),
      createSuggestion('jobs-next', 'Safest next step', 'What is the safest next step for the failed job?'),
    ],
  },
  'notifications-center': {
    id: 'notifications-center',
    route: 'notifications',
    title: 'Notifications Agent',
    subtitle: 'Jobs, security events, and push delivery history',
    intro: 'Ask what needs attention most, which event is newest, or why a notification failed to deliver.',
    placeholder: 'Ask what needs attention most in Notification Inbox...',
    suggestions: [
      createSuggestion('notif-top', 'Needs attention', 'What needs attention most in Notification Inbox?'),
      createSuggestion('notif-job', 'Failed job', 'Which failed background job needs attention?'),
      createSuggestion('notif-security', 'Security event', 'Which security event in Notification Inbox matters most?'),
      createSuggestion('notif-push', 'Push delivery', 'Why did a push notification fail to deliver?'),
    ],
  },
  'rollback-center': {
    id: 'rollback-center',
    route: 'rollback',
    title: 'Rollback Agent',
    subtitle: 'Safe snapshots, restore state, and recovery steps',
    intro: 'Ask whether a snapshot is safe to restore, why creation failed, or which rollback point to use.',
    placeholder: 'Ask why a rollback snapshot is missing, failed, or safe to restore...',
    suggestions: [
      createSuggestion('rollback-safe', 'Safest snapshot', 'Which rollback snapshot is safest to restore?'),
      createSuggestion('rollback-create', 'Create failed', 'Why did the latest safe snapshot fail to create?'),
      createSuggestion('rollback-restore', 'Restore failed', 'Why did rollback restore fail?'),
      createSuggestion('rollback-next', 'Next step', 'What is the safest next step in Rollback Center?'),
    ],
  },
  terminal: {
    id: 'terminal',
    route: 'terminal',
    title: 'Terminal Agent',
    subtitle: 'PTY support, token checks, blocked IPs, and session limits',
    intro: 'Ask why shell access is denied, why commands fail, or why sessions close.',
    placeholder: 'Ask why Terminal access or a command failed...',
    suggestions: [
      createSuggestion('term-denied', 'Access denied', 'Why is terminal access denied?'),
      createSuggestion('term-command', 'Command failed', 'Why did the terminal command fail?'),
      createSuggestion('term-ip', 'Blocked IP', 'Why is terminal blocked by IP restrictions?'),
      createSuggestion('term-session', 'Session closed', 'Why did the latest terminal session close?'),
      createSuggestion('term-token', 'Token expired', 'Why did the websocket token expire for Terminal?'),
      createSuggestion('term-pty', 'PTY missing', 'Why is PTY support missing for Terminal?'),
      createSuggestion('term-limit', 'Session limit', 'Why is the global terminal session limit reached?'),
      createSuggestion('term-shell', 'Shell unavailable', 'Why can I not open a shell in Terminal?'),
    ],
  },
  users: {
    id: 'users',
    route: 'users',
    title: 'Users Agent',
    subtitle: 'Login state, 2FA, sessions, roles, and account restrictions',
    intro: 'Ask why a user cannot log in, why sessions look wrong, or why account settings are incomplete.',
    placeholder: 'Ask why a user account, session, or role change failed...',
    suggestions: [
      createSuggestion('users-login', 'Cannot log in', 'Why can john not log in?'),
      createSuggestion('users-role', 'Role change', 'Why did user role change fail?'),
      createSuggestion('users-session', 'Invalid session', 'Why is the session token invalid for this user?'),
      createSuggestion('users-2fa', '2FA', 'Why is two-factor authentication not enabled for this user?'),
      createSuggestion('users-backup-codes', 'Backup codes', 'Why does this account have no backup codes remaining?'),
      createSuggestion('users-avatar', 'Avatar', 'Why is the avatar missing for this user?'),
      createSuggestion('users-api', 'API token', 'Why is there no API token configured for this user?'),
      createSuggestion('users-disabled', 'Disabled account', 'Why can a disabled account not log in?'),
    ],
  },
  vpn: {
    id: 'vpn',
    route: 'vpn',
    title: 'VPN Agent',
    subtitle: 'WireGuard install, runtime, peers, handshakes, and QR export',
    intro: 'Ask why WireGuard is down, why a peer has no handshake, or why export failed.',
    placeholder: 'Ask why VPN runtime, peer, config, or QR export is failing...',
    suggestions: [
      createSuggestion('vpn-running', 'Server not running', 'Why is the WireGuard server not running?'),
      createSuggestion('vpn-handshake', 'No handshake', 'Why does this peer have no handshake?'),
      createSuggestion('vpn-qr', 'QR export', 'Why did QR export fail for this peer?'),
      createSuggestion('vpn-endpoint', 'Public endpoint', 'Why is the public endpoint wrong?'),
      createSuggestion('vpn-client', 'Client config', 'Why did client config export fail?'),
      createSuggestion('vpn-installed', 'Install state', 'Why is WireGuard installed but not running?'),
      createSuggestion('vpn-peers', 'Peer connectivity', 'Why can this VPN peer not connect?'),
      createSuggestion('vpn-dashboard', 'Dashboard security', 'Why is WireGuard down while dashboard security findings are still active?'),
    ],
  },
  'internet-encryption': {
    id: 'internet-encryption',
    route: 'internet-encryption',
    title: 'Internet Encryption Agent',
    subtitle: 'Outbound VPN provider, routing scope, and leak protection',
    intro: 'Ask about imported provider configs, tunnel state, routing scope, and the kill-switch.',
    placeholder: 'Ask why Internet Encryption is off, disconnected, or not routing a device...',
    suggestions: [
      createSuggestion('ie-status', 'Current status', 'What is the current Internet Encryption status?'),
      createSuggestion('ie-config', 'Provider config', 'Why is no VPN provider configuration available?'),
      createSuggestion('ie-enable', 'Tunnel is off', 'Why is the outbound VPN tunnel off?'),
      createSuggestion('ie-scope', 'Routing scope', 'Which devices are routed through Internet Encryption?'),
      createSuggestion('ie-killswitch', 'Kill-switch', 'Is the Internet Encryption kill-switch active?'),
      createSuggestion('ie-endpoint', 'VPN endpoint', 'Which outbound VPN endpoint is active?'),
      createSuggestion('ie-transfer', 'Transfer', 'Is traffic currently passing through Internet Encryption?'),
      createSuggestion('ie-leak', 'Leak protection', 'Could traffic leak if the outbound VPN disconnects?'),
    ],
  },
  stealth: {
    id: 'stealth',
    route: 'stealth',
    title: 'Stealth Agent',
    subtitle: 'Anti-DPI transport, VPS identity, routing, and connection health',
    intro: 'Ask about Client, Server, Profile, Domain HTTPS, routing, and live Stealth status.',
    placeholder: 'Ask why Stealth is disconnected or how its transport and routing work...',
    suggestions: [
      createSuggestion('stealth-status', 'Current status', 'Is Stealth configured and connected?'),
      createSuggestion('stealth-client', 'Client setup', 'What is missing from the Stealth client setup?'),
      createSuggestion('stealth-server', 'Server deployment', 'What is the current Stealth server deployment status?'),
      createSuggestion('stealth-domain', 'Domain HTTPS', 'Does Stealth work without a domain?'),
      createSuggestion('stealth-routing', 'Routing scope', 'Which devices are routed through Stealth?'),
      createSuggestion('stealth-leaks', 'Leak protection', 'Are the Stealth kill-switch, DNS, and QUIC protections active?'),
      createSuggestion('stealth-profile', 'Transport profile', 'What does the browser-like Stealth transport profile change?'),
      createSuggestion('stealth-lifecycle', 'Lifecycle', 'What is the difference between Disable, Stop Server, and Remove from server?'),
    ],
  },
  marketplace: {
    id: 'marketplace',
    route: 'marketplace',
    title: 'Marketplace Agent',
    subtitle: 'Preview catalog state and package lifecycle readiness',
    intro: 'Ask what the Marketplace preview contains and why installation is not enabled yet.',
    placeholder: 'Ask what Marketplace supports today or why a package cannot be installed...',
    suggestions: [
      createSuggestion('market-state', 'Current state', 'What is the current Marketplace status?'),
      createSuggestion('market-install', 'Install disabled', 'Why can I not install Marketplace packages yet?'),
      createSuggestion('market-catalog', 'Package catalog', 'Is the Marketplace catalog live or a preview?'),
      createSuggestion('market-security', 'Package safety', 'What security checks are needed before Marketplace installation is enabled?'),
      createSuggestion('market-signatures', 'Signatures', 'Why do Marketplace packages need signatures?'),
      createSuggestion('market-jobs', 'Install jobs', 'Why does Marketplace need a package job lifecycle?'),
      createSuggestion('market-rollback', 'Rollback', 'Why is rollback required before Marketplace installs are enabled?'),
      createSuggestion('market-search', 'Search and filters', 'What can I do in the Marketplace preview today?'),
    ],
  },
  cloud: {
    id: 'cloud',
    route: 'cloud',
    title: 'Cloud Agent',
    subtitle: 'Storage pressure, shares, Telegram bot, and PiCloud state',
    intro: 'Ask why cloud storage is full, why shares failed, or why Telegram automation is unhealthy.',
    placeholder: 'Ask why Cloud or PiCloud storage, sharing, or Telegram is failing...',
    suggestions: [
      createSuggestion('cloud-storage', 'Storage pressure', 'Why is cloud storage under pressure?'),
      createSuggestion('cloud-share', 'Share link', 'Why did this share link stop working?'),
      createSuggestion('cloud-telegram', 'Telegram bot', 'Why is the Telegram bot unavailable?'),
      createSuggestion('cloud-trash', 'Trash', 'Why is trash view still full?'),
      createSuggestion('cloud-upload', 'Upload', 'Why did this cloud upload fail?'),
      createSuggestion('cloud-duplicates', 'Duplicates', 'Why do duplicate files still exist in Cloud?'),
      createSuggestion('cloud-thumbs', 'Thumbnails', 'Why are thumbnails missing in PiCloud?'),
      createSuggestion('cloud-media', 'Media storage', 'Why are cloud media files causing storage pressure?'),
    ],
  },
  ai: {
    id: 'ai',
    route: 'ai-chat',
    title: 'AI Agent',
    subtitle: 'Local Ollama runtime, sessions, models, and provider state',
    intro: 'Ask why AI Chat is unavailable, why models are missing, or why a provider is not ready.',
    placeholder: 'Ask why AI Chat, Ollama, model install, or provider state is failing...',
    suggestions: [
      createSuggestion('ai-install', 'Install running', 'Why is AI installation still running?'),
      createSuggestion('ai-stream', 'Streaming', 'Why is chat streaming unavailable in AI Chat?'),
      createSuggestion('ai-models', 'No models', 'Why does AI Chat say no models are installed?'),
      createSuggestion('ai-history', 'History', 'Why is AI chat history empty?'),
      createSuggestion('ai-runtime', 'Ollama health', 'Why is local Ollama not healthy?'),
      createSuggestion('ai-provider', 'Provider', 'Which provider is active for AI right now?'),
      createSuggestion('ai-api-key', 'API key', 'Why is the API key rejected for Claude?'),
      createSuggestion('ai-redaction', 'Redaction', 'Why was this external AI request redacted?'),
    ],
  },
  generic: {
    id: 'generic',
    route: 'dashboard',
    title: 'EasyPi Agent',
    subtitle: 'Context-aware diagnostics for the current section',
    intro: 'Start with a quick question about the page you are on, or ask the agent to explain the current issue.',
    placeholder: 'Ask what is wrong on this page...',
    suggestions: [
      createSuggestion('generic-current', 'Current page', 'What is wrong on this page right now?'),
      createSuggestion('generic-start', 'Where to start', 'What should I check first here?'),
      createSuggestion('generic-issue', 'Current issue', 'Why does this section look degraded?'),
      createSuggestion('generic-next', 'Next step', 'What is the safest next step here?'),
    ],
  },
}

export const mapPathnameToSectionId = (pathname: string): AgentSectionId => {
  const segment = pathname.replace(/^\/+/, '').split('/')[0]?.toLowerCase() || 'dashboard'

  switch (segment) {
    case 'dashboard':
      return 'dashboard'
    case 'monitoring':
      return 'monitoring'
    case 'guard':
    case 'piguard':
    case 'netprotection':
      return 'guard-security'
    case 'dns':
      return 'personal-dns'
    case 'files':
      return 'file-manager'
    case 'help':
      return 'help'
    case 'devices':
      return 'ip-cameras'
    case 'network-activity':
      return 'network-activity'
    case 'network':
      return 'network-toolkit'
    case 'remote-access':
      return 'remote-access'
    case 'security':
      return 'security'
    case 'settings':
      return 'settings'
    case 'setup':
      return 'setup'
    case 'backup':
      return 'system-backup'
    case 'jobs':
      return 'jobs'
    case 'notifications':
      return 'notifications-center'
    case 'rollback':
      return 'rollback-center'
    case 'terminal':
      return 'terminal'
    case 'users':
      return 'users'
    case 'vpn':
      return 'vpn'
    case 'internet-encryption':
      return 'internet-encryption'
    case 'stealth':
      return 'stealth'
    case 'marketplace':
      return 'marketplace'
    case 'cloud':
    case 'picloud':
      return 'cloud'
    case 'ai':
    case 'claude':
      return 'ai'
    default:
      return 'generic'
  }
}

export const getAgentSectionConfig = (pathname: string): AgentSectionConfig =>
  SECTION_CONFIGS[mapPathnameToSectionId(pathname)]

export const AGENT_SECTION_TABS: Partial<Record<AgentSectionId, readonly string[]>> = {
  'guard-security': [
    'dashboard', 'ad-tracker', 'nrd', 'shadow-mode', 'heuristics', 'parental', 'schedules', 'devices',
    'ad-blocking', 'lists', 'firewall', 'query-log', 'security', 'statistics', 'dns', 'advanced',
  ],
  settings: ['general', 'notifications', 'security', 'user'],
  'ip-cameras': ['cameras', 'recordings'],
  stealth: ['client', 'server', 'profile'],
  'network-activity': ['devices', 'query-log'],
  'network-toolkit': [
    'lan-scanner', 'port-scanner', 'speed-test', 'traffic-graph', 'active-connections', 'arp-scanner',
    'open-ports-alert',
  ],
  cloud: ['files', 'recent', 'trash', 'telegram', 'photos', 'videos', 'documents', 'audio', 'other', 'encrypted'],
  jobs: ['all', 'active', 'attention', 'completed'],
  'notifications-center': ['all', 'attention', 'jobs', 'security', 'push', 'watchdog'],
  ai: ['models', 'chat'],
}

const DEFAULT_AGENT_TABS: Partial<Record<AgentSectionId, string>> = {
  'guard-security': 'dashboard',
  settings: 'general',
  'ip-cameras': 'cameras',
  stealth: 'client',
  'network-activity': 'devices',
  cloud: 'files',
  jobs: 'all',
  'notifications-center': 'all',
  ai: 'models',
}

export const getAgentTabFromLocation = (
  search: string,
  hash: string,
  pathname = ''
): string | undefined => {
  const sectionId = mapPathnameToSectionId(pathname)
  const knownTabs = AGENT_SECTION_TABS[sectionId]
  const params = new URLSearchParams(search)
  const queryTab = params.get('tab')
  if (queryTab && (!knownTabs || knownTabs.includes(queryTab))) {
    return queryTab
  }
  const normalizedHash = hash.replace(/^#/, '').trim()
  if (normalizedHash && (!knownTabs || knownTabs.includes(normalizedHash))) {
    return normalizedHash
  }
  return DEFAULT_AGENT_TABS[sectionId]
}

export const explainAgent = async (
  request: DiagnosticExplainRequest
): Promise<DiagnosticExplainResponse> => aiApi.explainDiagnostic(request)

export const executeAgentAction = async (
  request: DiagnosticActionRequest
): Promise<DiagnosticActionResponse> => aiApi.executeDiagnosticAction(request)
