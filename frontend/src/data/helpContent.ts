export interface HelpSection {
  id: string
  title: string
  description: string
  route: string
  icon: string
  tags: string[]
  docs?: string
}

export interface HelpFAQ {
  id: string
  sectionId: string
  question: string
  answer: string
  tags: string[]
}

export interface HelpErrorCode {
  code: string
  status: number
  message: string
  meaning: string
  causes: string[]
  fixes: string[]
  related?: string[]
}

export interface HelpGuide {
  id: string
  title: string
  sectionId: string
  prerequisites: string[]
  steps: string[]
  troubleshooting: string[]
  video?: string
  estimatedTime?: string
}

export interface HelpSupportChannel {
  id: string
  label: string
  description: string
  action: string
  type: 'link'
}

export interface ContextHelpTopic {
  id: string
  route: string
  title: string
  summary: string
  guideId?: string
}

export interface HelpService {
  id: string
  name: string
  icon: string
  category: string
  description: string
  features: string[]
  requirements: string
  docs?: string
}

export const helpSections: HelpSection[] = [
  {
    id: 'setup',
    title: 'Setup & Permissions',
    description: 'Connect to backend, configure NetProtection and sudo permissions, DNS for Pi itself.',
    route: '/setup',
    icon: 'Plug',
    tags: ['backend', 'permissions', 'dns']
  },
  {
    id: 'dashboard',
    title: 'Dashboard',
    description: 'Overview of Pi status, services and quick actions.',
    route: '/dashboard',
    icon: 'LayoutDashboard',
    tags: ['overview', 'metrics']
  },
  {
    id: 'monitoring',
    title: 'Monitoring',
    description: 'Real-time CPU, RAM, disk, network and temperature graphs.',
    route: '/monitoring',
    icon: 'Activity',
    tags: ['metrics', 'alerts']
  },
  {
    id: 'network-activity',
    title: 'Network Activity',
    description: 'Live DNS requests, blocked domains and device activity feed.',
    route: '/network-activity',
    icon: 'Activity',
    tags: ['dns', 'activity', 'devices']
  },
  {
    id: 'network',
    title: 'Network Toolkit',
    description: 'LAN scanner, port scanner, speed test and traffic analysis.',
    route: '/network',
    icon: 'Wifi',
    tags: ['network', 'scanner']
  },
  {
    id: 'picloud',
    title: 'Cloud Storage',
    description: 'Personal cloud file system, uploads, tags, Telegram bot.',
    route: '/cloud',
    icon: 'Cloud',
    tags: ['storage', 'files', 'telegram']
  },
  {
    id: 'piguard',
    title: 'Guard Security',
    description: 'DNS firewall, blocklists, parental controls and threat monitoring.',
    route: '/guard',
    icon: 'ShieldCheck',
    tags: ['security', 'dns']
  },
  {
    id: 'backup',
    title: 'Backup & Restore',
    description: 'System and config backups, restore and download.',
    route: '/backup',
    icon: 'Database',
    tags: ['backup', 'restore']
  },
  {
    id: 'wireguard',
    title: 'WireGuard VPN',
    description: 'Server installation, peer management, QR codes and config export.',
    route: '/vpn',
    icon: 'Shield',
    tags: ['vpn', 'wireguard']
  },
  {
    id: 'system-security',
    title: 'System Security',
    description: 'Security scan, hardening, audit logs and remediation.',
    route: '/security',
    icon: 'ShieldCheck',
    tags: ['security', 'hardening']
  },
  {
    id: 'internet-encryption',
    title: 'Internet Encryption',
    description: 'Route all or selected devices through an imported WireGuard, OpenVPN, or Outline provider configuration.',
    route: '/internet-encryption',
    icon: 'Cloud',
    tags: ['vpn', 'remote']
  },
  {
    id: 'personal-dns',
    title: 'Personal DNS Server',
    description: 'Deploy encrypted DNS (NetProtection) to your VPS with DoH/DoT.',
    route: '/dns',
    icon: 'Globe',
    tags: ['dns', 'NetProtection', 'vps', 'doh', 'dot']
  },
  {
    id: 'remote-access',
    title: 'Remote Access',
    description: 'Access your Pi from anywhere via Tailscale VPN.',
    route: '/remote-access',
    icon: 'Globe',
    tags: ['tailscale', 'remote', 'vpn']
  },
  {
    id: 'marketplace',
    title: 'Marketplace & Services',
    description: 'Preview possible future EasyPi packages. Installation is not enabled.',
    route: '/marketplace',
    icon: 'ShoppingBag',
    tags: ['preview', 'planned']
  },
  {
    id: 'ai',
    title: 'AI Chat',
    description: 'Local AI via Ollama, model management and chat sessions.',
    route: '/ai',
    icon: 'Bot',
    tags: ['ai', 'ollama']
  },
  {
    id: 'terminal',
    title: 'Web Terminal',
    description: 'Full shell with history and sudo permissions.',
    route: '/terminal',
    icon: 'Terminal',
    tags: ['terminal', 'shell']
  },
  {
    id: 'files',
    title: 'Files & Explorer',
    description: 'Browse file system, upload and download outside PiCloud.',
    route: '/files',
    icon: 'FolderOpen',
    tags: ['files', 'explorer']
  },
  {
    id: 'devices',
    title: 'IP Cameras',
    description: 'Manage IP cameras, monitor status and view video streams.',
    route: '/devices',
    icon: 'Server',
    tags: ['cameras', 'surveillance']
  },
  {
    id: 'users',
    title: 'User Management',
    description: 'Create users, manage roles and access levels.',
    route: '/users',
    icon: 'Users',
    tags: ['users', 'roles', 'access']
  },
  {
    id: 'settings',
    title: 'Settings',
    description: 'Platform settings, timezone, theme, security, user profile and API tokens.',
    route: '/settings',
    icon: 'Settings',
    tags: ['settings', 'profile', 'api-token']
  }
]

export const faqs: HelpFAQ[] = [
  {
    id: 'faq-dashboard-widgets',
    sectionId: 'dashboard',
    question: 'Can I customize Dashboard cards?',
    answer: 'Yes. Click Customize → select desired metrics (CPU, services, notifications) and save the profile. Settings are stored in localStorage.',
    tags: ['dashboard', 'widgets']
  },
  {
    id: 'faq-monitoring-alerts',
    sectionId: 'monitoring',
    question: 'How to enable temperature or CPU alerts?',
    answer: 'In Monitoring → Alerts, set thresholds and notification channel. EasyPi will show a toast and log to Notifications when exceeded.',
    tags: ['monitoring', 'alerts']
  },
  {
    id: 'faq-setup-backend',
    sectionId: 'setup',
    question: 'How to connect to EasyPi from another device?',
    answer: 'Open EasyPi by Raspberry Pi IP address (e.g. http://192.168.1.100) or via Tailscale. Frontend automatically connects to backend on the same address.',
    tags: ['backend', 'url', 'connection']
  },
  {
    id: 'faq-setup-dns',
    sectionId: 'setup',
    question: 'Why configure DNS for Raspberry Pi itself?',
    answer: 'If all network traffic goes through NetProtection, the Pi may lose access to updates. In Pi DNS Settings, set external DNS (8.8.8.8 / 1.1.1.1) so the system updates directly.',
    tags: ['dns', 'NetProtection']
  },
  {
    id: 'faq-network-scan',
    sectionId: 'network',
    question: 'How to scan local network?',
    answer: 'On Network Toolkit page, select LAN Scanner, set range (e.g. 192.168.1.0/24) and click Scan. Results appear in a table with filters.',
    tags: ['network', 'lan']
  },
  {
    id: 'faq-network-ports',
    sectionId: 'network',
    question: 'What to do if port scanner finds nothing?',
    answer: 'Make sure device responds to ICMP and port is open. You can enable TCP SYN mode and increase timeout in Port Scanner settings.',
    tags: ['ports', 'scan']
  },
  {
    id: 'faq-picloud-upload',
    sectionId: 'picloud',
    question: 'Where are PiCloud files saved?',
    answer: 'All files go to data/picloud directory. Via File Manager you can see the same structure. Telegram-uploaded files are tagged with "Telegram".',
    tags: ['storage', 'files']
  },
  {
    id: 'faq-picloud-telegram',
    sectionId: 'picloud',
    question: 'How to set up Telegram bot for uploads?',
    answer: 'In Cloud Storage open Telegram tab, create a token with @BotFather and save in settings. After that the bot will send files directly to Cloud.',
    tags: ['telegram']
  },
  {
    id: 'faq-piguard-blocklists',
    sectionId: 'piguard',
    question: 'How to add a custom blocklist?',
    answer: 'Go to Guard Security → Blocklists → Add List, specify URL and category. The list appears in the table and updates automatically on schedule.',
    tags: ['blocklist']
  },
  {
    id: 'faq-piguard-false-positive',
    sectionId: 'piguard',
    question: 'What to do if a site is blocked incorrectly?',
    answer: 'Add the domain to Whitelist in Guard Security. You can make a temporary or permanent rule.',
    tags: ['whitelist']
  },
  {
    id: 'faq-piguard-shadow-mode',
    sectionId: 'piguard',
    question: 'What is Shadow Mode?',
    answer: 'Shadow Mode records what would be blocked without actually blocking. Use it to test new lists or rules safely.',
    tags: ['shadow-mode', 'testing']
  },
  {
    id: 'faq-piguard-ad-ai',
    sectionId: 'piguard',
    question: 'What is Ad/Tracker AI?',
    answer: 'It uses heuristics to detect ad and tracking patterns in DNS traffic. It is optional and should be monitored for false positives.',
    tags: ['ai', 'ad-tracker']
  },
  {
    id: 'faq-piguard-schedules',
    sectionId: 'piguard',
    question: 'How do schedules and time limits work?',
    answer: 'Schedules apply per device profile. If a device is outside the allowed time window, blocking rules are enforced immediately.',
    tags: ['schedules', 'time-limits']
  },
  {
    id: 'faq-piguard-device-rules',
    sectionId: 'piguard',
    question: 'Why device-specific rules do not apply?',
    answer: 'Device rules work only when the device uses EasyPi as DNS (or is routed through it). Confirm the device IP is correct and DNS points to EasyPi.',
    tags: ['devices', 'rules']
  },
  {
    id: 'faq-piguard-parental-not-blocking',
    sectionId: 'piguard',
    question: 'Parental Filter is ON, but some devices still open adult sites. Why?',
    answer: 'Parental Controls are DNS-based. If EasyPi does not see DNS traffic from the device (or it uses Encrypted DNS / VPN / proxy), blocking will not apply. Open Guard → Parental Controls and check the DNS status badge: "DNS active" means the device is protected, "DNS stale / not seen" means the device is bypassing EasyPi DNS.',
    tags: ['parental', 'dns', 'bypass', 'doh', 'vpn']
  },
  {
    id: 'faq-piguard-security-monitor',
    sectionId: 'piguard',
    question: 'Why Security Monitor shows 0 threats?',
    answer: 'The monitor reports only when suspicious traffic or IP bans are triggered. If nothing looks malicious, it stays at zero.',
    tags: ['security-monitor', 'threats']
  },
  {
    id: 'faq-gateway-mode',
    sectionId: 'piguard',
    question: 'What is Full Gateway Mode?',
    answer: 'It makes EasyPi the default gateway via DHCP. This forces all device traffic through EasyPi for maximum protection.',
    tags: ['gateway', 'routing']
  },
  {
    id: 'faq-backup-types',
    sectionId: 'backup',
    question: 'What is the difference between Full and Config backup?',
    answer: 'Full includes system and data. Config saves only configurations (YAML, env, scripts).',
    tags: ['backup']
  },
  {
    id: 'faq-wireguard-peer',
    sectionId: 'wireguard',
    question: 'How to add a new WireGuard client?',
    answer: 'Open WireGuard → Add Peer, set name and description, download config or scan QR code with your phone.',
    tags: ['wireguard', 'peer']
  },
  {
    id: 'faq-system-security-scan',
    sectionId: 'system-security',
    question: 'What does the Security Scan check?',
    answer: 'It checks common hardening items like default passwords, SSH root login, firewall status, outdated packages and read-only filesystem.',
    tags: ['security', 'scan']
  },
  {
    id: 'faq-system-security-fixes',
    sectionId: 'system-security',
    question: 'What happens when I click Fix?',
    answer: 'EasyPi applies the recommended remediation for that finding. Some fixes require a service restart or reboot.',
    tags: ['security', 'fix']
  },
  {
    id: 'faq-network-activity-source',
    sectionId: 'network-activity',
    question: 'Where do Network Activity stats come from?',
    answer: 'Stats are derived from NetProtection DNS logs and device activity. If devices are not using EasyPi DNS, counts will stay at zero.',
    tags: ['dns', 'activity']
  },
  {
    id: 'faq-network-activity-missing-device',
    sectionId: 'network-activity',
    question: 'Why is my device missing?',
    answer: 'The device must be on the same LAN and visible to the scanner or DHCP. Run a LAN scan and refresh the activity page.',
    tags: ['devices', 'lan']
  },
  {
    id: 'faq-network-arp',
    sectionId: 'network',
    question: 'What is ARP Scanner used for?',
    answer: 'ARP Scanner maps IP-to-MAC on your LAN and finds hidden devices that may not respond to ICMP.',
    tags: ['arp', 'lan']
  },
  {
    id: 'faq-network-open-ports-alert',
    sectionId: 'network',
    question: 'What does Open Ports Alert do?',
    answer: 'It warns when new open ports appear on devices, helping you detect accidental exposure or changes.',
    tags: ['ports', 'alert']
  },
  {
    id: 'faq-cameras-recording-na',
    sectionId: 'devices',
    question: 'Why does it show "Recording since: N/A"?',
    answer: 'Recording time is shown only when a stream is actively recorded. Check RTSP credentials and storage path settings.',
    tags: ['cameras', 'recording']
  },
  {
    id: 'faq-cameras-add',
    sectionId: 'devices',
    question: 'How to add an IP camera?',
    answer: 'Use the camera RTSP URL (rtsp://user:pass@ip:554/stream). Ensure the camera is reachable from EasyPi.',
    tags: ['cameras', 'rtsp']
  },
  {
    id: 'faq-users-add',
    sectionId: 'users',
    question: 'How to add a new user?',
    answer: 'Open Users → Add User, set username and password, choose role and save.',
    tags: ['users', 'roles']
  },
  {
    id: 'faq-users-roles',
    sectionId: 'users',
    question: 'What is the difference between admin and user?',
    answer: 'Admins can change system settings and run privileged actions. Regular users can view dashboards and use allowed features only.',
    tags: ['users', 'permissions']
  },
  {
    id: 'faq-internet-encryption',
    sectionId: 'internet-encryption',
    question: 'What is required for Internet Encryption?',
    answer: 'Obtain a WireGuard configuration, an OpenVPN profile, or a static Outline ss:// access key from your VPN provider, import it, choose all or selected devices, and enable the tunnel.',
    tags: ['vpn', 'wireguard', 'openvpn', 'outline']
  },
  {
    id: 'faq-personal-dns',
    sectionId: 'personal-dns',
    question: 'What is Personal DNS Server?',
    answer: 'It deploys NetProtection to your VPS with encrypted DNS (DoH/DoT). You get ad-blocking DNS accessible from anywhere with your own domain.',
    tags: ['dns', 'doh', 'dot', 'NetProtection']
  },
  {
    id: 'faq-personal-dns-deploy',
    sectionId: 'personal-dns',
    question: 'How to deploy Personal DNS Server?',
    answer: 'Enter VPS IP, SSH credentials (password or key), domain name and NetProtection admin password. EasyPi will install NetProtection and configure SSL certificates automatically.',
    tags: ['dns', 'deploy', 'vps']
  },
  {
    id: 'faq-remote-access',
    sectionId: 'remote-access',
    question: 'How does Remote Access work?',
    answer: 'EasyPi uses Tailscale to create a secure VPN tunnel. Once enabled, you can access your Pi from anywhere using the Tailscale IP address.',
    tags: ['tailscale', 'remote']
  },
  {
    id: 'faq-remote-access-authkey',
    sectionId: 'remote-access',
    question: 'What is a Tailscale auth key?',
    answer: 'An auth key is a pre-authorized token from Tailscale admin console. It allows headless devices like Pi to join your tailnet without manual approval.',
    tags: ['tailscale', 'authkey']
  },
  {
    id: 'faq-ai-models',
    sectionId: 'ai',
    question: 'What models are supported?',
    answer: 'Via Ollama you can download Qwen2.5, Llama3.1, DeepSeek-R1 and any models from the hub. Each has configurable system prompt and temperature.',
    tags: ['ai', 'models']
  },
  {
    id: 'faq-marketplace-install',
    sectionId: 'marketplace',
    question: 'Can Marketplace packages be installed now?',
    answer: 'No. Marketplace is a read-only preview of ideas that may be developed later. It does not expose package installation or privileged scripts.',
    tags: ['preview', 'planned']
  },
  {
    id: 'faq-terminal-sudo',
    sectionId: 'terminal',
    question: 'Can I run sudo commands from web terminal?',
    answer: 'Yes, if user is in the easypi group. Enter sudo command — EasyPi will request password and execute with the same permissions as on Pi.',
    tags: ['terminal', 'sudo']
  },
  {
    id: 'faq-files-download',
    sectionId: 'files',
    question: 'How to download an entire folder?',
    answer: 'Select folder in Files & Explorer and choose Download → Archive. System creates a zip and offers to download.',
    tags: ['files', 'download']
  },
  {
    id: 'faq-devices-status',
    sectionId: 'devices',
    question: 'Where do IP camera statuses come from?',
    answer: 'EasyPi pings cameras and checks RTSP/HTTP stream availability. Indicator color reflects last successful response and stream status.',
    tags: ['cameras', 'status']
  },
  {
    id: 'faq-settings-users',
    sectionId: 'settings',
    question: 'How to add a new EasyPi user?',
    answer: 'Go to Settings → Users → Add user. Assign roles (admin/viewer) and send login link. Account is stored in backend DB.',
    tags: ['settings', 'users']
  },
  {
    id: 'faq-settings-api-token',
    sectionId: 'settings',
    question: 'How to generate an API token?',
    answer: 'In Settings → User tab, click Generate Token. Copy and save it immediately — it will not be shown again. Use for integrations with Home Assistant, mobile apps, etc.',
    tags: ['api', 'token', 'integration']
  },
  {
    id: 'faq-settings-session',
    sectionId: 'settings',
    question: 'What is Session Info?',
    answer: 'Session Info shows your last login time, IP address and device/browser used. Active Sessions lists current sessions and lets you revoke sessions you no longer trust.',
    tags: ['session', 'security']
  },
  {
    id: 'faq-settings-theme',
    sectionId: 'settings',
    question: 'How to change theme?',
    answer: 'Go to Settings → General → Theme and select Light, Dark or Auto. Theme applies immediately and persists across sessions.',
    tags: ['theme', 'dark', 'light']
  }
]

export const errorCodes: HelpErrorCode[] = [
  {
    code: 'ERR_PERMISSION_DENIED',
    status: 403,
    message: 'Permission denied - sudo required',
    meaning: 'Operation requires sudo permissions or easypi group membership.',
    causes: [
      'User not added to easypi group',
      'Session not refreshed after adding to group'
    ],
    fixes: [
      'In Setup → System Permissions click Setup Permissions',
      'Run relogin or newgrp easypi'
    ],
    related: ['/setup']
  },
  {
    code: 'ERR_BACKUP_NOT_FOUND',
    status: 404,
    message: 'Backup not found',
    meaning: 'The specified backup archive is missing or was deleted.',
    causes: [
      'File deleted manually',
      'Incorrect backup identifier specified'
    ],
    fixes: [
      'Check list in Backup → Existing Backups',
      'Create a new backup before restoring'
    ],
    related: ['/backup']
  },
  {
    code: 'ERR_BLOCKLIST_MISSING',
    status: 404,
    message: 'Blocklist not found',
    meaning: 'Guard Security could not find blocklist with specified ID.',
    causes: [
      'List already deleted',
      'ID in request does not match'
    ],
    fixes: [
      'Refresh blocklist list',
      'Create blocklist again'
    ],
    related: ['/guard']
  },
  {
    code: 'ERR_WIREGUARD_NOT_INSTALLED',
    status: 412,
    message: 'WireGuard server is not installed. Install it first.',
    meaning: 'VPN features are unavailable without installed server.',
    causes: [
      'WireGuard not yet installed on Pi'
    ],
    fixes: [
      'Open WireGuard section and run Install Wizard'
    ],
    related: ['/vpn']
  },
  {
    code: 'ERR_PEER_EXISTS',
    status: 409,
    message: "Peer '{name}' already exists",
    meaning: 'WireGuard client name is taken.',
    causes: [
      'Duplicate name',
      'Spaces/symbols in name'
    ],
    fixes: [
      'Use unique Latin names',
      'Delete old peer if not needed'
    ],
    related: ['/vpn']
  },
  {
    code: 'ERR_DNS_CONFIG',
    status: 500,
    message: 'Failed to set DNS',
    meaning: 'nmcli command failed.',
    causes: [
      'No active connection',
      'Invalid DNS IP specified'
    ],
    fixes: [
      'Check that Ethernet/Wi-Fi are active',
      'Use valid IPv4 addresses'
    ],
    related: ['/setup']
  },
  {
    code: 'ERR_BACKUP_INCOMPLETE',
    status: 500,
    message: 'Backup is not completed',
    meaning: 'Requested backup is still being created.',
    causes: [
      'Backup creation in progress',
      'Power interruption during creation'
    ],
    fixes: [
      'Check task status',
      'Restart creation'
    ],
    related: ['/backup']
  },
  {
    code: 'ERR_SCRIPT_TIMEOUT',
    status: 408,
    message: 'Script execution timed out',
    meaning: 'Long script exceeded 120 second limit.',
    causes: [
      'Script hung or waiting for input',
      'Insufficient resources'
    ],
    fixes: [
      'Check service logs',
      'Run command manually in Terminal'
    ],
    related: ['/terminal']
  },
  {
    code: 'ERR_AUTH_INVALID_TOKEN',
    status: 401,
    message: 'Invalid token',
    meaning: 'JWT expired or missing.',
    causes: [
      'Token expired',
      '.env contains wrong SECRET'
    ],
    fixes: [
      'Re-login',
      'Restart backend after updating SECRET'
    ],
    related: ['/settings']
  },
  {
    code: 'ERR_FILE_NOT_FOUND',
    status: 404,
    message: 'File not found',
    meaning: 'File or directory in Files Manager/PiCloud is missing.',
    causes: ['Object deleted by user', 'Relative path outside /data'],
    fixes: ['Refresh file list', 'Check access permissions and path'],
    related: ['/files', '/cloud']
  },
  {
    code: 'ERR_NETWORK_SCAN_TIMEOUT',
    status: 408,
    message: 'Scan timed out',
    meaning: 'Network scanner exceeded timeout limit.',
    causes: ['Large IP range', 'Devices blocking ICMP/TCP'],
    fixes: ['Reduce range', 'Increase timeout in tool settings'],
    related: ['/network']
  },
  {
    code: 'ERR_AI_MODEL_MISSING',
    status: 500,
    message: 'Model not installed',
    meaning: 'Requested AI model is missing from Ollama.',
    causes: ['Model deleted', 'Wrong name in settings'],
    fixes: ['Open AI Chat → Models and click Install', 'Update chat config'],
    related: ['/ai']
  },
  {
    code: 'ERR_VPS_SSH_FAILED',
    status: 500,
    message: 'SSH connection to VPS failed',
    meaning: 'Could not establish SSH connection to remote server.',
    causes: ['Wrong IP address', 'Incorrect SSH credentials', 'Firewall blocking port 22', 'SSH key format invalid'],
    fixes: ['Verify VPS IP and SSH port', 'Check username and password/key', 'Ensure port 22 is open on VPS'],
    related: ['/dns', '/stealth']
  },
  {
    code: 'ERR_DNS_DEPLOY_FAILED',
    status: 500,
    message: 'DNS deployment failed',
    meaning: 'Personal DNS Server deployment did not complete.',
    causes: ['Installation failed', 'Port 53/80/443 already in use', 'Domain not pointing to VPS IP', 'SSL certificate issue'],
    fixes: ['Check VPS requirements', 'Stop conflicting services', 'Verify DNS A record points to VPS', 'Try deployment again'],
    related: ['/dns']
  },
  {
    code: 'ERR_TAILSCALE_NOT_INSTALLED',
    status: 412,
    message: 'Tailscale is not installed',
    meaning: 'Remote Access requires Tailscale to be installed on Pi.',
    causes: ['Tailscale package not installed', 'Service not running'],
    fixes: ['Install Tailscale via the Remote Access page', 'Run: curl -fsSL https://tailscale.com/install.sh | sh'],
    related: ['/remote-access']
  },
  {
    code: 'ERR_TAILSCALE_AUTH_FAILED',
    status: 401,
    message: 'Tailscale authentication failed',
    meaning: 'Auth key is invalid or expired.',
    causes: ['Auth key expired', 'Key already used (one-time key)', 'Invalid key format'],
    fixes: ['Generate new auth key from Tailscale admin console', 'Use reusable key for testing', 'Check key is copied correctly'],
    related: ['/remote-access']
  },
  {
    code: 'ERR_TELEGRAM_BOT_FAILED',
    status: 500,
    message: 'Telegram bot failed to start',
    meaning: 'PiCloud Telegram bot could not initialize.',
    causes: ['Invalid bot token', 'Network connectivity issue', 'Bot already running elsewhere', 'python-telegram-bot version mismatch'],
    fixes: ['Verify token from @BotFather', 'Check internet connection', 'Stop other bot instances', 'Update python-telegram-bot package'],
    related: ['/cloud']
  },
  {
    code: 'ERR_API_TOKEN_GENERATION',
    status: 500,
    message: 'Failed to generate API token',
    meaning: 'Could not create new API token for user.',
    causes: ['Database error', 'User not found'],
    fixes: ['Try again', 'Re-login and retry', 'Check database connection'],
    related: ['/settings']
  },
  {
    code: 'ERR_AVATAR_UPLOAD',
    status: 400,
    message: 'Failed to upload avatar',
    meaning: 'Avatar image could not be saved.',
    causes: ['File too large (max 5MB)', 'Invalid image format', 'Disk full'],
    fixes: ['Use smaller image', 'Use JPG/PNG format', 'Free up disk space'],
    related: ['/settings']
  },
  {
    code: 'ERR_PASSWORD_CHANGE',
    status: 400,
    message: 'Password change failed',
    meaning: 'Could not update user password.',
    causes: ['Current password incorrect', 'New password too weak', 'Passwords do not match'],
    fixes: ['Enter correct current password', 'Use stronger password (min 6 chars)', 'Ensure new passwords match'],
    related: ['/settings']
  },
  {
    code: 'ERR_CLIPBOARD_FAILED',
    status: 0,
    message: 'Failed to copy to clipboard',
    meaning: 'Browser could not copy text to clipboard.',
    causes: ['HTTP context (not HTTPS)', 'Browser permissions denied', 'Clipboard API not supported'],
    fixes: ['Manually select and copy text', 'Use HTTPS connection', 'Try different browser'],
    related: ['/settings', '/dns', '/security']
  },
  {
    code: 'ERR_VPS_CLEANUP_FAILED',
    status: 500,
    message: 'VPS cleanup failed',
    meaning: 'Could not remove services from VPS.',
    causes: ['SSH connection lost', 'Services still running', 'Permission denied'],
    fixes: ['Reconnect and try again', 'Manually stop services via SSH', 'Check SSH user has sudo access'],
    related: ['/dns']
  },
  {
    code: 'ERR_NETPROTECTION_OFFLINE',
    status: 503,
    message: 'NetProtection engine offline',
    meaning: 'DNS filtering engine is not running or unreachable.',
    causes: ['Service stopped or crashed', 'Port 53 already in use', 'Firewall blocked access'],
    fixes: ['Restart NetProtection service', 'Check port 53 conflicts', 'Review firewall rules'],
    related: ['/guard', '/setup']
  },
  {
    code: 'ERR_DNS_UPSTREAM_TIMEOUT',
    status: 504,
    message: 'DNS upstream timeout',
    meaning: 'Upstream DNS servers did not respond in time.',
    causes: ['Upstream DNS outage', 'Network gateway unreachable', 'ISP blocking DNS'],
    fixes: ['Change upstream DNS', 'Check router gateway', 'Try 1.1.1.1 or 8.8.8.8'],
    related: ['/guard', '/setup']
  },
  {
    code: 'ERR_BLOCKLIST_UPDATE_FAILED',
    status: 500,
    message: 'Blocklist update failed',
    meaning: 'EasyPi could not download or merge blocklists.',
    causes: ['List URL unreachable', 'Invalid list format', 'Network outage'],
    fixes: ['Verify list URL', 'Disable broken list', 'Retry update'],
    related: ['/guard']
  },
  {
    code: 'ERR_DEVICE_RULE_INVALID_DOMAIN',
    status: 400,
    message: 'Invalid device rule',
    meaning: 'The domain format in the rule is invalid.',
    causes: ['Protocol/path included', 'Invalid wildcard'],
    fixes: ['Use plain domain (example.com)', 'Use *.example.com for subdomains'],
    related: ['/guard']
  },
  {
    code: 'ERR_DEVICE_NOT_FOUND',
    status: 404,
    message: 'Device not found',
    meaning: 'The specified device IP is not in the device list.',
    causes: ['Wrong IP address', 'Device not on LAN', 'DNS not using EasyPi'],
    fixes: ['Run LAN scan', 'Add device manually', 'Verify DNS settings'],
    related: ['/guard', '/network-activity']
  },
  {
    code: 'ERR_CAMERA_STREAM_FAILED',
    status: 502,
    message: 'Camera stream unavailable',
    meaning: 'Camera stream could not be opened.',
    causes: ['Wrong RTSP URL', 'Camera offline', 'Port blocked'],
    fixes: ['Verify RTSP URL and port 554', 'Check camera power/network', 'Try from same LAN'],
    related: ['/devices']
  },
  {
    code: 'ERR_CAMERA_AUTH_FAILED',
    status: 401,
    message: 'Camera authentication failed',
    meaning: 'Camera credentials are invalid.',
    causes: ['Wrong username/password', 'Changed camera password'],
    fixes: ['Update credentials in camera settings', 'Verify camera account'],
    related: ['/devices']
  }
]

export const guides: HelpGuide[] = [
  {
    id: 'guide-setup',
    title: 'How to complete EasyPi setup',
    sectionId: 'setup',
    prerequisites: [
      'Raspberry Pi on the network',
      'Browser with access to EasyPi UI'
    ],
    steps: [
      'Open Setup and specify Backend URL of the Pi',
      'Fill in NetProtection URL if using Guard Security',
      'Click Setup Permissions to add yourself to easypi group',
      'Configure Pi DNS to external addresses and restart network'
    ],
    troubleshooting: [
      'If Backend is offline — check address and port 8000',
      'If permissions not applied — run relogin'
    ],
    estimatedTime: '5 min'
  },
  {
    id: 'guide-setup-updates-ui',
    title: 'Setup → EasyPi Update: what every button means',
    sectionId: 'setup',
    prerequisites: [
      'Admin account in EasyPi',
      'Setup page is reachable'
    ],
    steps: [
      'Safe Update (Recommended): updates files and restarts services, without deleting old files',
      'Clean Reinstall: runs install and removes obsolete release files (more aggressive)',
      'From URL: download release archive from a direct link and apply update',
      'From Archive: use a signed archive staged in /opt/EasyPi/data/updates on the server',
      'Git Pull mode is intentionally removed from UI to avoid merge/rebase conflicts',
      'Help & Support button opens this guide from Setup',
      'Run Safe Update starts the recommended signed update and restarts services when the files are applied',
      'Safe Update applies a signed release while preserving existing configuration and data',
      'Clean Reinstall is reserved for a deliberate full application cleanup and reinstall',
      'Output panel: shows exact command, exit code, stdout/stderr for diagnostics'
    ],
    troubleshooting: [
      'If update fails, review the output panel and do not retry until the reported cause is understood',
      'For archive mode, verify path exists on server and is readable',
      'For URL mode, verify direct download URL and internet access',
      'If UI still shows old version, hard refresh browser cache'
    ],
    estimatedTime: '3 min'
  },
  {
    id: 'guide-piguard',
    title: 'How to secure DNS with Guard Security',
    sectionId: 'piguard',
    prerequisites: ['NetProtection installed', 'Backend connected to Pi'],
    steps: [
      'Open Guard Security and ensure Dashboard is connected',
      'Add recommended blocklists (Filters → Add defaults)',
      'Enable Protection and configure Firewall rules',
      'Set up Parental Controls for children\'s devices'
    ],
    troubleshooting: [
      'If stats are empty — check that router uses Pi as DNS',
      'For false positives add domain to Whitelist'
    ],
    estimatedTime: '10 min'
  },
  {
    id: 'guide-parental-controls',
    title: 'Parental Controls: How it works (DNS Active / Stale / Not Seen)',
    sectionId: 'piguard',
    prerequisites: [
      'NetProtection is running',
      'Device is connected to your Wi-Fi (not mobile data)',
      'EasyPi is set as DNS in your router DHCP (recommended) or on the device manually',
      'Optional: Full Gateway mode if you want IP-level blocking and strongest bypass resistance'
    ],
    steps: [
      'Open Guard Security → Parental Controls and add the device (name + IP)',
      'Enable Parental Filter (adult content), Safe Search, and Safe Browsing if needed',
      'Browse from the device and watch the DNS badge on the device card',
      'DNS active = device is using EasyPi DNS and is protected',
      'DNS stale / not seen = device is not using EasyPi DNS (common causes: browser Encrypted DNS/DoH, VPN/proxy, wrong Wi-Fi, or incorrect IP)',
      'Full Gateway mode: set router DHCP Gateway to EasyPi so ALL device traffic is routed through EasyPi (strongest protection)',
      'If bypass is detected, EasyPi shows an Anti-Bypass banner with actions:',
      'Warn (recommended) = block bypass channels (DoH/DoT/QUIC/VPN endpoints) without killing the whole internet',
      'Quarantine = full internet off for that device until admin clicks Restore Internet'
    ],
    troubleshooting: [
      'If DNS is not seen — first confirm the device is on the same Wi-Fi and the IP address is correct',
      'Disable browser Encrypted DNS (DoH) and any built-in VPN/proxy features (Opera/Firefox/Private DNS)',
      'If you can\'t control device DNS — use Transparent DNS (only when EasyPi is router or Tailscale exit node)',
      'If you enabled Full Gateway and "internet disappeared" — check the Anti-Bypass banner: the device may be Quarantined. Restore Internet, then disable the bypass (DoH/VPN/proxy) on the device.',
      'If DNS is active but a site still opens — add the domain to blocklist and report it (heuristics/blocklists may need updates)'
    ],
    estimatedTime: '6 min'
  },
  {
    id: 'guide-piguard-device-rules',
    title: 'How to use device-specific rules',
    sectionId: 'piguard',
    prerequisites: ['Device uses EasyPi DNS', 'Device IP is known'],
    steps: [
      'Open Guard Security → Devices',
      'Select a device and add a Block or Allow domain',
      'Save rules and wait for DNS refresh',
      'Verify in Query Log that requests are blocked'
    ],
    troubleshooting: [
      'If rules do not apply — confirm device DNS points to EasyPi',
      'Use exact domain or wildcard pattern for subdomains'
    ],
    estimatedTime: '5 min'
  },
  {
    id: 'guide-network-activity',
    title: 'How to read Network Activity',
    sectionId: 'network-activity',
    prerequisites: ['Devices using EasyPi DNS'],
    steps: [
      'Open Network Activity and select a time range',
      'Check total vs blocked queries per device',
      'Click a device to view its recent queries',
      'Use filters to find specific domains'
    ],
    troubleshooting: [
      'If values are 0 — verify router DNS points to EasyPi',
      'Run LAN scan and refresh the list'
    ],
    estimatedTime: '4 min'
  },
  {
    id: 'guide-system-security',
    title: 'How to run a security scan',
    sectionId: 'system-security',
    prerequisites: ['Admin access'],
    steps: [
      'Open System Security and click Run Scan',
      'Review Critical and Warning findings',
      'Click Fix on items you want to remediate',
      'Check Audit Logs for applied changes'
    ],
    troubleshooting: [
      'If a fix fails — check logs or permissions',
      'Some fixes require a reboot'
    ],
    estimatedTime: '6 min'
  },
  {
    id: 'guide-cameras',
    title: 'How to add and record IP cameras',
    sectionId: 'devices',
    prerequisites: ['Camera on the same LAN', 'RTSP URL'],
    steps: [
      'Open IP Cameras and click Add Camera',
      'Enter RTSP URL, name and credentials',
      'Test stream and save',
      'Enable recording and choose storage path'
    ],
    troubleshooting: [
      'If stream is offline — verify RTSP URL and port 554',
      'Check camera user/password and network reachability'
    ],
    estimatedTime: '7 min'
  },
  {
    id: 'guide-wireguard',
    title: 'How to deploy WireGuard VPN',
    sectionId: 'wireguard',
    prerequisites: ['Updated Raspberry Pi', 'Port 51820/UDP open'],
    steps: [
      'Go to Security → WireGuard and run Install Wizard',
      'After installation create first client (peer)',
      'Download config or scan QR, add to device',
      'Check status and traffic in WireGuard Dashboard'
    ],
    troubleshooting: [
      'If port is closed — configure forwarding on router',
      'If peer won\'t connect — verify keys and server address'
    ],
    estimatedTime: '15 min'
  },
  {
    id: 'guide-backup',
    title: 'How to backup and restore EasyPi',
    sectionId: 'backup',
    prerequisites: ['Free space in data/backups'],
    steps: [
      'Open Backup → Create backup and select type',
      'Wait for Completion, download archive if needed',
      'To restore select desired archive and click Restore',
      'Check logs in Backup → Tasks & History'
    ],
    troubleshooting: [
      'If backup fails — check logs in scripts/backup/*.sh',
      'For large archives use external storage'
    ],
    estimatedTime: '8 min'
  },
  {
    id: 'guide-picloud',
    title: 'How to manage files with Cloud Storage',
    sectionId: 'picloud',
    prerequisites: ['data/picloud folder mounted', 'Browser with drag & drop'],
    steps: [
      'Open Cloud Storage and select category (Photos, Docs, etc.)',
      'Use Upload for files or Telegram Bot',
      'Add tags and color labels for quick search',
      'Configure Sharing to get public link'
    ],
    troubleshooting: [
      'If upload hangs — check free disk space',
      'Telegram bot requires valid token and webhook'
    ]
  },
  {
    id: 'guide-picloud-telegram',
    title: 'How to set up Telegram bot for Cloud Storage',
    sectionId: 'picloud',
    prerequisites: ['Telegram account', 'Internet access on Pi'],
    steps: [
      'Open Cloud Storage and go to Telegram tab',
      'Create bot with @BotFather and copy token',
      'Paste token in EasyPi and click Save',
      'Click Start to run the bot, then Stop/Restart as needed',
      'Send files to your bot — they appear in Cloud automatically'
    ],
    troubleshooting: [
      'If bot won\'t start — verify token is correct',
      'Check bot is not running elsewhere',
      'Files appear in data/picloud with Telegram tag'
    ],
    estimatedTime: '5 min'
  },
  {
    id: 'guide-services',
    title: 'Marketplace preview',
    sectionId: 'marketplace',
    prerequisites: [],
    steps: [
      'Open Marketplace to review planned package ideas',
      'Use search and category filters to browse the preview',
      'Use the dedicated EasyPi section for features that are already supported'
    ],
    troubleshooting: [
      'Install buttons are intentionally disabled because no production package lifecycle is available',
      'Use VPN, Remote Access, AI Chat, or another dedicated section for supported installation flows'
    ]
  },
  {
    id: 'guide-ai',
    title: 'How to work with the AI assistant',
    sectionId: 'ai',
    prerequisites: ['Ollama installed', 'At least 6GB RAM for large models'],
    steps: [
      'Open AI Chat and check Ollama status in Installation panel',
      'Select model (Qwen, Llama, DeepSeek) and click Install if needed',
      'Create new chat session, set system prompt and temperature',
      'Chat with model or run scripts via suggested templates'
    ],
    troubleshooting: [
      'If model won\'t start — check Ollama log and free memory',
      'For slow generation reduce context or choose smaller model'
    ],
    estimatedTime: '7 min'
  },
  {
    id: 'guide-internet-encryption',
    title: 'How to configure Internet Encryption',
    sectionId: 'internet-encryption',
    prerequisites: ['A WireGuard/OpenVPN profile or a static Outline ss:// access key'],
    steps: [
      'Open Internet Encryption and paste the provider configuration or access key',
      'Import the configuration and confirm that the detected VPN engine is correct',
      'Choose whether all devices or only selected devices should use the tunnel',
      'Enable the tunnel and verify the public IP from a routed device'
    ],
    troubleshooting: [
      'If import fails, obtain a fresh configuration from the VPN provider',
      'For OpenVPN profiles that require credentials, save the provider username and password in this section',
      'If the tunnel starts but a device is not routed, recheck the selected-device scope'
    ]
  },
  {
    id: 'guide-personal-dns',
    title: 'How to deploy Personal DNS Server',
    sectionId: 'personal-dns',
    prerequisites: ['VPS with public IP', 'Domain pointing to VPS (optional)', 'SSH access'],
    steps: [
      'Open Personal DNS and enter VPS IP address',
      'Choose SSH authentication (password or key)',
      'Enter domain name and NetProtection admin password',
      'Click Deploy and wait for installation to complete',
      'Configure your devices to use the new DNS server'
    ],
    troubleshooting: [
      'If deployment fails — check SSH credentials',
      'Ensure ports 53, 80, 443, 3000 are not in use',
      'Use Cleanup button to remove and redeploy',
      'Verify domain A record points to VPS IP'
    ],
    estimatedTime: '10 min'
  },
  {
    id: 'guide-remote-access',
    title: 'How to set up Remote Access with Tailscale',
    sectionId: 'remote-access',
    prerequisites: ['Tailscale account', 'Internet access on Pi'],
    steps: [
      'Open Remote Access page',
      'Get auth key from Tailscale admin console (Settings → Keys)',
      'Paste auth key and click Save',
      'Click Enable to start Tailscale',
      'Access Pi from anywhere using Tailscale IP'
    ],
    troubleshooting: [
      'If connection fails — check auth key is valid and not expired',
      'Use reusable key for easier testing',
      'Verify Pi has internet access'
    ],
    estimatedTime: '5 min'
  },
  {
    id: 'guide-settings',
    title: 'How to configure EasyPi settings',
    sectionId: 'settings',
    prerequisites: ['Admin access to EasyPi'],
    steps: [
      'Open Settings from header menu',
      'General: Set timezone, language and theme',
      'Security: Change password, enable or disable 2FA, review active sessions, and revoke untrusted sessions',
      'User: Upload avatar, view session info, generate API token',
      'Save changes — they apply immediately'
    ],
    troubleshooting: [
      'If theme doesn\'t apply — refresh the page',
      'API token shown only once — save it immediately',
      'Session info updates after next login'
    ],
    estimatedTime: '3 min'
  },
  {
    id: 'guide-users',
    title: 'How to manage users',
    sectionId: 'users',
    prerequisites: ['Admin access to EasyPi'],
    steps: [
      'Open Users page',
      'Click Add User and set username/password',
      'Select role (admin or user) and save',
      'Use Edit/Delete to maintain access list'
    ],
    troubleshooting: [
      'If user cannot log in — reset password',
      'Only admins can change roles'
    ],
    estimatedTime: '4 min'
  },
  {
    id: 'guide-network',
    title: 'How to audit your network',
    sectionId: 'network',
    prerequisites: ['Router on same subnet', 'ICMP/TCP permissions'],
    steps: [
      'Open Network Toolkit and run LAN Scan',
      'Use Port Scanner for critical devices',
      'Run Speed Test and Traffic Graph for channel analysis',
      'Save report and configure open port notifications'
    ],
    troubleshooting: [
      'If devices not found — enable SNMP/ICMP on them',
      'Port scanning requires sufficient timeouts'
    ]
  },
  {
    id: 'guide-terminal',
    title: 'How to work with the web terminal',
    sectionId: 'terminal',
    prerequisites: ['easypi group membership', 'Modern browser'],
    steps: [
      'Open Terminal and select tab or create new session',
      'Enter command. History is saved locally and available after reload',
      'Use Upload/Download buttons to transfer files to current directory',
      'Click Run Saved Command to repeat frequently used scripts'
    ],
    troubleshooting: ['If command hangs — use Ctrl+C', 'For sudo commands ensure you are in easypi group']
  },
  {
    id: 'guide-monitoring',
    title: 'How to monitor resources in real time',
    sectionId: 'monitoring',
    prerequisites: ['Telegraf/collectd agents installed (enabled by default)'],
    steps: [
      'Go to Monitoring Dashboard and select period (Realtime/24h)',
      'Hover over CPU/RAM/Disk graphs to see exact values',
      'Enable Alerts and set threshold values',
      'Export data to CSV or connect Grafana via API'
    ],
    troubleshooting: ['If graphs are empty — check metrics-collector service', 'Ensure Pi time is synchronized']
  }
]

export const supportChannels: HelpSupportChannel[] = [
  {
    id: 'github',
    label: 'GitHub Issues',
    description: 'Report a bug or suggest an improvement',
    action: 'https://github.com/NewNetGuard/EasyPi/issues',
    type: 'link'
  }
]

export const quickLinks = [
  { id: 'getting-started', label: 'Getting Started', target: '/help?guide=guide-setup' },
  { id: 'faq', label: 'FAQ', target: '#faq' },
  { id: 'errors', label: 'Troubleshooting', target: '#errors' },
  { id: 'tutorials', label: 'Tutorials', target: '#guides' },
  { id: 'support', label: 'Contact Support', target: '#support' }
]

export const contextHelpTopics: ContextHelpTopic[] = [
  {
    id: 'setup-overview',
    route: '/setup',
    title: 'Setup & Permissions',
    summary: 'Configure backend URL, NetProtection and sudo permissions before using EasyPi.',
    guideId: 'guide-setup'
  },
  {
    id: 'dashboard-overview',
    route: '/dashboard',
    title: 'Dashboard',
    summary: 'Monitor Pi resources, services and notifications.',
    guideId: 'guide-setup'
  },
  {
    id: 'piguard-overview',
    route: '/guard',
    title: 'Guard Security',
    summary: 'Manage DNS firewall, blocklists and threats.',
    guideId: 'guide-piguard'
  },
  {
    id: 'backup-overview',
    route: '/backup',
    title: 'Backup & Restore',
    summary: 'Create and restore system backups.',
    guideId: 'guide-backup'
  },
  {
    id: 'network-overview',
    route: '/network',
    title: 'Network Toolkit',
    summary: 'Analyze network, scan devices and ports.',
    guideId: 'guide-network'
  },
  {
    id: 'network-activity-overview',
    route: '/network-activity',
    title: 'Network Activity',
    summary: 'View live DNS requests and device activity.',
    guideId: 'guide-network-activity'
  },
  {
    id: 'picloud-overview',
    route: '/cloud',
    title: 'Cloud Storage',
    summary: 'Upload and share files from your Pi.',
    guideId: 'guide-picloud'
  },
  {
    id: 'marketplace-overview',
    route: '/marketplace',
    title: 'Marketplace',
    summary: 'Read-only preview of package ideas that may be developed later.',
    guideId: 'guide-services'
  },
  {
    id: 'internet-encryption-overview',
    route: '/internet-encryption',
    title: 'Internet Encryption',
    summary: 'Route devices through an imported WireGuard, OpenVPN, or Outline provider configuration.',
    guideId: 'guide-internet-encryption'
  },
  {
    id: 'personal-dns-overview',
    route: '/dns',
    title: 'Personal DNS Server',
    summary: 'Deploy encrypted DNS (DoH/DoT) to your VPS.',
    guideId: 'guide-personal-dns'
  },
  {
    id: 'remote-access-overview',
    route: '/remote-access',
    title: 'Remote Access',
    summary: 'Access your Pi from anywhere via Tailscale.',
    guideId: 'guide-remote-access'
  },
  {
    id: 'system-security-overview',
    route: '/security',
    title: 'System Security',
    summary: 'Run security scans and apply hardening fixes.',
    guideId: 'guide-system-security'
  },
  {
    id: 'vpn-overview',
    route: '/vpn',
    title: 'WireGuard VPN',
    summary: 'Manage WireGuard server and clients.',
    guideId: 'guide-wireguard'
  },
  {
    id: 'users-overview',
    route: '/users',
    title: 'User Management',
    summary: 'Create users and manage roles.',
    guideId: 'guide-users'
  },
  {
    id: 'settings-overview',
    route: '/settings',
    title: 'Settings',
    summary: 'Configure theme, timezone, security and user profile.',
    guideId: 'guide-settings'
  },
  {
    id: 'default-help',
    route: '*',
    title: 'EasyPi Help',
    summary: 'Need help? Open Help & Support or select the appropriate section.'
  }
]

export const helpServices: HelpService[] = [
  {
    id: 'wireguard',
    name: 'WireGuard',
    icon: '🔐',
    category: 'Network',
    description: 'VPN tunnel with peer management and QR codes.',
    features: ['High-speed VPN', 'QR codes', 'Peer management'],
    requirements: '512MB RAM · 1GB disk · Port 51820',
    docs: 'https://www.wireguard.com/quickstart/'
  },
  {
    id: 'NetProtection',
    name: 'NetProtection',
    icon: '🛡️',
    category: 'Network',
    description: 'DNS-based ad and tracker blocking with DoH/DoT support.',
    features: ['DNS filtering', 'DoH/DoT', 'Parental controls', 'Query log'],
    requirements: '512MB RAM · 1GB disk · Ports 53/80/443/3000',
    docs: 'https://github.com/NetProtectionTeam/NetProtectionHome/wiki'
  },
  {
    id: 'tailscale',
    name: 'Tailscale',
    icon: '🌐',
    category: 'Network',
    description: 'Zero-config VPN for secure remote access.',
    features: ['Mesh VPN', 'SSO integration', 'Exit nodes', 'Subnet routing'],
    requirements: '256MB RAM · 100MB disk · No open ports needed',
    docs: 'https://tailscale.com/kb/'
  }
]
