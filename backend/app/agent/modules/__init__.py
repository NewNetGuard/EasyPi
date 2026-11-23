"""Agent modules for EasyPi."""

from app.agent.modules.backup_agent import BackupAgent
from app.agent.modules.ai_runtime_agent import AIRuntimeAgent
from app.agent.modules.camera_backup_cloud_reasoning_agent import CameraBackupCloudReasoningAgent
from app.agent.modules.cameras_agent import CamerasAgent
from app.agent.modules.cloud_agent import CloudAgent
from app.agent.modules.dashboard_agent import DashboardAgent
from app.agent.modules.dashboard_incident_agent import DashboardIncidentAgent
from app.agent.modules.dashboard_monitoring_agent import DashboardMonitoringAgent
from app.agent.modules.dashboard_reasoning_agent import DashboardReasoningAgent
from app.agent.modules.files_agent import FilesAgent
from app.agent.modules.guard_remote_setup_reasoning_agent import GuardRemoteSetupReasoningAgent
from app.agent.modules.help_agent import HelpAgent
from app.agent.modules.jobs_agent import JobsAgent
from app.agent.modules.monitoring_agent import MonitoringAgent
from app.agent.modules.netprotection_agent import NetProtectionAgent
from app.agent.modules.notifications_agent import NotificationsAgent
from app.agent.modules.network_activity_agent import NetworkActivityAgent
from app.agent.modules.network_toolkit_agent import NetworkToolkitAgent
from app.agent.modules.personal_dns_agent import PersonalDNSAgent
from app.agent.modules.claude_provider_agent import ClaudeProviderAgent
from app.agent.modules.remote_dashboard_services_reasoning_agent import RemoteDashboardServicesReasoningAgent
from app.agent.modules.remote_access_agent import RemoteAccessAgent
from app.agent.modules.rollback_agent import RollbackAgent
from app.agent.modules.security_agent import SecurityAgent
from app.agent.modules.settings_agent import SettingsAgent
from app.agent.modules.setup_guard_network_reasoning_agent import SetupGuardNetworkReasoningAgent
from app.agent.modules.setup_agent import SetupAgent
from app.agent.modules.system_services_agent import SystemServicesAgent
from app.agent.modules.terminal_agent import TerminalAgent
from app.agent.modules.users_agent import UsersAgent
from app.agent.modules.users_auth_agent import UsersAuthAgent
from app.agent.modules.users_auth_reasoning_agent import UsersAuthReasoningAgent
from app.agent.modules.users_security_settings_reasoning_agent import UsersSecuritySettingsReasoningAgent
from app.agent.modules.vpn_dashboard_security_reasoning_agent import VPNDashboardSecurityReasoningAgent
from app.agent.modules.wireguard_agent import WireGuardAgent

__all__ = [
    "BackupAgent",
    "AIRuntimeAgent",
    "CameraBackupCloudReasoningAgent",
    "CamerasAgent",
    "CloudAgent",
    "DashboardAgent",
    "DashboardIncidentAgent",
    "DashboardMonitoringAgent",
    "DashboardReasoningAgent",
    "FilesAgent",
    "GuardRemoteSetupReasoningAgent",
    "HelpAgent",
    "JobsAgent",
    "MonitoringAgent",
    "NetProtectionAgent",
    "NotificationsAgent",
    "NetworkActivityAgent",
    "NetworkToolkitAgent",
    "PersonalDNSAgent",
    "ClaudeProviderAgent",
    "RemoteDashboardServicesReasoningAgent",
    "RemoteAccessAgent",
    "RollbackAgent",
    "SecurityAgent",
    "SettingsAgent",
    "SetupGuardNetworkReasoningAgent",
    "SetupAgent",
    "SystemServicesAgent",
    "TerminalAgent",
    "UsersAgent",
    "UsersAuthAgent",
    "UsersAuthReasoningAgent",
    "UsersSecuritySettingsReasoningAgent",
    "VPNDashboardSecurityReasoningAgent",
    "WireGuardAgent",
]
