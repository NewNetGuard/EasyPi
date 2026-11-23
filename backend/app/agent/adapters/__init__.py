"""Adapters used by the EasyPi agent."""

from app.agent.adapters.backup import BackupAdapter
from app.agent.adapters.ai_runtime import AIRuntimeAdapter
from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.cloud import CloudAdapter
from app.agent.adapters.files import FilesAdapter
from app.agent.adapters.help import HelpAdapter
from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.netprotection import NetProtectionAdapter
from app.agent.adapters.network_activity import NetworkActivityAdapter
from app.agent.adapters.network_toolkit import NetworkToolkitAdapter
from app.agent.adapters.operations import OperationsAdapter
from app.agent.adapters.personal_dns import PersonalDNSAdapter
from app.agent.adapters.provider import ProviderAdapter
from app.agent.adapters.remote_access import RemoteAccessAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.adapters.system import SystemAdapter
from app.agent.adapters.tailscale import TailscaleAdapter
from app.agent.adapters.terminal import TerminalAdapter
from app.agent.adapters.users import UsersAdapter
from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.adapters.wireguard import WireGuardAdapter

__all__ = [
    "BackupAdapter",
    "AIRuntimeAdapter",
    "CamerasAdapter",
    "CloudAdapter",
    "FilesAdapter",
    "HelpAdapter",
    "MonitoringAdapter",
    "NetProtectionAdapter",
    "NetworkActivityAdapter",
    "NetworkToolkitAdapter",
    "OperationsAdapter",
    "PersonalDNSAdapter",
    "ProviderAdapter",
    "RemoteAccessAdapter",
    "SecurityAdapter",
    "ServiceStatusAdapter",
    "SetupAdapter",
    "SystemAdapter",
    "TailscaleAdapter",
    "TerminalAdapter",
    "UsersAdapter",
    "UsersAuthAdapter",
    "WireGuardAdapter",
]
