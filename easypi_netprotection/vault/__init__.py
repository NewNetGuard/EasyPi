"""
EasyPi NetProtection — Vault Package.

Persistence layer: SQLite хранилище, модели данных, шифрование.
"""

from .models import (
    Matcher,
    MatcherCreate,
    MatcherUpdate,
    MatcherKind,
    Device,
    DeviceUpdate,
    DeviceKind,
    ShieldProfile,
    ShieldPreset,
    Schedule,
    FlowRecord,
    Verdict as VerdictModel,
    EvidenceItem,
    MetricsSnapshot,
    SystemHealth,
)

from .repository import (
    VaultRepository,
)

from .secrets import (
    SecretsVault,
    IPAnonymizer,
    generate_secure_token,
    generate_api_key,
)

__all__ = [
    # Models
    "Matcher",
    "MatcherCreate",
    "MatcherUpdate",
    "MatcherKind",
    "Device",
    "DeviceUpdate",
    "DeviceKind",
    "ShieldProfile",
    "ShieldPreset",
    "Schedule",
    "FlowRecord",
    "VerdictModel",
    "EvidenceItem",
    "MetricsSnapshot",
    "SystemHealth",
    
    # Repository
    "VaultRepository",
    
    # Secrets
    "SecretsVault",
    "IPAnonymizer",
    "generate_secure_token",
    "generate_api_key",
]
