"""
EasyPi NetProtection — Intelligent DNS-based Network Protection Engine.

Встроенный модуль сетевой защиты для платформы EasyPi.
Обеспечивает интеллектуальную фильтрацию DNS-трафика с прозрачным
объяснением каждого решения через Verdict Pipeline.

Usage:
    from easypi_netprotection import NetProtectionServer, load_config
    
    config = load_config()
    server = NetProtectionServer(config=config)
    await server.start()

© 2026 NewNetGuard (EasyPi Project). All rights reserved.
"""

# Version metadata must be calculated before the public re-exports below.
# ruff: noqa: E402

def _read_version() -> str:
    """Product version from the repo-root VERSION file (single source of truth)."""
    from pathlib import Path
    try:
        value = (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
        return value or "1.1.9"
    except OSError:
        return "1.1.9"


__version__ = _read_version()
__author__ = "NewNetGuard"
__license__ = "Proprietary"

from .config import (
    NetProtectionConfig,
    UpstreamConfig,
    CacheConfig,
    ChronicleConfig,
    GuardianConfig,
    load_config,
)

from .server import (
    NetProtectionServer,
    ServerState,
    ServerStats,
    run_server,
    create_server,
    main,
)

# Verdict Pipeline
from .verdict.outcome import (
    Verdict,
    VerdictType,
)

from .verdict.evidence import (
    Evidence,
    EvidenceSource,
    EvidenceWeight,
)

# Shield Profiles
from .shield.profiles import (
    ShieldProfile,
    ShieldProfileType,
    ShieldProfileType as ProfileType,  # Backwards compatibility
)

# Chronicle
from .chronicle.flow_log import (
    FlowEntry,
    FlowStatus,
    FlowLogger,
)

from .chronicle.metrics import (
    NetProtectionMetrics,
)

# System
from .system.bootstrap import (
    Bootstrap,
    BootstrapContext,
    bootstrap_netprotection,
)

from .system.guardian import (
    Guardian,
    GuardianMode,
    HealthStatus,
)

__all__ = [
    # Version
    "__version__",
    "__author__",
    "__license__",
    
    # Config
    "NetProtectionConfig",
    "UpstreamConfig",
    "CacheConfig",
    "ChronicleConfig",
    "GuardianConfig",
    "load_config",
    
    # Server
    "NetProtectionServer",
    "ServerState",
    "ServerStats",
    "run_server",
    "create_server",
    "main",
    
    # Verdict
    "Verdict",
    "VerdictType",
    "Evidence",
    "EvidenceSource",
    "EvidenceWeight",
    
    # Shield
    "ShieldProfile",
    "ShieldProfileType",
    "ProfileType",
    
    # Chronicle
    "FlowEntry",
    "FlowStatus",
    "FlowLogger",
    "NetProtectionMetrics",
    
    # System
    "Bootstrap",
    "BootstrapContext",
    "bootstrap_netprotection",
    "Guardian",
    "GuardianMode",
    "HealthStatus",
]
