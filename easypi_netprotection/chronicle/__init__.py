"""
EasyPi NetProtection — Chronicle Package.

Observability: DNS flow logging, metrics aggregation.
Security: IP anonymization with salt management and rotation.
"""

from .flow_log import (
    FlowLogger,
    FlowEntry,
    FlowStatus,
    QueryType,
    FlowLogStorage,
    IPAnonymizer,
    SaltManager,
    create_flow_logger,
    MAX_RETENTION_DAYS,
)

from .metrics import (
    NetProtectionMetrics,
    MetricsRegistry,
    Counter,
    Gauge,
    Histogram,
    TimeSeries,
    TopNTracker,
    TimeGranularity,
)

__all__ = [
    # Flow Log
    "FlowLogger",
    "FlowEntry",
    "FlowStatus",
    "QueryType",
    "FlowLogStorage",
    "IPAnonymizer",
    "SaltManager",
    "create_flow_logger",
    "MAX_RETENTION_DAYS",
    
    # Metrics
    "NetProtectionMetrics",
    "MetricsRegistry",
    "Counter",
    "Gauge",
    "Histogram",
    "TimeSeries",
    "TopNTracker",
    "TimeGranularity",
]
