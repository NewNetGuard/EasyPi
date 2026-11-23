"""
EasyPi NetProtection - Heuristics Engine

Advanced domain analysis using multiple signals:
- First Seen Cache (domain novelty)
- DGA Detection (botnet domains)
- Homoglyph Detection (phishing)
- Domain Analysis (length, depth, entropy)
- Signal Aggregator (multi-signal scoring with decay)
- Shadow Mode (observe before block)
- Device Anomaly (traffic spike detection)
- ASN Cluster (IP/ASN reputation)

© 2025 EasyPi Project
"""

from .first_seen import FirstSeenCache, FirstSeenRecord, get_first_seen_cache
from .signal_aggregator import (
    SignalAggregator,
    Signal,
    SignalType,
    AggregatedScore,
    get_signal_aggregator,
)
from .dga_detector import DGADetector, DGAResult, get_dga_detector, is_dga_domain
from .homoglyph import HomoglyphDetector, HomoglyphResult, get_homoglyph_detector, is_homoglyph_attack
from .domain_analysis import DomainAnalyzer, DomainAnalysisResult, get_domain_analyzer
from .shadow_mode import ShadowMode, ShadowRecord, ShadowAction, get_shadow_mode
from .device_anomaly import DeviceAnomalyDetector, DeviceStats, AnomalyResult, get_device_anomaly_detector
from .asn_cluster import ASNClusterAnalyzer, ASNInfo, IPReputation, ASNClusterResult, get_asn_cluster_analyzer
from .engine import HeuristicsEngine, HeuristicsResult, get_heuristics_engine

__all__ = [
    # First Seen
    "FirstSeenCache",
    "FirstSeenRecord",
    "get_first_seen_cache",
    # Signal Aggregator
    "SignalAggregator",
    "Signal",
    "SignalType",
    "AggregatedScore",
    "get_signal_aggregator",
    # DGA
    "DGADetector",
    "DGAResult",
    "get_dga_detector",
    "is_dga_domain",
    # Homoglyph
    "HomoglyphDetector",
    "HomoglyphResult",
    "get_homoglyph_detector",
    "is_homoglyph_attack",
    # Domain Analysis
    "DomainAnalyzer",
    "DomainAnalysisResult",
    "get_domain_analyzer",
    # Shadow Mode
    "ShadowMode",
    "ShadowRecord",
    "ShadowAction",
    "get_shadow_mode",
    # Device Anomaly
    "DeviceAnomalyDetector",
    "DeviceStats",
    "AnomalyResult",
    "get_device_anomaly_detector",
    # ASN Cluster
    "ASNClusterAnalyzer",
    "ASNInfo",
    "IPReputation",
    "ASNClusterResult",
    "get_asn_cluster_analyzer",
    # Main Engine
    "HeuristicsEngine",
    "HeuristicsResult",
    "get_heuristics_engine",
]
