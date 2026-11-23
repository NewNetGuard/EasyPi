"""
EasyPi NetProtection — Intel Package.

Signal Collectors: domain intelligence, CNAME uncloaking,
ASN lookup, entropy detection, TLS probing.
"""

from .domain_intel import (
    DomainIntelProvider,
    DomainCategory,
    DomainReputation,
)

from .cname_chain import (
    CNAMEChainAnalyzer,
    CNAMEChainResult,
)

from .asn_lookup import (
    ASNLookupProvider,
    ASNInfo,
    ASNLookupResult,
)

from .entropy_check import (
    EntropyAnalyzer,
    EntropyAnalysisResult,
    EntropyThresholds,
    PatternDetector,
)

from .tls_probe import (
    TLSProbeProvider,
    TLSProbeResult,
)

__all__ = [
    # Domain Intel
    "DomainIntelProvider",
    "DomainCategory",
    "DomainReputation",
    
    # CNAME Chain
    "CNAMEChainAnalyzer",
    "CNAMEChainResult",
    
    # ASN Lookup
    "ASNLookupProvider",
    "ASNInfo",
    "ASNLookupResult",
    
    # Entropy
    "EntropyAnalyzer",
    "EntropyAnalysisResult",
    "EntropyThresholds",
    "PatternDetector",
    
    # TLS Probe
    "TLSProbeProvider",
    "TLSProbeResult",
]
