"""
EasyPi NetProtection — Core Package.

DNS Runtime: resolver, cache, upstream management.
"""

from .cache import (
    DNSCache,
    CacheEntry,
    CacheStats,
)

from .upstream import (
    UpstreamManager,
    UpstreamPool,
    UpstreamServer,
    UpstreamProtocol,
    UpstreamHealth,
)

from .resolver import (
    DNSResolver,
    DNSQuestion,
    DNSResponse,
    FlowContext,
)

__all__ = [
    # Cache
    "DNSCache",
    "CacheEntry",
    "CacheStats",
    
    # Upstream
    "UpstreamManager",
    "UpstreamPool",
    "UpstreamServer",
    "UpstreamProtocol",
    "UpstreamHealth",
    
    # Resolver
    "DNSResolver",
    "DNSQuestion",
    "DNSResponse",
    "FlowContext",
]
