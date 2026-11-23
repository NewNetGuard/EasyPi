"""
Safe Search Module

DNS-based enforcement of Safe Search for Google, Bing, YouTube and DuckDuckGo.
Forces search engines to use their safe/restricted modes.

LIMITATIONS (document in UI):
- Only works when clients use this DNS server
- DoH/DoT configured on devices will bypass this protection
- Direct IP access to search engines bypasses DNS
- VPNs may use their own DNS servers
"""

from .enforcer import (
    SafeSearchEnforcer,
    SafeSearchRewrite,
    SafeSearchTarget,
    get_safesearch_enforcer,
    SAFESEARCH_REWRITES,
    SAFESEARCH_TTL_SECONDS,
    SAFE_ENDPOINTS,
)

__all__ = [
    "SafeSearchEnforcer",
    "SafeSearchRewrite",
    "SafeSearchTarget",
    "get_safesearch_enforcer",
    "SAFESEARCH_REWRITES",
    "SAFESEARCH_TTL_SECONDS",
    "SAFE_ENDPOINTS",
]
