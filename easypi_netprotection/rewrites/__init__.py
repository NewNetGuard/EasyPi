"""
EasyPi NetProtection - DNS Rewrites Module

Custom DNS mapping rules that override normal resolution.
Supports exact match, wildcard patterns, and CNAME targets.
"""

from .manager import RewriteManager, get_rewrite_manager
from .models import RewriteRule, RewriteType, RewriteMatch


__all__ = [
    "RewriteManager",
    "get_rewrite_manager",
    "RewriteRule",
    "RewriteType",
    "RewriteMatch",
]
