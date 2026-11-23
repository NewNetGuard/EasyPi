"""
Brand Protection — Whitelist and protection for known brands.

Features:
- Protected brand registry (prevents false positives)
- Brand whitelist (official domains)
- User-defined brand additions
- Auto-exclusion from homoglyph detection
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import BrandEntry


class BrandProtection:
    """
    Brand protection and whitelist management.
    
    Protects against:
    1. False positives on legitimate brand domains
    2. Missing user's own domains from detection
    3. Overly aggressive homoglyph detection
    """
    
    # Default protected brands with their official domains
    DEFAULT_BRANDS = [
        BrandEntry(
            name="google",
            domains=[
                "google.com", "google.ru", "google.co.uk", "google.de", "google.fr",
                "gmail.com", "youtube.com", "googleapis.com", "gstatic.com",
                "googleusercontent.com", "googlevideo.com", "google-analytics.com",
                "googletagmanager.com", "googleadservices.com", "doubleclick.net",
            ],
            keywords=["google", "gmail", "youtube"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="microsoft",
            domains=[
                "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
                "microsoftonline.com", "azure.com", "windows.com", "xbox.com",
                "skype.com", "linkedin.com", "github.com", "visualstudio.com",
                "msn.com", "bing.com", "msedge.net", "onedrive.com",
            ],
            keywords=["microsoft", "windows", "azure", "office"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="apple",
            domains=[
                "apple.com", "icloud.com", "itunes.com", "mzstatic.com",
                "apple-dns.net", "aaplimg.com", "cdn-apple.com",
            ],
            keywords=["apple", "icloud", "itunes"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="amazon",
            domains=[
                "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp",
                "amazonaws.com", "cloudfront.net", "aws.amazon.com", "prime.amazon.com",
                "amazonvideo.com", "amazon-adsystem.com",
            ],
            keywords=["amazon", "aws", "prime"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="facebook",
            domains=[
                "facebook.com", "fb.com", "instagram.com", "messenger.com",
                "whatsapp.com", "whatsapp.net", "fbcdn.net", "fbsbx.com",
                "facebook.net", "meta.com", "threads.net",
            ],
            keywords=["facebook", "instagram", "whatsapp", "meta"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="twitter",
            domains=[
                "twitter.com", "x.com", "twimg.com", "t.co",
                "periscope.tv", "pscp.tv",
            ],
            keywords=["twitter", "x.com"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="paypal",
            domains=[
                "paypal.com", "paypal.me", "paypalobjects.com",
                "braintree-api.com", "braintreegateway.com",
            ],
            keywords=["paypal"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="netflix",
            domains=[
                "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net",
                "nflxext.com", "fast.com",
            ],
            keywords=["netflix"],
            protected=True,
            owner_verified=False,
        ),
        BrandEntry(
            name="cloudflare",
            domains=[
                "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
                "cloudflarestream.com", "one.one", "1.1.1.1", "1.0.0.1",
            ],
            keywords=["cloudflare"],
            protected=True,
            owner_verified=False,
        ),
    ]
    
    def __init__(self, db_path: str | Path | None = None):
        """
        Initialize brand protection.
        
        Args:
            db_path: Optional path to JSON file for persistent storage
        """
        self.db_path = Path(db_path) if db_path else None
        self._brands: dict[str, BrandEntry] = {}
        self._domain_to_brand: dict[str, str] = {}
        
        # Load defaults
        for brand in self.DEFAULT_BRANDS:
            self._add_brand_internal(brand)
        
        # Load from file if exists
        if self.db_path and self.db_path.exists():
            self._load_from_file()
    
    def _add_brand_internal(self, brand: BrandEntry) -> None:
        """Add brand to internal structures."""
        self._brands[brand.name.lower()] = brand
        for domain in brand.domains:
            self._domain_to_brand[domain.lower()] = brand.name.lower()
    
    def _load_from_file(self) -> None:
        """Load brands from JSON file."""
        if not self.db_path:
            return
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for brand_data in data.get("brands", []):
                brand = BrandEntry(**brand_data)
                self._add_brand_internal(brand)
        except Exception:
            pass  # File might not exist or be corrupted
    
    def _save_to_file(self) -> None:
        """Save brands to JSON file."""
        if not self.db_path:
            return
        
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                "brands": [
                    brand.model_dump()
                    for brand in self._brands.values()
                    if brand.owner_verified  # Only save user-added brands
                ]
            }
            
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass
    
    def add_brand(
        self,
        name: str,
        domains: list[str],
        keywords: list[str] | None = None,
        owner_verified: bool = True,
    ) -> BrandEntry:
        """
        Add a protected brand.
        
        Args:
            name: Brand name
            domains: List of official domains
            keywords: Keywords for homoglyph detection
            owner_verified: Whether this is user-verified
        
        Returns:
            Created BrandEntry
        """
        brand = BrandEntry(
            name=name,
            domains=[d.lower() for d in domains],
            keywords=keywords or [name.lower()],
            protected=True,
            owner_verified=owner_verified,
        )
        
        self._add_brand_internal(brand)
        self._save_to_file()
        
        return brand
    
    def add_user_domain(
        self,
        brand_name: str,
        domain: str,
    ) -> bool:
        """
        Add a domain to an existing brand.
        
        Args:
            brand_name: Name of the brand
            domain: Domain to add
        
        Returns:
            True if added, False if brand not found
        """
        brand = self._brands.get(brand_name.lower())
        if not brand:
            return False
        
        domain = domain.lower()
        if domain not in brand.domains:
            brand.domains.append(domain)
            self._domain_to_brand[domain] = brand_name.lower()
            self._save_to_file()
        
        return True
    
    def remove_brand(self, name: str) -> bool:
        """Remove a brand from protection."""
        name = name.lower()
        brand = self._brands.pop(name, None)
        
        if brand:
            for domain in brand.domains:
                self._domain_to_brand.pop(domain.lower(), None)
            self._save_to_file()
            return True
        
        return False
    
    def is_protected_domain(self, domain: str) -> tuple[bool, str | None]:
        """
        Check if domain belongs to a protected brand.
        
        Args:
            domain: Domain to check
        
        Returns:
            Tuple of (is_protected, brand_name)
        """
        domain = domain.lower()
        
        # Direct lookup
        if domain in self._domain_to_brand:
            return True, self._domain_to_brand[domain]
        
        # Check subdomain (e.g., www.google.com -> google.com)
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._domain_to_brand:
                return True, self._domain_to_brand[parent]
        
        return False, None
    
    def get_brand(self, name: str) -> BrandEntry | None:
        """Get brand by name."""
        return self._brands.get(name.lower())
    
    def get_all_brands(self) -> list[BrandEntry]:
        """Get all protected brands."""
        return list(self._brands.values())
    
    def get_brand_domains(self, name: str) -> list[str]:
        """Get all domains for a brand."""
        brand = self._brands.get(name.lower())
        return brand.domains if brand else []
    
    def should_skip_detection(self, domain: str) -> bool:
        """
        Check if domain should skip homoglyph/threat detection.
        
        Protected brand domains should not be flagged as threats.
        """
        is_protected, _ = self.is_protected_domain(domain)
        return is_protected
    
    def get_brand_for_detection(self, domain: str) -> dict[str, Any] | None:
        """
        Get brand info for homoglyph detection.
        
        If domain looks like it's impersonating a brand, return that brand's info.
        """
        domain = domain.lower()
        
        for brand in self._brands.values():
            # Check keywords
            for keyword in brand.keywords:
                if keyword in domain:
                    # Make sure it's not an official domain
                    is_official, _ = self.is_protected_domain(domain)
                    if not is_official:
                        return {
                            "name": brand.name,
                            "domains": brand.domains,
                            "keywords": brand.keywords,
                        }
        
        return None
    
    def export_to_allowlist(self) -> list[str]:
        """Export all protected domains as allowlist entries."""
        domains = []
        for brand in self._brands.values():
            if brand.protected:
                domains.extend(brand.domains)
        return list(set(domains))


class UserBrandWhitelist:
    """
    User's own domains whitelist.
    
    Domains added here are:
    1. Never flagged as threats
    2. Never analyzed for homoglyphs
    3. Always allowed through filtering
    """
    
    def __init__(self, db_path: str | Path | None = None):
        """Initialize user whitelist."""
        self.db_path = Path(db_path) if db_path else None
        self._domains: set[str] = set()
        self._patterns: list[str] = []  # Wildcard patterns
        
        if self.db_path and self.db_path.exists():
            self._load()
    
    def _load(self) -> None:
        """Load from file."""
        if not self.db_path:
            return
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self._domains = set(data.get("domains", []))
            self._patterns = data.get("patterns", [])
        except Exception:
            pass
    
    def _save(self) -> None:
        """Save to file."""
        if not self.db_path:
            return
        
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                "domains": list(self._domains),
                "patterns": self._patterns,
            }
            
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def add(self, domain: str, is_pattern: bool = False) -> None:
        """Add domain or pattern to whitelist."""
        domain = domain.lower()
        
        if is_pattern or "*" in domain:
            if domain not in self._patterns:
                self._patterns.append(domain)
        else:
            self._domains.add(domain)
        
        self._save()
    
    def remove(self, domain: str) -> bool:
        """Remove domain from whitelist."""
        domain = domain.lower()
        
        if domain in self._domains:
            self._domains.remove(domain)
            self._save()
            return True
        
        if domain in self._patterns:
            self._patterns.remove(domain)
            self._save()
            return True
        
        return False
    
    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted."""
        domain = domain.lower()
        
        # Direct match
        if domain in self._domains:
            return True
        
        # Pattern match
        import fnmatch
        for pattern in self._patterns:
            if fnmatch.fnmatch(domain, pattern):
                return True
        
        # Check parent domains
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._domains:
                return True
        
        return False
    
    def get_all(self) -> dict[str, list[str]]:
        """Get all whitelist entries."""
        return {
            "domains": list(self._domains),
            "patterns": self._patterns,
        }
    
    def clear(self) -> None:
        """Clear all entries."""
        self._domains.clear()
        self._patterns.clear()
        self._save()
