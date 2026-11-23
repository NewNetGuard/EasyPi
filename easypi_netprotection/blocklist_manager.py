"""
EasyPi NetProtection - Two-Layer Blocklist Manager

Architecture:
- verified_blocklist.txt  - Only CC0/MIT sources (hardcoded, safe)
- custom_blocklist.txt    - User-added sources (at their own risk)  
- effective_blocklist.txt - Combined, deduplicated, production-ready

Safety guarantees:
- Verified sources are hardcoded, cannot be changed via API
- Custom layer failures don't break verified layer
- Atomic writes (tmp → rename) prevent corruption
- Automatic rollback on failures
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, asdict
from .time_utils import utc_now
from enum import Enum
from pathlib import Path
from typing import Optional

from .safe_http import fetch_text, validate_remote_url_syntax

logger = logging.getLogger(__name__)


# =============================================================================
# Constants & Configuration
# =============================================================================

class SourceFormat(Enum):
    HOSTS = "hosts"
    DOMAINS = "domains"
    ADBLOCK = "adblock"


class License(Enum):
    CC0 = "CC0"
    MIT = "MIT"
    GPL3 = "GPL-3.0"
    CC_BY_NC = "CC BY-NC 4.0"  # NonCommercial — incompatible with a product that is sold
    VERIFY = "Terms — verify for commercial use"  # e.g. abuse.ch's 2025 terms: the free feed is
                                                  # primarily non-commercial → ship OFF by default
    MPL2 = "MPL-2.0"     # weak copyleft — commercial use fine (we fetch + use, never modify files)
    CC_BY = "CC BY 3.0"  # commercial use fine WITH attribution (shown in the UI + blocklist header)
    UNKNOWN = "unknown"


# Permissive licenses that are safe to ship ACTIVE by default in a product that may be
# sold. Anything else (GPL copyleft, NonCommercial, unknown) is opt-in: EasyPi ships it
# DISABLED and the user must explicitly consent to enable it — at which point the list is
# fetched to the user's OWN device. EasyPi never bundles or redistributes the list itself,
# so shipping only the URL + an opt-in toggle is not "distribution" of the list.
CONSENT_FREE_LICENSES = frozenset({License.CC0, License.MIT, License.MPL2, License.CC_BY})


def license_requires_consent(license: "License") -> bool:
    return license not in CONSENT_FREE_LICENSES


# =============================================================================
# Hardcoded Verified Sources — LICENSE-AUDITED for a commercial product (2026-08).
# EasyPi only FETCHES these at runtime on the end user's device — it never bundles or
# redistributes the lists — so shipping the URL + a toggle is not "distribution".
#   * Permissive (ship ACTIVE): 1Hosts Lite (MPL-2.0), AdAway (CC BY 3.0, attributed).
#   * Copyleft opt-in (OFF by default, user consents): HaGeZi x2 + OISD (GPL-3.0).
# Removed: phishing.army (CC BY-NC, NonCommercial) and URLhaus/abuse.ch (2025 terms
# restrict commercial use of the content + automated retrieval without a Spamhaus licence).
# =============================================================================

@dataclass
class VerifiedSource:
    id: str
    name: str
    url: str
    format: SourceFormat
    license: License
    description: str
    max_size_mb: float | None = None
    enabled: bool = True
    info_url: str = ""  # human-readable project / license page (shown in the consent dialog;
                        # never the raw multi-MB list, which chokes a browser)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "format": self.format.value,
            "license": self.license.value,
            "description": self.description,
            "max_size_mb": self.max_size_mb,
            "enabled": self.enabled,
            "info_url": self.info_url or self.url,
        }


VERIFIED_SOURCES: list[VerifiedSource] = [
    # NOTE: URLhaus / abuse.ch removed from the sellable build — abuse.ch's 2025 terms
    # restrict commercial use of the content and automated retrieval without a separate
    # Spamhaus licence. Phishing Army (CC BY-NC, NonCommercial) removed for the same reason.
    # Malware / phishing / scam coverage is retained via HaGeZi TIF below.

    # ==========================================================================
    # HAGEZI COLLECTION — GPL-3.0 (top quality; fetched at runtime, NOT redistributed)
    # ==========================================================================
    VerifiedSource(
        id="hagezi-multi",
        name="HaGeZi Multi PRO",
        url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        format=SourceFormat.DOMAINS,
        license=License.GPL3,
        description="Multi-source blocklist PRO - aggressive ads/tracking/analytics, recommended balance (GPL-3.0, © HaGeZi)",
        max_size_mb=25.0,
        enabled=False,  # opt-in: GPL-3.0 — user consents, then it is fetched to their device
        info_url="https://github.com/hagezi/dns-blocklists",
    ),
    VerifiedSource(
        id="hagezi-tif",
        name="HaGeZi Threat Intelligence Feeds",
        url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        format=SourceFormat.DOMAINS,
        license=License.GPL3,
        description="Threat Intelligence - malware, phishing, scam (GPL-3.0, © HaGeZi)",
        max_size_mb=60.0,  # tif-onlydomains is ~40MB / 2.1M domains and grows; 25 was too low -> feed silently failed
        enabled=False,  # opt-in: GPL-3.0
        info_url="https://github.com/hagezi/dns-blocklists",
    ),

    # ==========================================================================
    # OISD — GPL-3.0 per the upstream repo LICENSE (oisd.nl site also restricts mirroring)
    # ==========================================================================
    VerifiedSource(
        id="oisd-small",
        name="OISD Small",
        url="https://small.oisd.nl/domainswild",
        format=SourceFormat.DOMAINS,
        license=License.GPL3,
        description="OISD curated blocklist - small version (GPL-3.0; do not mirror per oisd.nl)",
        enabled=False,  # opt-in: GPL-3.0
        info_url="https://oisd.nl/",
    ),

    # ==========================================================================
    # PERMISSIVE — ship ACTIVE by default (commercial-safe, fetched directly at runtime)
    # ==========================================================================
    VerifiedSource(
        id="1hosts-lite",
        name="1Hosts Lite",
        url="https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards",
        format=SourceFormat.DOMAINS,
        license=License.MPL2,
        description="Universal ads + trackers + malware, balanced (Lite). Downloaded directly from upstream.",
        max_size_mb=15.0,
        enabled=True,
        info_url="https://github.com/badmojr/1Hosts",
    ),
    VerifiedSource(
        id="adaway",
        name="AdAway Mobile Ads",
        url="https://adaway.org/hosts.txt",
        format=SourceFormat.HOSTS,
        license=License.CC_BY,
        description="Mobile app ads + analytics, small & focused (© AdAway). Downloaded directly from upstream.",
        max_size_mb=5.0,
        enabled=True,
        info_url="https://adaway.org/",
    ),
]


# =============================================================================
# Custom Source
# =============================================================================

@dataclass
class CustomSource:
    id: str
    name: str
    url: str
    format: SourceFormat
    added_at: str
    user_confirmed_risks: bool = False
    enabled: bool = True
    last_error: Optional[str] = None
    domain_count: int = 0  # Number of domains in this source
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "format": self.format.value,
            "added_at": self.added_at,
            "user_confirmed_risks": self.user_confirmed_risks,
            "enabled": self.enabled,
            "last_error": self.last_error,
            "domain_count": self.domain_count,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "CustomSource":
        return cls(
            id=data["id"],
            name=data["name"],
            url=data["url"],
            format=SourceFormat(data["format"]),
            added_at=data["added_at"],
            user_confirmed_risks=data.get("user_confirmed_risks", False),
            enabled=data.get("enabled", True),
            last_error=data.get("last_error"),
            domain_count=data.get("domain_count", 0),
        )


# =============================================================================
# Status Classes
# =============================================================================

@dataclass
class LayerStatus:
    name: str
    success: bool
    domain_count: int
    sources_count: int
    sources_ok: list[str]
    sources_failed: list[str]
    generated_at: Optional[str]
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EffectiveStatus:
    total_domains: int
    verified_domains: int
    custom_domains: int
    sources: list[str]
    licenses: list[str]
    generated_at: str
    mode: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GenerationProgress:
    phase: str
    current_source: str
    sources_done: int
    sources_total: int
    domains_collected: int
    progress_percent: int  # 0-100
    message: str
    
    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# Network Config
# =============================================================================

@dataclass
class NetworkConfig:
    timeout_seconds: float = 30.0  # Increased from 5.0 for large blocklists
    max_size_mb: float = 10.0
    max_concurrent: int = 3
    min_interval_seconds: float = 10.0  # Reduced from 60.0 for faster retries
    retry_count: int = 3  # Increased retries
    retry_delay: float = 2.0  # Increased delay between retries


# =============================================================================
# Domain Parser
# =============================================================================

class DomainParser:
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    SKIP_DOMAINS = {
        'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
        'ip6-localhost', 'ip6-loopback', '0.0.0.0', '127.0.0.1', '::1',
    }
    
    @classmethod
    def detect_format(cls, content: str) -> SourceFormat:
        """
        Auto-detect blocklist format from content.
        
        Formats:
        - hosts: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        - adblock: "||domain.com^"
        - domains: one domain per line
        """
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
            and not line.strip().startswith('#')
            and not line.strip().startswith('!')
        ]
        
        if not lines:
            return SourceFormat.DOMAINS
        
        # Sample first 100 non-comment lines
        sample = lines[:100]
        
        hosts_count = 0
        adblock_count = 0
        domain_count = 0
        
        for line in sample:
            if line.startswith('@@') or '##' in line or '#@#' in line:
                # Adblock exception or cosmetic rule
                adblock_count += 1
                continue
            # Check hosts format: starts with IP address
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::', '::0'):
                hosts_count += 1
            # Check adblock format: starts with || and contains ^
            elif line.startswith('||') or line.startswith('|http') or line.startswith('http'):
                adblock_count += 1
            # Otherwise assume domain list
            else:
                domain_count += 1
        
        # Determine format based on majority
        if hosts_count > adblock_count and hosts_count > domain_count:
            return SourceFormat.HOSTS
        elif adblock_count > hosts_count and adblock_count > domain_count:
            return SourceFormat.ADBLOCK
        else:
            return SourceFormat.DOMAINS
    
    @classmethod
    def parse(cls, content: str, fmt: SourceFormat) -> tuple[set[str], int]:
        domains = set()
        rejected = 0
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            domain = cls._extract_domain(line, fmt)
            if domain and cls._is_valid(domain):
                domains.add(domain.lower())
            else:
                rejected += 1
        
        return domains, rejected
    
    @classmethod
    def _extract_domain(cls, line: str, fmt: SourceFormat) -> Optional[str]:
        if fmt == SourceFormat.HOSTS:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::'):
                return parts[1].split('#')[0].strip()
        elif fmt == SourceFormat.DOMAINS:
            return line.split('#')[0].split()[0] if line else None
        elif fmt == SourceFormat.ADBLOCK:
            # Ignore exception and cosmetic rules
            if line.startswith('@@') or '##' in line or '#@#' in line:
                return None

            # Strip options (e.g. $script,domain=...)
            rule = line.split('$', 1)[0]

            # Skip regex rules
            if rule.startswith('/') and rule.endswith('/'):
                return None

            # Handle ||example.com/path^ or ||example.com^
            if rule.startswith('||'):
                candidate = rule[2:]
                # Cut at separators: ^ / ? #
                for sep in ('^', '/', '?', '#'):
                    if sep in candidate:
                        candidate = candidate.split(sep, 1)[0]
                        break
                candidate = candidate.lstrip('.').lstrip('*')
                if candidate and '*' not in candidate and '/' not in candidate:
                    return candidate

            # Handle |https://example.com/path or https://example.com/path
            if rule.startswith('|http') or rule.startswith('http'):
                url_candidate = rule.lstrip('|')
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url_candidate)
                    hostname = parsed.hostname
                    if hostname:
                        return hostname.lstrip('.')
                except Exception:
                    return None
        return None
    
    @classmethod
    def _is_valid(cls, domain: str) -> bool:
        if not domain or domain.lower() in cls.SKIP_DOMAINS:
            return False
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return False
        return bool(cls.DOMAIN_PATTERN.match(domain))


# =============================================================================
# Blocklist Manager
# =============================================================================

class BlocklistManager:
    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.verified_file = self.data_dir / "verified_blocklist.txt"
        self.custom_file = self.data_dir / "custom_blocklist.txt"
        self.effective_file = self.data_dir / "effective_blocklist.txt"
        self.metadata_file = self.data_dir / "blocklist_metadata.json"
        self.custom_sources_file = self.data_dir / "custom_sources.json"
        self.source_cache_dir = self.data_dir / "source_cache"
        self.source_cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.network = NetworkConfig()
        self._last_generation_time: float = 0
        self._generation_lock = asyncio.Lock()
        self._progress: Optional[GenerationProgress] = None
        
        self._custom_sources: list[CustomSource] = self._load_custom_sources()
        self._verified_enabled: dict[str, bool] = self._load_verified_enabled()
    
    # =========================================================================
    # Source Cache Management
    # =========================================================================
    
    def _get_cache_path(self, source_id: str) -> Path:
        """Get cache file path for a source."""
        return self.source_cache_dir / f"{source_id}.txt"
    
    def _save_source_cache(self, source_id: str, domains: set[str]) -> None:
        """Cache downloaded domains for a source."""
        cache_path = self._get_cache_path(source_id)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(domains)))
            logger.info(f"Cached {len(domains)} domains for {source_id}")
        except Exception as e:
            logger.error(f"Failed to cache {source_id}: {e}")
    
    def _load_source_cache(self, source_id: str) -> Optional[set[str]]:
        """Load cached domains for a source."""
        cache_path = self._get_cache_path(source_id)
        if not cache_path.exists():
            return None
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                domains = {line.strip() for line in f if line.strip()}
            logger.info(f"Loaded {len(domains)} cached domains for {source_id}")
            return domains
        except Exception as e:
            logger.error(f"Failed to load cache for {source_id}: {e}")
            return None
    
    # =========================================================================
    # Custom Sources Management
    # =========================================================================
    
    def _load_custom_sources(self) -> list[CustomSource]:
        if not self.custom_sources_file.exists():
            return []
        try:
            with open(self.custom_sources_file, 'r') as f:
                data = json.load(f)
            return [CustomSource.from_dict(s) for s in data.get("sources", [])]
        except Exception as e:
            logger.error(f"Failed to load custom sources: {e}")
            return []
    
    def _save_custom_sources(self):
        data = {"sources": [s.to_dict() for s in self._custom_sources]}
        self._atomic_write_json(self.custom_sources_file, data)
    
    def _load_verified_enabled(self) -> dict[str, bool]:
        if not self.metadata_file.exists():
            return {s.id: s.enabled for s in VERIFIED_SOURCES}
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
            return data.get("verified_enabled", {s.id: s.enabled for s in VERIFIED_SOURCES})
        except (OSError, json.JSONDecodeError, TypeError):
            return {s.id: s.enabled for s in VERIFIED_SOURCES}
    
    def get_verified_sources(self) -> list[dict]:
        result = []
        for source in VERIFIED_SOURCES:
            d = source.to_dict()
            d["enabled"] = self._verified_enabled.get(source.id, source.enabled)
            # GPL / NonCommercial / unknown → the UI must show the license and require an
            # explicit opt-in tick before enabling. CC0 / MIT enable freely.
            d["requires_consent"] = license_requires_consent(source.license)
            result.append(d)
        return result
    
    def get_custom_sources(self) -> list[dict]:
        return [s.to_dict() for s in self._custom_sources]
    
    def set_verified_source_enabled(self, source_id: str, enabled: bool,
                                    user_confirmed_risks: bool = False) -> bool:
        source = next((s for s in VERIFIED_SOURCES if s.id == source_id), None)
        if source is None:
            return False
        # Enabling a non-permissive (GPL / NonCommercial / unknown) source requires an
        # explicit consent tick: the user is choosing to fetch that list to their own
        # device. Disabling never needs consent.
        if enabled and license_requires_consent(source.license) and not user_confirmed_risks:
            raise ValueError("Must confirm license risks")
        self._verified_enabled[source_id] = enabled
        self._save_metadata()
        return True
    
    def add_custom_source(self, name: str, url: str, format: str, user_confirmed_risks: bool) -> dict:
        if not user_confirmed_risks:
            raise ValueError("Must confirm license risks")
        
        validate_remote_url_syntax(url)
        
        source = CustomSource(
            id=hashlib.sha256(url.encode()).hexdigest()[:12],
            name=name,
            url=url,
            format=SourceFormat(format),
            added_at=utc_now().isoformat(),
            user_confirmed_risks=True,
            enabled=True,
        )
        
        self._custom_sources.append(source)
        self._save_custom_sources()
        logger.info(f"Added custom source: {name}")
        return source.to_dict()
    
    def add_custom_source_from_file(self, name: str, content: str, format: str, user_confirmed_risks: bool) -> dict:
        """Add custom blocklist from uploaded file content."""
        if not user_confirmed_risks:
            raise ValueError("Must confirm license risks")
        
        # Generate unique ID from content hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        
        # Auto-detect format if "auto" is specified
        if format == "auto":
            fmt = DomainParser.detect_format(content)
        else:
            fmt = SourceFormat(format)
        
        # Parse content to get domains
        domains, _ = DomainParser.parse(content, fmt)
        domain_count = len(domains)
        
        # Save original file to custom blocklists directory
        custom_files_dir = self.data_dir / "custom_files"
        custom_files_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = custom_files_dir / f"{content_hash}.txt"
        file_path.write_text(content, encoding='utf-8')
        
        # Also create/update custom_blocklist.txt with parsed domains
        self._write_custom_blocklist(domains, name)
        
        # Use file:// URL scheme for local files
        file_url = f"file://{file_path.absolute()}"
        
        source = CustomSource(
            id=content_hash,
            name=f"[File] {name}",
            url=file_url,
            format=fmt,
            added_at=utc_now().isoformat(),
            user_confirmed_risks=True,
            enabled=True,
            domain_count=domain_count,
        )
        
        self._custom_sources.append(source)
        self._save_custom_sources()
        logger.info(f"Added custom source from file: {name} ({domain_count} domains)")
        return source.to_dict()
    
    def _write_custom_blocklist(self, domains: set, source_name: str) -> None:
        """Write parsed domains to custom_blocklist.txt for direct use by DNS."""
        generated_at = utc_now().isoformat()
        header = f"""# EasyPi NetProtection - Custom Blocklist
# Source: {source_name}
# Generated: {generated_at}
# Domains: {len(domains):,}
#
# WARNING: This file may contain domains from sources with unknown licenses.
# Use at your own risk.
#
"""
        try:
            with open(self.custom_file, 'w', encoding='utf-8') as f:
                f.write(header)
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
            logger.info(f"Wrote custom blocklist: {len(domains):,} domains")
        except Exception as e:
            logger.error(f"Failed to write custom blocklist: {e}")
    
    def remove_custom_source(self, source_id: str) -> bool:
        for i, source in enumerate(self._custom_sources):
            if source.id == source_id:
                # Also delete the file if it's a local file
                if source.url.startswith('file://'):
                    try:
                        file_path = Path(source.url.replace('file://', ''))
                        if file_path.exists():
                            file_path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to delete file for source {source_id}: {e}")
                del self._custom_sources[i]
                self._save_custom_sources()
                
                # Remove custom_blocklist.txt if no more custom sources
                if not self._custom_sources and self.custom_file.exists():
                    try:
                        self.custom_file.unlink()
                        logger.info("Removed custom_blocklist.txt (no more custom sources)")
                    except Exception as e:
                        logger.warning(f"Failed to remove custom_blocklist.txt: {e}")
                return True
        return False
    
    def set_custom_source_enabled(self, source_id: str, enabled: bool) -> bool:
        for source in self._custom_sources:
            if source.id == source_id:
                source.enabled = enabled
                self._save_custom_sources()
                return True
        return False
    
    async def apply_custom_sources(self) -> dict:
        """
        Apply custom sources to effective blocklist WITHOUT full regeneration.
        
        This reads the existing verified_blocklist.txt and combines it with
        all enabled custom sources to create a new effective_blocklist.txt.
        
        Much faster than generate_all() since it doesn't re-download verified sources.
        
        Returns:
            dict with status and domain counts
        """
        if not self.verified_file.exists():
            return {
                "success": False,
                "error": "Verified blocklist not found. Please run full generation first.",
            }
        
        enabled_custom = [s for s in self._custom_sources if s.enabled]
        
        # Load verified domains
        try:
            verified_domains = self._load_blocklist(self.verified_file)
            verified_count = len(verified_domains)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to load verified blocklist: {e}",
            }
        
        # Load custom domains from all enabled sources
        custom_domains: set[str] = set()
        sources_ok: list[str] = []
        sources_failed: list[str] = []
        
        for source in enabled_custom:
            try:
                content = await self._download(source.url)
                domains, rejected = DomainParser.parse(content, source.format)
                custom_domains.update(domains)
                sources_ok.append(source.name)
                logger.info(f"Loaded {len(domains)} domains from {source.name}")
            except Exception as e:
                sources_failed.append(source.name)
                logger.error(f"Failed to load {source.name}: {e}")
        
        # Combine and deduplicate
        all_domains = verified_domains | custom_domains
        custom_unique = len(all_domains) - verified_count
        duplicates = len(custom_domains) - custom_unique
        
        # Build metadata
        generated_at = utc_now().isoformat()
        
        # Load metadata to get verified sources
        metadata = self._load_metadata()
        verified_sources = metadata.get("verified", {}).get("sources_ok", [])
        all_sources = verified_sources + sources_ok
        
        # Build header
        extra_header = f"""# Mode: verified+custom (apply_custom_sources)
# Timestamp: {generated_at}
# 
# === Layer Statistics ===
# Verified layer: {verified_count:,} domains
# Custom layer: {len(custom_domains):,} domains (raw), {custom_unique:,} unique
# Duplicates removed: {duplicates:,}
# Total unique: {len(all_domains):,}
#
# === Custom Sources Applied ===
# OK: {', '.join(sources_ok) if sources_ok else '(none)'}
# Failed: {', '.join(sources_failed) if sources_failed else '(none)'}
"""
        
        # Write effective blocklist
        try:
            self._atomic_write_blocklist(
                self.effective_file,
                all_domains,
                "effective",
                all_sources,
                generated_at,
                extra_header
            )
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write effective blocklist: {e}",
            }
        
        # Update metadata
        if metadata.get("effective"):
            metadata["effective"]["total_domains"] = len(all_domains)
            metadata["effective"]["custom_domains"] = custom_unique
            metadata["effective"]["sources"] = all_sources
            metadata["effective"]["generated_at"] = generated_at
            metadata["effective"]["mode"] = "verified+custom"
        metadata["updated_at"] = generated_at
        
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to update metadata: {e}")
        
        logger.info(f"Applied custom sources: {len(all_domains):,} total domains ({custom_unique:,} from custom)")
        
        return {
            "success": True,
            "verified_domains": verified_count,
            "custom_domains": len(custom_domains),
            "custom_unique": custom_unique,
            "duplicates_removed": duplicates,
            "total_domains": len(all_domains),
            "sources_ok": sources_ok,
            "sources_failed": sources_failed,
        }
    
    # =========================================================================
    # Cleanup
    # =========================================================================
    
    def clear_blocklists(self) -> dict:
        """
        Delete all blocklist files for fresh regeneration.
        Returns info about deleted files.
        """
        deleted = []
        errors = []
        
        files_to_delete = [
            self.verified_file,
            self.custom_file,
            self.effective_file,
        ]
        
        for file_path in files_to_delete:
            if file_path.exists():
                try:
                    file_path.unlink()
                    deleted.append(file_path.name)
                    logger.info(f"Deleted blocklist: {file_path.name}")
                except Exception as e:
                    errors.append(f"{file_path.name}: {e}")
                    logger.error(f"Failed to delete {file_path.name}: {e}")
        
        # Reset progress
        self._progress = None
        
        return {
            "deleted": deleted,
            "errors": errors,
            "success": len(errors) == 0
        }
    
    # =========================================================================
    # Generation
    # =========================================================================
    
    async def generate_all(self, force_clean: bool = True) -> dict:
        """
        Generate all blocklist layers atomically.
        Uses lock to prevent parallel generations.
        Rate limited to prevent abuse.
        
        Args:
            force_clean: If True, delete existing blocklists before regenerating
        """
        # Rate limit check
        if not await self._check_rate_limit():
            return {"error": "Rate limited. Please wait 10 seconds before regenerating."}
        
        # Single lock for entire operation - prevents parallel generations
        if self._generation_lock.locked():
            return {"error": "Generation already in progress. Please wait."}
        
        async with self._generation_lock:
            # Clean existing blocklists first
            if force_clean:
                self._update_progress("cleaning", "old blocklists", 0, 3, 0, 0, "Removing old blocklists...")
                clean_result = self.clear_blocklists()
                if clean_result["errors"]:
                    logger.warning(f"Some files couldn't be deleted: {clean_result['errors']}")
            
            # Generate verified layer
            self._update_progress("downloading", "verified sources", 0, 2, 0, 0, "Downloading verified sources...")
            verified = await self._generate_layer_internal(
                "verified",
                [s for s in VERIFIED_SOURCES if self._verified_enabled.get(s.id, True)],
                self.verified_file
            )
            
            # Generate custom layer (failures don't break verified)
            custom = None
            if self._custom_sources:
                enabled_custom = [s for s in self._custom_sources if s.enabled]
                if enabled_custom:
                    self._update_progress("downloading", "custom sources", 1, 2, verified.domain_count, 0, "Downloading custom sources...")
                    try:
                        custom = await self._generate_layer_internal("custom", enabled_custom, self.custom_file)
                    except Exception as e:
                        logger.error(f"Custom layer failed: {e}")
                        custom = LayerStatus(
                            name="custom", success=False, domain_count=0,
                            sources_count=len(enabled_custom),
                            sources_ok=[], sources_failed=[s.name for s in enabled_custom],
                            generated_at=None, error=str(e)
                        )
            
            # Combine into effective blocklist
            self._update_progress("writing", "effective blocklist", 2, 2, 0, 0, "Combining layers...")
            effective = await self._combine_effective(verified, custom)
            
            self._update_progress("done", "", 2, 2, effective.total_domains, 0, 
                f"Complete! {effective.total_domains:,} domains from {len(effective.sources)} sources")
            
            return {
                "verified": verified.to_dict(),
                "custom": custom.to_dict() if custom else None,
                "effective": effective.to_dict(),
            }
    
    async def _generate_layer_internal(self, layer_name: str, sources: list, output_file: Path) -> LayerStatus:
        all_domains: set[str] = set()
        sources_ok: list[str] = []
        sources_failed: list[str] = []
        sources_from_cache: list[str] = []
        total_rejected = 0
        total_sources = len(sources)
        
        sem = asyncio.Semaphore(self.network.max_concurrent)
        
        async def process(source, index: int) -> tuple[str, set[str], int, bool, str, bool]:
            """Returns: (source_id, domains, rejected, success, error, from_cache)"""
            async with sem:
                source_id = source.id if hasattr(source, 'id') else source.to_dict()["id"]
                name = source.name if hasattr(source, 'name') else source.to_dict()["name"]
                url = source.url if hasattr(source, 'url') else source.to_dict()["url"]
                fmt = source.format if hasattr(source, 'format') else SourceFormat(source.to_dict()["format"])
                
                # Calculate progress percentage
                progress_pct = int((index / total_sources) * 100)
                self._update_progress(
                    "downloading", name, index, total_sources,
                    len(all_domains), progress_pct, f"[{index+1}/{total_sources}] Downloading {name}..."
                )
                
                try:
                    content = await self._download(url, getattr(source, "max_size_mb", None))
                    domains, rejected = DomainParser.parse(content, fmt)
                    logger.info(f"{name}: {len(domains)} domains, {rejected} rejected")
                    
                    # Cache successful download
                    self._save_source_cache(source_id, domains)
                    
                    return source_id, domains, rejected, True, "", False
                except Exception as e:
                    logger.error(f"{name} failed: {e}")
                    
                    # Try to load from cache
                    cached_domains = self._load_source_cache(source_id)
                    if cached_domains:
                        logger.info(f"{name}: using {len(cached_domains)} cached domains")
                        return source_id, cached_domains, 0, True, f"From cache (download failed: {e})", True
                    
                    return source_id, set(), 0, False, str(e), False
        
        tasks = [process(s, i) for i, s in enumerate(sources)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for source, result in zip(sources, results):
            name = source.name if hasattr(source, 'name') else source.to_dict()["name"]
            
            if isinstance(result, Exception):
                sources_failed.append(name)
                if hasattr(source, 'last_error'):
                    source.last_error = str(result)
            else:
                source_id, domains, rejected, success, error, from_cache = result
                if success:
                    all_domains.update(domains)
                    total_rejected += rejected
                    if from_cache:
                        sources_from_cache.append(name)
                    sources_ok.append(name)
                else:
                    sources_failed.append(name)
        
        if layer_name == "custom":
            self._save_custom_sources()
        
        generated_at = utc_now().isoformat()
        
        # Include cache info in the layer output
        extra_info = ""
        if sources_from_cache:
            extra_info = f"# From cache: {', '.join(sources_from_cache)}\n"
        
        try:
            self._atomic_write_blocklist(output_file, all_domains, layer_name, sources_ok, generated_at, extra_info)
        except Exception as e:
            return LayerStatus(
                name=layer_name, success=False, domain_count=0,
                sources_count=len(sources), sources_ok=sources_ok,
                sources_failed=sources_failed, generated_at=None, error=str(e)
            )
        
        return LayerStatus(
            name=layer_name, success=True, domain_count=len(all_domains),
            sources_count=len(sources), sources_ok=sources_ok,
            sources_failed=sources_failed, generated_at=generated_at
        )
    
    async def _combine_effective(self, verified: LayerStatus, custom: Optional[LayerStatus]) -> EffectiveStatus:
        """
        Combine verified and custom layers into effective blocklist.
        - Deduplicates domains (using set)
        - Writes detailed metadata (timestamp, sources, counts per layer)
        """
        all_domains: set[str] = set()  # Set ensures deduplication
        sources: list[str] = []
        licenses: set[str] = set()
        
        # Load verified layer
        verified_domains = 0
        verified_before_dedup = 0
        if self.verified_file.exists():
            try:
                v_set = self._load_blocklist(self.verified_file)
                verified_before_dedup = len(v_set)
                all_domains.update(v_set)  # set.update() deduplicates
                verified_domains = len(v_set)
                sources.extend(verified.sources_ok)
                for s in VERIFIED_SOURCES:
                    if s.name in verified.sources_ok:
                        licenses.add(s.license.value)
            except Exception as e:
                logger.error(f"Load verified failed: {e}")
        
        # Load custom layer
        custom_domains = 0
        custom_before_dedup = 0
        mode = "verified_only"
        
        if custom and custom.success and self.custom_file.exists():
            try:
                c_set = self._load_blocklist(self.custom_file)
                custom_before_dedup = len(c_set)
                domains_before = len(all_domains)
                all_domains.update(c_set)  # Deduplicates overlapping domains
                custom_domains = len(all_domains) - domains_before  # Only unique custom domains
                sources.extend(custom.sources_ok)
                mode = "verified+custom"
                if custom_before_dedup > 0:
                    licenses.add("user-added")
            except Exception as e:
                logger.error(f"Load custom failed: {e}")
        
        generated_at = utc_now().isoformat()
        
        # Calculate deduplication stats
        total_before_dedup = verified_before_dedup + custom_before_dedup
        duplicates_removed = total_before_dedup - len(all_domains)
        
        # Build detailed header with metadata
        extra_header = f"""# Mode: {mode}
# Timestamp: {generated_at}
# 
# === Layer Statistics ===
# Verified layer: {verified_domains:,} domains
# Custom layer: {custom_before_dedup:,} domains (raw), {custom_domains:,} unique
# Duplicates removed: {duplicates_removed:,}
# Total unique: {len(all_domains):,}
#
# === Sources ===
# {chr(10).join('# - ' + s for s in sources) if sources else '# (none)'}
#
# === Licenses ===
# {', '.join(sorted(licenses)) if licenses else '(none)'}
"""
        
        try:
            self._atomic_write_blocklist(self.effective_file, all_domains, "effective", sources, generated_at, extra_header)
            logger.info(f"Effective blocklist: {len(all_domains):,} domains ({duplicates_removed:,} duplicates removed)")
        except Exception as e:
            logger.error(f"Write effective failed: {e}")
        
        status = EffectiveStatus(
            total_domains=len(all_domains),
            verified_domains=verified_domains,
            custom_domains=custom_domains,
            sources=sources,
            licenses=list(licenses),
            generated_at=generated_at,
            mode=mode,
        )
        
        self._save_metadata(verified, custom, status)
        return status
    
    # =========================================================================
    # File Operations
    # =========================================================================
    
    async def _download(self, url: str, max_size_mb: float | None = None) -> str:
        size_limit_mb = max_size_mb if max_size_mb is not None else self.network.max_size_mb
        max_bytes = int(size_limit_mb * 1024 * 1024)
        
        for attempt in range(self.network.retry_count + 1):
            try:
                return await fetch_text(
                    url,
                    max_bytes=max_bytes,
                    timeout_seconds=self.network.timeout_seconds,
                    allowed_file_root=self.data_dir / "custom_files",
                )
            except ValueError as e:
                if attempt < self.network.retry_count:
                    await asyncio.sleep(self.network.retry_delay)
                    continue
                raise ValueError(f"Feed download failed: {e}") from e
        
        raise ValueError("Download failed")
    
    def _atomic_write_blocklist(self, path: Path, domains: set[str], layer: str, sources: list[str], ts: str, extra: str = ""):
        header = f"""# EasyPi NetProtection - {layer.upper()}
# Generated: {ts}
# Domains: {len(domains)}
# Sources: {', '.join(sources) or 'none'}
{extra}
"""
        content = header + '\n'.join(sorted(domains)) + '\n'
        
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix='.tmp')
        try:
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
                f.write(content)
            os.replace(tmp_path, path)
            logger.info(f"Written {path.name}: {len(domains)} domains")
        except:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    
    def _atomic_write_json(self, path: Path, data: dict):
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.data_dir, suffix='.tmp')
        try:
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    
    def _load_blocklist(self, path: Path) -> set[str]:
        domains = set()
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.add(line)
        return domains
    
    def _save_metadata(self, verified: Optional[LayerStatus] = None, custom: Optional[LayerStatus] = None, effective: Optional[EffectiveStatus] = None):
        existing = {}
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    existing = json.load(f)
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        
        if verified:
            existing["verified"] = verified.to_dict()
        if custom:
            existing["custom"] = custom.to_dict()
        if effective:
            existing["effective"] = effective.to_dict()
        
        existing["verified_enabled"] = self._verified_enabled
        existing["updated_at"] = utc_now().isoformat()
        
        self._atomic_write_json(self.metadata_file, existing)
    
    def _load_metadata(self) -> dict:
        """Load metadata from file."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load metadata: {e}")
        return {}
    
    # =========================================================================
    # Status
    # =========================================================================
    
    async def _check_rate_limit(self) -> bool:
        now = time.time()
        if now - self._last_generation_time < self.network.min_interval_seconds:
            return False
        self._last_generation_time = now
        return True
    
    def _update_progress(self, phase: str, src: str, done: int, total: int, collected: int, progress_pct: int, msg: str):
        self._progress = GenerationProgress(phase, src, done, total, collected, progress_pct, msg)
    
    def get_progress(self) -> Optional[dict]:
        return self._progress.to_dict() if self._progress else None
    
    def get_status(self) -> dict:
        result = {
            "verified": None,
            "custom": None,
            "effective": None,
            "verified_sources": self.get_verified_sources(),
            "custom_sources": self.get_custom_sources(),
        }
        
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                result["verified"] = data.get("verified")
                result["custom"] = data.get("custom")
                result["effective"] = data.get("effective")
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        
        return result
    
    def get_effective_domains(self) -> set[str]:
        if not self.effective_file.exists():
            return set()
        try:
            return self._load_blocklist(self.effective_file)
        except OSError:
            return set()
