"""
Device Profile Models

Data models for per-device DNS filtering profiles.

SECURITY NOTES:
- MAC addresses can be spoofed; use IP bindings in trusted networks only
- CIDR ranges should not be too broad (max /16 for safety)
- Binding priority: MAC > IP > CIDR > Default profile
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class FilterLevel(Enum):
    """Predefined filtering levels."""
    
    NONE = "none"              # No filtering (passthrough)
    MINIMAL = "minimal"        # Only malware/phishing
    STANDARD = "standard"      # Malware + ads + trackers
    STRICT = "strict"          # Everything + adult content
    CUSTOM = "custom"          # Custom blocklist selection


class BindingType(Enum):
    """
    Device binding type.
    
    Priority order (highest to lowest):
    1. MAC - most specific, but can be spoofed
    2. IP  - single IP, use only for static assignments
    3. RANGE - CIDR block, use sparingly
    """
    
    MAC = "mac"       # MAC address binding (priority 1)
    IP = "ip"         # IP address binding (priority 2)
    RANGE = "range"   # IP range (CIDR) (priority 3)
    
    @property
    def priority(self) -> int:
        """Binding type priority (higher = more specific)."""
        return {
            BindingType.MAC: 100,
            BindingType.IP: 50,
            BindingType.RANGE: 10,
        }.get(self, 0)


# MAC address regex (various formats)
MAC_PATTERNS = [
    re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'),       # aa:bb:cc:dd:ee:ff
    re.compile(r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$'),       # aa-bb-cc-dd-ee-ff
    re.compile(r'^[0-9A-Fa-f]{12}$'),                           # aabbccddeeff
]

# Maximum CIDR prefix lengths (to prevent too-broad ranges)
MAX_CIDR_PREFIX_V4 = 16   # /16 = 65536 addresses max
MAX_CIDR_PREFIX_V6 = 48   # /48 for IPv6

# Special profile blacklist entry that enables adult-domain heuristics.
ADULT_HEURISTIC_MARKER = "__adult_heuristic__"

# High-confidence adult TLDs.
ADULT_TLDS = frozenset({"porn", "xxx", "adult", "sex"})

# Strong adult indicators with low false-positive risk.
ADULT_STRONG_SUBSTRINGS = (
    "porn",
    "xnxx",
    "xvideos",
    "xhamster",
    "youporn",
    "redtube",
    "tube8",
    "spankbang",
    "chaturbate",
    "stripchat",
    "livejasmin",
    "brazzers",
    "bangbros",
    "realitykings",
    "camgirl",
    "camgirls",
    "camsex",
    "onlyfans",
    "fansly",
    "manyvids",
    "hentai",
    "nsfw",
    "escort",
    "milf",
    "boobs",
    # Adult brands and infra seen in the wild
    "faphouse",
    "noodlemagazine",
    "xgroovy",
    "xhcdn",
    "ahcdn",
    "flixcdn",
    "pvvstream",
    "fuq",
    "phncdn",
    "xvv1deos",
)

# Cyrillic adult indicators (high confidence).
ADULT_RU_STRONG_SUBSTRINGS = (
    "порно",
    "эрот",
    "секс",
    "хентай",
    "ебля",
    "трах",
    "шлюх",
    "минет",
)

# Weak indicators are only applied when they are standalone tokens/labels.
ADULT_WEAK_TOKENS = frozenset({
    "sex",
    "nude",
    "naked",
    "erotic",
    "fetish",
    "cams",
    "cam",
    "18plus",
    "xxx",
})

# Cyrillic weak indicators (token-based).
ADULT_RU_WEAK_TOKENS = frozenset({
    "секс",
    "порно",
    "эротика",
    "хентай",
})

# Common benign words that include "sex" but are not adult content.
ADULT_BENIGN_EXACT = frozenset({
    "essex",
    "sussex",
    "middlesex",
})

# Exact domains that should always be treated as adult services.
ADULT_KNOWN_BASE_DOMAINS = frozenset({
    "fuq.com",
    "faphouse.com",
    "noodlemagazine.com",
    "xhcdn.com",
    "ahcdn.com",
    "flixcdn.com",
    "pvvstream.pro",
    "xgroovy.com",
    "phncdn.com",
    "brazzersnetwork.com",
    "xvv1deos.com",
    "yaeby.channel",
    "yaeby.work",
    "project1content.com",
    "project1service.com",
})

# Obfuscated adult-brand patterns (leet/variant spellings).
ADULT_STRONG_PATTERNS = (
    re.compile(r"xv+i+deos"),   # xvideos, xvvideos, xv1deos, etc.
    re.compile(r"pornh[uv]b"),  # pornhub variants like pornhvb
)

# Lightweight leetspeak normalization for domain-label matching.
_LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
})


def _base_domain(labels: list[str]) -> str:
    """Extract a simple base domain (last two labels)."""
    if len(labels) >= 2:
        return labels[-2] + "." + labels[-1]
    return labels[0] if labels else ""


def _decode_idna_label(label: str) -> str:
    """
    Decode one domain label from punycode when possible.

    Keeps original label on decode errors.
    """
    if not label:
        return label
    if not label.isascii():
        return label
    try:
        return label.encode("ascii").decode("idna")
    except Exception:
        return label


def _domain_variants_for_matching(domain: str) -> list[str]:
    """
    Build normalized domain variants for heuristic matching.

    Returns at least the input domain and, when available, a decoded IDN form.
    """
    normalized = domain.lower().strip().rstrip(".")
    if not normalized:
        return []

    variants = [normalized]
    labels = [p for p in normalized.split(".") if p]
    if labels:
        decoded_labels = [_decode_idna_label(label).lower() for label in labels]
        decoded = ".".join(decoded_labels)
        if decoded and decoded != normalized:
            variants.append(decoded)
    return variants


def _normalize_label_for_adult_matching(label: str) -> str:
    """Normalize a DNS label for resilient adult-keyword matching."""
    normalized = label.lower().translate(_LEET_TRANSLATION)
    # Keep alnum only to compare obfuscated variants reliably.
    normalized = re.sub(r"[^a-z0-9а-яё]+", "", normalized)
    return normalized


def _matches_adult_heuristics(domain: str) -> bool:
    """
    Detect likely adult domains without a giant static list.

    The goal is to improve parental blocking coverage for new/mirror domains
    while keeping false positives manageable.
    """
    variants = _domain_variants_for_matching(domain)
    for normalized in variants:
        if "." not in normalized:
            continue

        labels = [label for label in normalized.split(".") if label]
        if len(labels) < 2:
            continue

        # High-confidence exact base-domain matches.
        if _base_domain(labels) in ADULT_KNOWN_BASE_DOMAINS:
            return True

        # Strong TLD signal.
        if labels[-1] in ADULT_TLDS:
            return True

        for raw_label in labels[:-1]:
            if not raw_label:
                continue

            label = raw_label.replace("_", "-")
            if label in ADULT_BENIGN_EXACT:
                continue

            normalized_label = _normalize_label_for_adult_matching(label)
            label_candidates = (label, normalized_label)

            # High-confidence substrings (brand names + explicit terms).
            for candidate in label_candidates:
                if not candidate:
                    continue
                if any(keyword in candidate for keyword in ADULT_STRONG_SUBSTRINGS):
                    return True
                if any(keyword in candidate for keyword in ADULT_RU_STRONG_SUBSTRINGS):
                    return True
                if any(pattern.search(candidate) for pattern in ADULT_STRONG_PATTERNS):
                    return True

            # Split label to tokens for weaker terms.
            tokens = [t for t in re.split(r"[^a-z0-9а-яё]+", label) if t]
            if normalized_label:
                tokens.append(normalized_label)
            for token in tokens:
                if token in ADULT_BENIGN_EXACT:
                    continue
                if token in ADULT_WEAK_TOKENS or token in ADULT_RU_WEAK_TOKENS:
                    return True
                # Catch "sexshop", "sexchat", "sexvideo", etc.
                if token.startswith("sex") and token not in ADULT_BENIGN_EXACT:
                    return True

            # Common composition patterns.
            if "cam" in label and ("girl" in label or "girls" in label or "sex" in label):
                return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# ADULT DOMAIN FEED (large maintained blocklist, O(1) membership)
# ═══════════════════════════════════════════════════════════════════════════════
# A curated static list + heuristics cannot cover the long tail of adult sites
# (beeg, txxx, youjizz, ...). We load a large adult-domains feed (refreshed by
# scripts/settings/update_adult_blocklist.sh) into a frozenset and consult it for
# any profile that enables adult blocking (via ADULT_HEURISTIC_MARKER). Lookup is
# O(1), so it stays fast on the DNS hot path.

_ADULT_FEED: frozenset[str] | None = None
_ADULT_FEED_MTIME: float | None = None
_ADULT_FEED_PATH: Path | None = None


def _adult_feed_path() -> Path:
    global _ADULT_FEED_PATH
    if _ADULT_FEED_PATH is None:
        try:
            from ..config import get_settings
            _ADULT_FEED_PATH = Path(get_settings().NETPROTECTION_DATA_DIR) / "adult_domains.txt"
        except Exception:
            _ADULT_FEED_PATH = Path("/opt/EasyPi/data/netprotection/adult_domains.txt")
    return _ADULT_FEED_PATH


def _get_adult_feed() -> frozenset:
    """Lazily load the adult-domains feed, reloading when the file changes."""
    global _ADULT_FEED, _ADULT_FEED_MTIME
    path = _adult_feed_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        _ADULT_FEED = frozenset()
        _ADULT_FEED_MTIME = None
        return _ADULT_FEED
    if _ADULT_FEED is None or _ADULT_FEED_MTIME != mtime:
        domains: set[str] = set()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for raw in fh:
                    line = raw.strip().lower()
                    if not line or line[0] in "#!":
                        continue
                    dom = line.split()[-1].strip().rstrip(".")
                    if dom and "." in dom:
                        domains.add(dom)
        except OSError:
            pass
        _ADULT_FEED = frozenset(domains)
        _ADULT_FEED_MTIME = mtime
    return _ADULT_FEED


def _in_adult_feed(domain: str) -> bool:
    """O(1) membership check against the adult feed (exact + registrable base)."""
    feed = _get_adult_feed()
    if not feed:
        return False
    d = domain.lower().strip().rstrip(".")
    if not d:
        return False
    if d in feed:
        return True
    labels = d.split(".")
    # Check the registrable base and one level up (covers www./cdn. subdomains).
    for n in (2, 3):
        if len(labels) >= n:
            candidate = ".".join(labels[-n:])
            if candidate in feed:
                return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# PII MASKING FOR LOGS
# ═══════════════════════════════════════════════════════════════════════════════

def mask_mac(mac: str) -> str:
    """Mask MAC address for logging (show only OUI prefix)."""
    try:
        normalized = normalize_mac(mac)
        parts = normalized.split(':')
        # Show OUI (first 3 octets), mask the rest
        return f"{parts[0]}:{parts[1]}:{parts[2]}:xx:xx:xx"
    except ValueError:
        return "xx:xx:xx:xx:xx:xx"


def mask_ip(ip: str) -> str:
    """Mask IP address for logging."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            # Show first two octets: 192.168.xxx.xxx
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        else:
            # IPv6: show first 4 groups
            parts = ip.split(':')
            return ':'.join(parts[:4]) + '::xxxx'
    except ValueError:
        return "x.x.x.x"


def hash_identifier(value: str, salt: str = "") -> str:
    """Hash identifier for correlation without exposing PII."""
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:12]


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to lowercase colon-separated format."""
    # Remove all separators
    clean = re.sub(r'[:\-.]', '', mac.upper())
    
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address length: {mac}")
    
    if not re.match(r'^[0-9A-F]{12}$', clean):
        raise ValueError(f"Invalid MAC address characters: {mac}")
    
    # Format as aa:bb:cc:dd:ee:ff
    return ':'.join(clean[i:i+2].lower() for i in range(0, 12, 2))


def validate_mac(mac: str) -> bool:
    """Check if string is a valid MAC address."""
    try:
        normalize_mac(mac)
        return True
    except ValueError:
        return False


@dataclass
class DeviceBinding:
    """
    Binding of a device identifier to a profile.
    
    Supports:
    - MAC address (priority 1, most specific but spoofable)
    - Static IP address (priority 2)
    - IP range (CIDR notation, priority 3)
    
    SECURITY NOTES:
    - MAC addresses can be spoofed by local attackers
    - IP bindings should use static DHCP reservations
    - CIDR ranges limited to /16 to prevent overly broad rules
    """
    
    id: str
    profile_id: str
    binding_type: BindingType
    value: str                    # MAC, IP, or CIDR
    name: str = ""                # Friendly device name
    enabled: bool = True
    trusted: bool = False         # Whether in trusted network zone
    last_seen: datetime | None = None
    query_count: int = 0
    blocked_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate and normalize binding value."""
        if isinstance(self.binding_type, str):
            self.binding_type = BindingType(self.binding_type)
        
        # Normalize value
        if self.binding_type == BindingType.MAC:
            self.value = normalize_mac(self.value)
        elif self.binding_type == BindingType.IP:
            self._validate_ip(self.value)
        elif self.binding_type == BindingType.RANGE:
            self._validate_cidr(self.value)
    
    @property
    def priority(self) -> int:
        """Get binding priority for conflict resolution."""
        base = self.binding_type.priority
        # Trusted bindings get +10 priority boost
        return base + (10 if self.trusted else 0)
    
    def _validate_ip(self, ip: str) -> None:
        """Validate IP address."""
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip}") from e
    
    def _validate_cidr(self, cidr: str) -> None:
        """Validate CIDR notation with size limits."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Security: limit range size
            if network.version == 4:
                if network.prefixlen < MAX_CIDR_PREFIX_V4:
                    raise ValueError(
                        f"CIDR range too broad: /{network.prefixlen}. "
                        f"Maximum is /{MAX_CIDR_PREFIX_V4} (65536 addresses)"
                    )
            else:  # IPv6
                if network.prefixlen < MAX_CIDR_PREFIX_V6:
                    raise ValueError(
                        f"IPv6 CIDR range too broad: /{network.prefixlen}. "
                        f"Maximum is /{MAX_CIDR_PREFIX_V6}"
                    )
        except ValueError:
            raise
    
    def matches(self, client_ip: str, client_mac: str | None = None) -> bool:
        """Check if this binding matches the given client."""
        if not self.enabled:
            return False
        
        if self.binding_type == BindingType.MAC:
            if client_mac:
                try:
                    return normalize_mac(client_mac) == self.value
                except ValueError:
                    return False
            return False
        
        elif self.binding_type == BindingType.IP:
            return client_ip == self.value
        
        elif self.binding_type == BindingType.RANGE:
            try:
                network = ipaddress.ip_network(self.value, strict=False)
                ip = ipaddress.ip_address(client_ip)
                return ip in network
            except ValueError:
                return False
        
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "profile_id": self.profile_id,
            "binding_type": self.binding_type.value,
            "value": self.value,
            "name": self.name,
            "enabled": self.enabled,
            "trusted": self.trusted,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "query_count": self.query_count,
            "blocked_count": self.blocked_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceBinding":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            profile_id=data["profile_id"],
            binding_type=BindingType(data["binding_type"]),
            value=data["value"],
            name=data.get("name", ""),
            enabled=data.get("enabled", True),
            trusted=data.get("trusted", False),
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            query_count=data.get("query_count", 0),
            blocked_count=data.get("blocked_count", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )


@dataclass
class DeviceProfile:
    """
    Device filtering profile.
    
    Defines what filtering rules apply to devices bound to this profile.
    """
    
    id: str
    name: str
    description: str = ""
    filter_level: FilterLevel = FilterLevel.STANDARD
    
    # Custom blocklist selection (when filter_level == CUSTOM)
    enabled_blocklists: list[str] = field(default_factory=list)
    
    # Custom whitelist for this profile
    whitelist: list[str] = field(default_factory=list)
    
    # Custom blacklist for this profile (additional blocks)
    blacklist: list[str] = field(default_factory=list)
    
    # SafeSearch enforcement
    safe_search: bool = False

    # Explicit Parental Control state for auto-managed device profiles.
    # A managed profile can also exist solely for Shield or Safe Browsing, so
    # its id/name must never be treated as proof that parental policy is on.
    parental_enabled: bool = False

    # Anti-bypass response mode (used by auto-managed parental profiles).
    # - warn: block bypass channels/endpoints (default)
    # - quarantine: full internet off when bypass is detected (fail-closed)
    # - log_only: monitor only (may allow bypass)
    bypass_mode: str = "warn"
    
    # Time-based restrictions
    schedule_enabled: bool = False
    schedule: dict[str, Any] = field(default_factory=dict)  # Day -> hours
    
    # Logging
    log_queries: bool = True
    
    # Is this the default profile for unbound devices?
    is_default: bool = False
    
    # Stats
    device_count: int = 0
    
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate and normalize."""
        if isinstance(self.filter_level, str):
            self.filter_level = FilterLevel(self.filter_level)

        mode = str(self.bypass_mode or "warn").strip().lower()
        if mode not in {"warn", "quarantine", "log_only"}:
            mode = "warn"
        self.bypass_mode = mode
        
        # Normalize domain lists
        self.whitelist = [d.lower().strip().rstrip('.') for d in self.whitelist]
        self.blacklist = [d.lower().strip().rstrip('.') for d in self.blacklist]
    
    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in profile whitelist."""
        domain = domain.lower().rstrip('.')
        
        for pattern in self.whitelist:
            # General wildcard support (e.g., *xvideos*, *.porn)
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatch(domain, pattern):
                    return True
                continue
            if pattern.startswith('*.'):
                # Legacy wildcard
                base = pattern[2:]
                if domain == base or domain.endswith('.' + base):
                    return True
                continue
            if domain == pattern:
                return True
            if '.' in pattern and domain.endswith('.' + pattern):
                return True
        
        return False
    
    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain is in profile blacklist."""
        domain = domain.lower().rstrip('.')
        
        for pattern in self.blacklist:
            # Special marker used for dynamic adult-domain detection.
            if pattern == ADULT_HEURISTIC_MARKER:
                if _matches_adult_heuristics(domain) or _in_adult_feed(domain):
                    return True
                continue
            # General wildcard support (e.g., *xvideos*, *.porn)
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatch(domain, pattern):
                    return True
                continue
            if pattern.startswith('*.'):
                base = pattern[2:]
                if domain == base or domain.endswith('.' + base):
                    return True
                continue
            if domain == pattern:
                return True
            if '.' in pattern and domain.endswith('.' + pattern):
                return True
        
        return False
    
    def is_active_now(self) -> bool:
        """Check if profile is active based on schedule."""
        if not self.schedule_enabled or not self.schedule:
            return True
        
        now = datetime.now()
        day_name = now.strftime('%A').lower()  # monday, tuesday, etc.
        current_hour = now.hour
        
        day_schedule = self.schedule.get(day_name, {})
        if not day_schedule:
            return True  # No restrictions for this day
        
        start_hour = day_schedule.get('start', 0)
        end_hour = day_schedule.get('end', 24)
        
        # Check if current time is within restricted hours
        if start_hour <= current_hour < end_hour:
            return True
        
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "filter_level": self.filter_level.value,
            "enabled_blocklists": self.enabled_blocklists,
            "whitelist": self.whitelist,
            "blacklist": self.blacklist,
            "safe_search": self.safe_search,
            "parental_enabled": self.parental_enabled,
            "bypass_mode": self.bypass_mode,
            "schedule_enabled": self.schedule_enabled,
            "schedule": self.schedule,
            "log_queries": self.log_queries,
            "is_default": self.is_default,
            "device_count": self.device_count,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceProfile":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            filter_level=FilterLevel(data.get("filter_level", "standard")),
            enabled_blocklists=data.get("enabled_blocklists", []),
            whitelist=data.get("whitelist", []),
            blacklist=data.get("blacklist", []),
            safe_search=data.get("safe_search", False),
            parental_enabled=data.get("parental_enabled", False),
            bypass_mode=data.get("bypass_mode", "warn"),
            schedule_enabled=data.get("schedule_enabled", False),
            schedule=data.get("schedule", {}),
            log_queries=data.get("log_queries", True),
            is_default=data.get("is_default", False),
            device_count=data.get("device_count", 0),
            enabled=data.get("enabled", True),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )


# Predefined filter level blocklist mappings
FILTER_LEVEL_BLOCKLISTS = {
    FilterLevel.NONE: [],
    FilterLevel.MINIMAL: [
        "malware",
        "phishing",
    ],
    FilterLevel.STANDARD: [
        "malware",
        "phishing",
        "ads",
        "trackers",
    ],
    FilterLevel.STRICT: [
        "malware",
        "phishing",
        "ads",
        "trackers",
        "adult",
        "gambling",
        "social",
    ],
}
