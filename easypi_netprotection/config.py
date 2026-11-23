from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class UpstreamConfig(BaseModel):
    """Configuration for upstream DNS servers."""
    
    servers: list[str] = Field(
        default=[
            "https://dns.quad9.net/dns-query",
            "tls://1.1.1.1:853",
            "tls://9.9.9.9:853",
        ],
        description="List of upstream DNS servers (DoH/DoT/DoQ URLs)",
    )
    timeout_ms: int = Field(
        default=3000,
        ge=100,
        le=30000,
        description="Timeout for upstream queries in milliseconds",
    )
    retry_count: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Number of retries on upstream failure",
    )
    health_check_interval_sec: int = Field(
        default=60,
        ge=10,
        description="Interval between upstream health checks",
    )


class CacheConfig(BaseModel):
    """Configuration for DNS response caching."""
    
    max_entries: int = Field(
        default=10000,
        ge=100,
        le=1000000,
        description="Maximum number of cached entries",
    )
    default_ttl_sec: int = Field(
        default=300,
        ge=1,
        description="Default TTL for cached responses",
    )
    negative_ttl_sec: int = Field(
        default=60,
        ge=1,
        description="TTL for negative (NXDOMAIN) responses",
    )
    min_ttl_sec: int = Field(
        default=10,
        ge=1,
        description="Minimum TTL override",
    )
    max_ttl_sec: int = Field(
        default=86400,
        ge=60,
        description="Maximum TTL cap",
    )


class ChronicleConfig(BaseModel):
    """Configuration for flow logging (Chronicle)."""
    
    enabled: bool = Field(
        default=True,
        description="Enable flow logging",
    )
    retention_days: int = Field(
        default=7,
        ge=1,
        le=90,  # Max 90 days to prevent abuse
        description="Days to retain flow logs (1-90)",
    )
    max_retention_override: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Maximum retention days allowed via API",
    )
    anonymize_ip: bool = Field(
        default=True,
        description="Hash IP addresses in logs",
    )
    anonymize_ipv6_prefix: int = Field(
        default=64,
        ge=32,
        le=128,
        description="IPv6 prefix length to preserve (rest zeroed)",
    )
    
    # Salt management (MUST be set via env NETPROTECTION_CHRONICLE__HASH_SALT)
    hash_salt: str = Field(
        default="",
        description="Salt for IP hashing (REQUIRED: set via NETPROTECTION_CHRONICLE__HASH_SALT env)",
    )
    salt_file: str = Field(
        default="data/.salt",
        description="File path for persistent salt storage",
    )
    salt_rotation_days: int = Field(
        default=30,
        ge=7,
        le=365,
        description="Days between salt rotations",
    )
    salt_double_window: bool = Field(
        default=True,
        description="Keep previous salt for double-window correlation",
    )
    
    max_entries: int = Field(
        default=100000,
        ge=1000,
        le=10000000,
        description="Maximum flow log entries before rotation",
    )
    
    # Privacy controls
    store_evidence_summary: bool = Field(
        default=True,
        description="Store evidence summary in logs (may contain PII)",
    )
    evidence_max_length: int = Field(
        default=500,
        ge=0,
        le=10000,
        description="Maximum length for evidence_summary (0=unlimited)",
    )
    store_response_ips: bool = Field(
        default=True,
        description="Store response IPs in logs (infrastructure disclosure)",
    )
    response_ips_max_count: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Maximum response IPs to store (0=unlimited)",
    )
    
    # DoS protection
    buffer_max_size: int = Field(
        default=10000,
        ge=100,
        le=100000,
        description="Maximum in-memory buffer size",
    )
    buffer_backpressure_threshold: float = Field(
        default=0.8,
        ge=0.5,
        le=1.0,
        description="Buffer fill ratio to trigger backpressure (0.8 = 80%)",
    )
    drop_on_overflow: bool = Field(
        default=True,
        description="Drop oldest entries on buffer overflow instead of blocking",
    )
    
    # Database maintenance
    db_max_size_mb: int = Field(
        default=500,
        ge=10,
        le=10000,
        description="Maximum database size in MB (triggers cleanup)",
    )
    vacuum_interval_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours between VACUUM operations",
    )
    auto_vacuum: bool = Field(
        default=True,
        description="Enable automatic database vacuuming",
    )
    
    # Failure handling
    fail_open: bool = Field(
        default=True,
        description="Continue DNS on logging failures (fail-open)",
    )
    max_consecutive_failures: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Consecutive failures before disabling logging",
    )
    
    @field_validator("hash_salt", mode="before")
    @classmethod
    def generate_salt_if_empty(cls, v: str) -> str:
        # Salt MUST come from env or file, never auto-generate at startup
        # This ensures stability across restarts
        if not v or v == "auto":
            # Return empty - will be loaded from salt_file or generated once
            return ""
        return v


class GuardianConfig(BaseModel):
    """Configuration for Guardian watchdog."""
    
    enabled: bool = Field(
        default=True,
        description="Enable Guardian watchdog",
    )
    health_check_interval_sec: int = Field(
        default=30,
        ge=5,
        description="Interval between health checks",
    )
    safe_mode_on_failure: bool = Field(
        default=True,
        description="Bypass filtering on critical failure",
    )
    max_consecutive_failures: int = Field(
        default=3,
        ge=1,
        description="Failures before triggering safe mode",
    )
    recovery_check_interval_sec: int = Field(
        default=10,
        ge=5,
        description="Interval for recovery attempts in safe mode",
    )


class HeuristicsConfig(BaseModel):
    """Configuration for Heuristics Engine."""
    
    enabled: bool = Field(
        default=True,
        description="Enable heuristics analysis",
    )
    observe_threshold: int = Field(
        default=30,
        ge=0,
        le=100,
        description="Score threshold to enter observe/shadow mode (0-100)",
    )
    block_threshold: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Score threshold to block domain (0-100)",
    )
    
    # Individual detectors
    enable_dga_detection: bool = Field(
        default=True,
        description="Enable DGA (Domain Generation Algorithm) detection",
    )
    enable_homoglyph_detection: bool = Field(
        default=True,
        description="Enable homoglyph/brand impersonation detection",
    )
    enable_first_seen_tracking: bool = Field(
        default=True,
        description="Enable first-seen domain novelty tracking",
    )
    enable_domain_analysis: bool = Field(
        default=True,
        description="Enable domain structure analysis (length, depth, numbers)",
    )
    enable_device_anomaly: bool = Field(
        default=True,
        description="Enable device traffic anomaly detection",
    )
    enable_asn_cluster: bool = Field(
        default=True,
        description="Enable ASN/IP reputation analysis",
    )
    enable_shadow_mode: bool = Field(
        default=True,
        description="Enable shadow mode (observe suspicious before blocking)",
    )
    
    # Tuning
    dga_score_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="DGA detection threshold (0.0-1.0)",
    )
    homoglyph_score_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Homoglyph detection threshold (0.0-1.0)",
    )
    first_seen_new_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description="Days to consider domain as 'new'",
    )
    enable_nrd_block: bool = Field(
        default=False,
        description="Block newly-registered domains (NRD) present in the downloaded feed",
    )
    nrd_max_age_days: int = Field(
        default=14,
        ge=1,
        le=30,
        description="NRD age window in days; selects which feed to download (7/14/30)",
    )
    shadow_auto_expire_days: int = Field(
        default=30,
        ge=7,
        le=90,
        description="Days until shadow mode entries auto-expire",
    )
    shadow_auto_promote_hits: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Hit count to auto-promote from shadow to blocklist",
    )
    
    # Performance
    quick_mode_threshold_ms: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Processing time (ms) to trigger quick mode",
    )
    persist_signals: bool = Field(
        default=True,
        description="Persist heuristic signals to database",
    )
    max_signals_per_domain: int = Field(
        default=50,
        ge=10,
        le=500,
        description="Maximum signals to store per domain",
    )


class VerdictConfig(BaseModel):
    """Configuration for Verdict Engine."""
    
    default_action: Literal["allow", "deny"] = Field(
        default="allow",
        description="Default action when no matcher hits",
    )
    enable_cname_uncloak: bool = Field(
        default=True,
        description="Follow CNAME chains for verdict",
    )
    cname_uncloak_strict: bool = Field(
        default=False,
        description="If true, block a first-party domain when ANY CNAME in its "
                    "chain is on a blocklist (aggressive — breaks legitimate sites "
                    "whose content CNAMEs through a listed domain). Default false: "
                    "block only KNOWN cloaking trackers (precise, site-safe).",
    )
    enable_entropy_check: bool = Field(
        default=True,
        description="Check subdomain entropy for tunneling",
    )
    entropy_threshold: float = Field(
        default=3.5,
        ge=2.0,
        le=5.0,
        description="Shannon entropy threshold for suspicious domains",
    )
    max_cname_depth: int = Field(
        default=8,
        ge=1,
        le=20,
        description="Maximum CNAME chain depth to follow",
    )
    min_confidence_to_block: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Minimum confidence score required to block a domain",
    )
    evidence_aggregation: Literal["weighted", "max", "average"] = Field(
        default="weighted",
        description="Method for aggregating evidence confidence scores",
    )


class ListenerConfig(BaseModel):
    """Configuration for DNS listener."""
    
    address: str = Field(
        default="0.0.0.0",
        description="Listen address for DNS server",
    )
    port: int = Field(
        default=53,
        ge=1,
        le=65535,
        description="Listen port for DNS server",
    )
    enable_udp: bool = Field(
        default=True,
        description="Enable UDP listener",
    )
    enable_tcp: bool = Field(
        default=True,
        description="Enable TCP listener",
    )
    tcp_timeout_sec: int = Field(
        default=10,
        ge=1,
        description="TCP connection timeout",
    )
    udp_workers: int = Field(default=64, ge=1, le=256)
    udp_queue_size: int = Field(default=2048, ge=64, le=16384)
    max_concurrent_queries: int = Field(default=256, ge=16, le=2048)
    max_client_queries: int = Field(default=64, ge=4, le=512)
    max_connections: int = Field(default=256, ge=16, le=2048)


class EncryptedDnsConfig(BaseModel):
    """Configuration for encrypted DNS listeners (DoH/DoT)."""

    doh_enabled: bool = Field(
        default=False,
        description="Enable DNS over HTTPS (DoH) listener",
    )
    doh_address: str = Field(
        default="0.0.0.0",
        description="Listen address for DoH server",
    )
    doh_port: int = Field(
        default=8053,
        ge=1,
        le=65535,
        description="Listen port for DoH server",
    )
    doh_path: str = Field(
        default="/dns-query",
        description="DoH endpoint path",
    )
    dot_enabled: bool = Field(
        default=False,
        description="Enable DNS over TLS (DoT) listener",
    )
    dot_address: str = Field(
        default="0.0.0.0",
        description="Listen address for DoT server",
    )
    dot_port: int = Field(
        default=853,
        ge=1,
        le=65535,
        description="Listen port for DoT server",
    )
    tls_cert_path: str = Field(
        default="certs/cert.pem",
        description="TLS certificate path",
    )
    tls_key_path: str = Field(
        default="certs/key.pem",
        description="TLS private key path",
    )


class VaultConfig(BaseModel):
    """Configuration for data persistence."""
    
    db_path: Path = Field(
        default=Path("data/netprotection.db"),
        description="Path to SQLite database",
    )
    encryption_enabled: bool = Field(
        default=True,
        description="Enable config encryption",
    )
    backup_on_start: bool = Field(
        default=True,
        description="Create DB backup on service start",
    )
    max_backups: int = Field(
        default=5,
        ge=1,
        description="Maximum number of backup files to keep",
    )


class NetProtectionSettings(BaseSettings):
    """Root configuration for EasyPi NetProtection."""
    
    model_config = SettingsConfigDict(
        env_prefix="NETPROTECTION_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )
    
    enabled: bool = Field(
        default=True,
        description="Enable NetProtection module",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug logging",
    )
    block_mode: Literal["zero_address", "nxdomain"] = Field(
        default="zero_address",
        description="DNS response returned for blocked A and AAAA queries",
    )
    
    listener: ListenerConfig = Field(default_factory=ListenerConfig)
    encrypted_dns: EncryptedDnsConfig = Field(default_factory=EncryptedDnsConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    chronicle: ChronicleConfig = Field(default_factory=ChronicleConfig)
    guardian: GuardianConfig = Field(default_factory=GuardianConfig)
    verdict: VerdictConfig = Field(default_factory=VerdictConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    heuristics: HeuristicsConfig = Field(default_factory=HeuristicsConfig)
    
    @classmethod
    def from_toml(cls, path: Path | str) -> NetProtectionSettings:
        """Load settings from TOML file."""
        import tomllib
        
        path = Path(path)
        if not path.exists():
            return cls()
        
        with open(path, "rb") as f:
            data = tomllib.load(f)
        
        np_config = data.get("netprotection", {})
        return cls(**np_config)
    
    def to_toml(self, path: Path | str) -> None:
        """Save settings to TOML file."""
        try:
            import tomli_w
        except ImportError:
            raise ImportError(
                "tomli_w is required for saving config. "
                "Install with: pip install tomli-w"
            )
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {"netprotection": self.model_dump(mode="json")}
        
        with open(path, "wb") as f:
            tomli_w.dump(data, f)
    
    # Backward compatibility properties for code expecting flat structure
    @property
    def listen_address(self) -> str:
        """Backward compatibility: return listener.address"""
        return self.listener.address
    
    @property
    def listen_port(self) -> int:
        """Backward compatibility: return listener.port"""
        return self.listener.port
    
    @property
    def NETPROTECTION_DATA_DIR(self) -> Path:
        """Backward compatibility: return data directory path."""
        # Use vault.db_path parent or default to data/netprotection
        if self.vault.db_path.parent != Path("."):
            return self.vault.db_path.parent
        return Path("data/netprotection")

_settings: NetProtectionSettings | None = None


def get_settings() -> NetProtectionSettings:
    """Get cached settings instance."""
    global _settings
    if _settings is None:
        config_path = os.environ.get("NETPROTECTION_CONFIG")
        if not config_path:
            preferred_path = Path("/opt/EasyPi/config/netprotection.toml")
            if preferred_path.exists():
                config_path = str(preferred_path)
            else:
                config_path = "config/netprotection.toml"
        _settings = NetProtectionSettings.from_toml(config_path)
    return _settings


def reload_settings() -> NetProtectionSettings:
    """Force reload settings from file."""
    global _settings
    _settings = None
    return get_settings()


def load_config(path: Path | str | None = None) -> NetProtectionSettings:
    """
    Load configuration from file or environment.
    
    Args:
        path: Optional path to config file. If None, uses default or env var.
    
    Returns:
        NetProtectionSettings instance.
    """
    if path:
        return NetProtectionSettings.from_toml(path)
    return get_settings()


# Alias for backward compatibility
NetProtectionConfig = NetProtectionSettings
