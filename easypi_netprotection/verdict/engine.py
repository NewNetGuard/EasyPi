"""Stable public facade for the NetProtection verdict engine."""

# ruff: noqa: F401

# ruff: noqa: F401

from easypi_netprotection.verdict.engine_components.context import (
    AD_GENESIS_AVAILABLE,
    Any,
    BlocklistFilter,
    CNAMEChainAnalyzer,
    CNAME_ANALYZER_AVAILABLE,
    ConfidenceLevel,
    DOH_DOT_DOMAINS,
    Evidence,
    EvidenceChain,
    EvidenceItem,
    EvidenceSource,
    FREQUENCY_AVAILABLE,
    FrequencyAnalyzer,
    HEURISTICS_AVAILABLE,
    HeuristicsEngine,
    IntelProvider,
    MatcherRegistry,
    NRD_AVAILABLE,
    PARENTAL_AVAILABLE,
    PROFILES_AVAILABLE,
    ParentalController,
    Path,
    ProfileManager,
    Protocol,
    RewriteManager,
    RewriteType,
    SAFESEARCH_AVAILABLE,
    SCHEDULE_CHECKER_AVAILABLE,
    STREAMING_BLOCKER_AVAILABLE,
    SafeSearchEnforcer,
    ScheduleChecker,
    ShieldProvider,
    TYPE_CHECKING,
    VerdictAction,
    VerdictModel,
    VerdictReason,
    VerdictResult,
    asyncio,
    dataclass,
    fnmatch,
    get_ad_genesis_blocklist,
    get_blocklist_filter,
    get_cname_analyzer,
    get_domains_for_service,
    get_heuristics_engine,
    get_matcher_registry,
    get_nrd_filter,
    get_parental_controller,
    get_profile_manager,
    get_rewrite_manager,
    get_safesearch_enforcer,
    get_schedule_checker,
    get_settings,
    get_streaming_blocker,
    ipaddress,
    json,
    logger,
    logging,
    sys,
    time,
    verdict_runtime,
)

from easypi_netprotection.verdict.engine_components.behavioral import (
    VerdictBehavioralMixin,
)
from easypi_netprotection.verdict.engine_components.bypass import VerdictBypassMixin
from easypi_netprotection.verdict.engine_components.decision import VerdictDecisionMixin
from easypi_netprotection.verdict.engine_components.pipeline import VerdictPipelineMixin
from easypi_netprotection.verdict.engine_components.policy_checks import (
    VerdictPolicyChecksMixin,
)
from easypi_netprotection.verdict.engine_components.post_resolution import (
    VerdictPostResolutionMixin,
)


class VerdictEngine(
    VerdictBypassMixin,
    VerdictPipelineMixin,
    VerdictPolicyChecksMixin,
    VerdictDecisionMixin,
    VerdictBehavioralMixin,
    VerdictPostResolutionMixin,
):
    """
    Orchestrates the Verdict Pipeline.

    Pipeline stages:
    0. DNS Rewrites (highest priority - custom mappings)
    1. Allowlist check
    2. Blocklist check (high-performance set lookup)
    3. Matcher evaluation (user rules)
    4. Intel analysis (domain intelligence)
    5. Shield policy check (device/profile policies)
    6. Evidence aggregation
    7. Final verdict determination
    """

    def __init__(
        self,
        matcher_registry: MatcherRegistry | None = None,
        blocklist_filter: BlocklistFilter | None = None,
        rewrite_manager: RewriteManager | None = None,
        profile_manager: "ProfileManager | None" = None,
        safesearch_enforcer: "SafeSearchEnforcer | None" = None,
        data_dir: str | None = None,
    ):
        self.settings = get_settings()
        self.matchers = matcher_registry or get_matcher_registry()

        # Blocklist filter for domain blocking
        self._blocklist = blocklist_filter or get_blocklist_filter(data_dir)

        # DNS Rewrites
        self._rewrites = rewrite_manager or get_rewrite_manager(data_dir)

        # Device Profiles (per-device filtering)
        if PROFILES_AVAILABLE:
            self._profiles = profile_manager or get_profile_manager(data_dir)
        else:
            self._profiles = None

        # Safe Search enforcer
        if SAFESEARCH_AVAILABLE:
            self._safesearch = safesearch_enforcer or get_safesearch_enforcer()
        else:
            self._safesearch = None

        # Parental Controls
        if PARENTAL_AVAILABLE:
            self._parental = get_parental_controller(data_dir)
        else:
            self._parental = None

        # Heuristics Engine (DGA, Homoglyph, First-Seen, etc.)
        if HEURISTICS_AVAILABLE and self.settings.heuristics.enabled:
            self._heuristics = get_heuristics_engine(
                data_dir=data_dir,
                observe_threshold=self.settings.heuristics.observe_threshold,
                block_threshold=self.settings.heuristics.block_threshold,
            )
            logger.info("Heuristics engine enabled")
        else:
            self._heuristics = None

        # Schedule Checker (time-based blocking from backend)
        if SCHEDULE_CHECKER_AVAILABLE:
            self._schedule_checker = get_schedule_checker(data_dir)
            logger.info("Schedule checker enabled")
        else:
            self._schedule_checker = None

        # Frequency analyzer (beaconing / burst / C2 callback detection)
        if FREQUENCY_AVAILABLE:
            self._frequency = FrequencyAnalyzer()
            logger.info("Frequency analyzer (beaconing/C2) enabled")
        else:
            self._frequency = None

        # Ad-Genesis behavioral blocklist (cheap O(1) lookup of a batch-built set;
        # ACTIVE block, logged in the query log). No-op until the batch has learned
        # from real DNS traffic, so it never blocks on a fresh install, and
        # navigation content is structurally excluded from the set.
        if AD_GENESIS_AVAILABLE and self.settings.heuristics.enabled:
            try:
                np_dir = getattr(self.settings, "NETPROTECTION_DATA_DIR", None)
                self._ad_genesis = get_ad_genesis_blocklist(np_dir) if np_dir else None
            except Exception as e:
                logger.warning(f"Ad-Genesis blocklist not loaded: {e}")
                self._ad_genesis = None
        else:
            self._ad_genesis = None

        self._intel_providers: list[IntelProvider] = []
        self._shield_provider: ShieldProvider | None = None

        # Configuration
        self._min_confidence_to_block = self.settings.verdict.min_confidence_to_block
        self._cname_uncloak_strict = bool(
            getattr(self.settings.verdict, "cname_uncloak_strict", False)
        )
        self._safe_mode = False

        # Statistics
        self._total_verdicts = 0
        self._blocked_count = 0
        self._allowed_count = 0
        self._blocklist_blocks = 0
        self._safesearch_redirects = 0
        self._parental_blocks = 0
        self._heuristics_blocks = 0
        self._heuristics_observes = 0
        self._schedule_blocks = 0
        self._avg_processing_ms = 0.0

        # Anti-bypass alerts:
        # When a managed parental profile queries known VPN/DoH/proxy/Tor domains,
        # record an alert for the UI. Depending on profile.bypass_mode, we may also
        # queue a fail-closed quarantine (full internet block).
        self._managed_parental_profile_prefix = "parental_device_"
        self._fail_closed_queue_path = (
            Path(self.settings.NETPROTECTION_DATA_DIR) / "fail_closed_requests.jsonl"
        )
        self._bypass_event_queue_path = (
            Path(self.settings.NETPROTECTION_DATA_DIR) / "bypass_events.jsonl"
        )
        # Shared state with backend/runner:
        # - backend applies quarantine by writing fail_closed_devices.json and updating iptables
        # - netprotection engine reads that file to avoid re-queueing while already quarantined
        self._fail_closed_state_path = (
            Path(self.settings.NETPROTECTION_DATA_DIR) / "fail_closed_devices.json"
        )
        self._fail_closed_state_mtime_ns: int | None = None
        self._fail_closed_state_ips: set[str] = set()
        self._fail_closed_state_macs: set[str] = set()
        self._bypass_domain_patterns: tuple[str, ...] = (
            self._load_bypass_domain_patterns()
        )
        self._bypass_domain_groups: dict[str, tuple[str, ...]] = (
            self._load_bypass_domain_groups()
        )
        self._adult_domain_patterns: tuple[str, ...] = (
            self._load_adult_domain_patterns()
        )
        # Throttle bypass event queue writes to avoid spamming disk/UI.
        self._bypass_event_min_interval_sec = 15.0
        self._bypass_event_last_by_ip: dict[str, float] = {}

        # CDN/Infrastructure whitelist for CNAME uncloaking
        # These are legitimate CDN/cloud providers that many sites use
        # CNAME to these should NOT trigger blocking
        self._cdn_whitelist_suffixes = {
            # Akamai
            ".edgekey.net",
            ".akamaiedge.net",
            ".akamai.net",
            ".akamaitechnologies.com",
            ".akamaihd.net",
            # Cloudflare
            ".cloudflare.net",
            ".cloudflare.com",
            ".cloudflare-dns.com",
            # Amazon/AWS
            ".cloudfront.net",
            ".amazonaws.com",
            ".awsglobalaccelerator.com",
            # Google
            ".googleusercontent.com",
            ".googlevideo.com",
            ".gstatic.com",
            ".googleapis.com",
            # Microsoft/Azure
            ".azureedge.net",
            ".azure.com",
            ".msedge.net",
            ".trafficmanager.net",
            # Fastly
            ".fastly.net",
            ".fastlylb.net",
            # Other CDNs
            ".edgecastcdn.net",
            ".stackpathdns.com",
            ".incapdns.net",
            ".imperva.com",
            # Social/Major sites infrastructure
            ".facebook.com",
            ".fbcdn.net",
            ".instagram.com",
            ".whatsapp.net",
            ".twitter.com",
            ".twimg.com",
            # E-commerce platforms
            ".ebay.com",
            ".ebay-us.com",
            ".ebaystatic.com",
            ".ebayimg.com",
            ".ebayrtm.com",
            ".amazon.com",
            ".amazon.de",
            ".amazon-adsystem.com",
            ".media-amazon.com",
            ".ssl-images-amazon.com",
        }


# Singleton instance
_engine: VerdictEngine | None = None


def get_verdict_engine(
    blocklist_filter: BlocklistFilter | None = None,
    data_dir: str | None = None,
) -> VerdictEngine:
    """Get the global verdict engine instance."""
    global _engine
    if _engine is None:
        _engine = VerdictEngine(
            blocklist_filter=blocklist_filter,
            data_dir=data_dir,
        )
    return _engine
