"""Stable NetProtection service facade.

Runtime capabilities are initialized in the acyclic component context.
"""

# ruff: noqa: F401

from app.services.netprotection_components.runtime_context import (
    ADULT_HEURISTIC_MARKER,
    APP_BLOCKER_AVAILABLE,
    Any,
    AppBlocker,
    AppleMusicFlowPolicy,
    CandidateFlow,
    CandidateLogFollower,
    DEFAULT_MIN_UNEXPLAINED_FLOWS,
    DEFAULT_MIN_WAN_BYTES,
    DEFAULT_RESOLVED_WINDOW_SEC,
    DNS_SHADOW_AVAILABLE,
    DNS_SHADOW_DOMAIN,
    DNS_SHADOW_GROUP,
    DailymotionFlowPolicy,
    DeezerFlowPolicy,
    DeviceAnomalyStoreError,
    Dict,
    DisneyFlowPolicy,
    EASYPI_ROOT,
    EpicGamesFlowPolicy,
    FLOW_LOGGER_AVAILABLE,
    FacebookFlowPolicy,
    FlowEntry,
    FlowLogStorage,
    FlowLogger,
    FlowStatus,
    GooglePlayFlowPolicy,
    HboFlowPolicy,
    IPAnonymizer,
    IP_BLOCK_CATALOG_EXCLUSIONS,
    IP_BLOCK_SERVICES,
    InstagramFlowPolicy,
    List,
    MinecraftFlowPolicy,
    NETPROTECTION_AVAILABLE,
    NetProtectionConfig,
    NetProtectionServer,
    Optional,
    PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS,
    PRISM_FLOW_ENFORCER_RETRY_SECONDS,
    PRISM_FLOW_ENFORCER_STABLE_SECONDS,
    PRISM_FLOW_POLICY_POLL_SECONDS,
    Path,
    PinterestFlowPolicy,
    PlayStationFlowPolicy,
    PrimeVideoFlowPolicy,
    QueryType,
    RobloxFlowPolicy,
    SaltManager,
    ScheduleStoreError,
    SignalFlowPolicy,
    SnapchatFlowPolicy,
    SoundCloudFlowPolicy,
    SpotifyFlowPolicy,
    SteamFlowPolicy,
    TikTokFlowPolicy,
    TinderFlowPolicy,
    TumblrFlowPolicy,
    TwitchFlowPolicy,
    VimeoFlowPolicy,
    WeChatFlowPolicy,
    XboxFlowPolicy,
    _cert_has_san,
    _compute_windowed_bytes,
    _detect_dns_shadow,
    _parse_conntrack_snapshot,
    _read_recent_resolved_ips,
    _sanitize_mac,
    _short_err,
    asyncio,
    datetime,
    fnmatch,
    get_all_domains_for_services,
    get_catalog_categories,
    get_catalog_services,
    get_easypi_root,
    get_netprotection_data_dir,
    importlib,
    json,
    logger,
    logging,
    os,
    re,
    sanitize_domain,
    sanitize_mac,
    subprocess,
    sys,
    time,
    timezone,
    trigger_profiles_reload,
    uuid,
    validate_flowgraph_candidate_event,
)

from app.services.netprotection_components.analytics import AnalyticsMixin  # noqa: E402
from app.services.netprotection_components.policy_data import PolicyDataMixin  # noqa: E402
from app.services.netprotection_components.schedules import SchedulesMixin  # noqa: E402
from app.services.netprotection_components.settings import SettingsMixin  # noqa: E402
from app.services.netprotection_components.shadow_apps import ShadowAppsMixin  # noqa: E402
from app.services.netprotection_components.threat_blocklists import (  # noqa: E402
    ThreatBlocklistsMixin,
)


from app.services.netprotection_components.detection import DetectionMixin  # noqa: E402
from app.services.netprotection_components.dns_runtime import DnsRuntimeMixin  # noqa: E402
from app.services.netprotection_components.parental import ParentalMixin  # noqa: E402
from app.services.netprotection_components.runtime import RuntimeMixin  # noqa: E402


class NetProtectionService(
    AnalyticsMixin,
    PolicyDataMixin,
    ThreatBlocklistsMixin,
    SchedulesMixin,
    SettingsMixin,
    ShadowAppsMixin,
    DetectionMixin,
    RuntimeMixin,
    DnsRuntimeMixin,
    ParentalMixin,
):
    """
    Service for EasyPi NetProtection DNS engine.

    Provides:
    - Status and statistics
    - Verdict history (query log) with SQLite persistence
    - Matchers (blocklist rules)
    - Shield profiles
    - Device management
    - Threat intelligence
    """

    _TOR_BRIDGE_PATTERNS: tuple[str, ...] = (
        "bridges.torproject.org",
        "*.bridges.torproject.org",
        "bridge.torproject.org",
        "*.bridge.torproject.org",
        "snowflake.torproject.org",
        "*.snowflake.torproject.org",
        "snowflake-broker.torproject.net",
        "*.snowflake-broker.torproject.net",
    )

    def __init__(self):
        self._server: Optional[Any] = None
        self._config: Optional[Any] = None
        self._verdict_engine: Optional[Any] = None
        self._threat_db: Optional[Any] = None
        self._domain_exporter: Optional[Any] = None
        self._flow_logger: Optional[Any] = None

        # Data paths - use centralized paths
        self.data_dir = get_netprotection_data_dir()
        self.db_path = self.data_dir / "threats.db"
        self.flow_log_path = self.data_dir / "flow_log.db"
        self.prism_flowgraph_path = Path("/var/lib/easypi/prism/flowgraph.jsonl")
        self.config_path = self.data_dir / "config.json"
        self.verdicts_path = self.data_dir / "verdicts.json"

        # In-memory stats (will be replaced by actual engine)
        self._stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "allowed_queries": 0,
            "cache_hits": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        # Recent verdicts (ring buffer) - fallback if FlowLogger not available
        self._recent_verdicts: List[Dict] = []
        self._max_verdicts = 1000

        # Query log configuration
        self._query_log_config = {
            "enabled": True,
            "store_evidence": True,
            "store_response_ips": True,
            "retention_days": 7,
        }
        # Browsing Activity combines bounded reads from DNS SQLite and PRISM's
        # append-only flow graph. Cache the merged view so a dashboard poll does
        # not rescan both stores on every request.
        self._browsing_activity_cache: dict[str, tuple[float, list[dict]]] = {}
        self._browsing_activity_cache_lock = asyncio.Lock()
        self._browsing_activity_forced_refresh: dict[str, float] = {}
        # Fail-closed queue (produced by netprotection engine, consumed by backend with sudo runner)
        self._fail_closed_queue_path = self.data_dir / "fail_closed_requests.jsonl"
        self._fail_closed_queue_processing_path = (
            self.data_dir / "fail_closed_requests.processing"
        )
        self._fail_closed_lock = asyncio.Lock()
        self._client_policy_lock = asyncio.Lock()
        self._schedules_lock = asyncio.Lock()
        self._fail_closed_worker_task: asyncio.Task | None = None
        self._failsafe_monitor_task: asyncio.Task | None = None
        self._prism_flow_policy_task: asyncio.Task | None = None
        # Persist the last known fail-closed trigger per IP for UI (why internet was blocked).
        self._fail_closed_meta_path = self.data_dir / "fail_closed_meta.json"
        self._fail_closed_bypass_pattern_cache: dict[str, tuple[str, ...]] = {}

        # Anti-bypass alerts queue (produced by netprotection engine, consumed by backend for UI banner).
        self._bypass_events_queue_path = self.data_dir / "bypass_events.jsonl"
        self._bypass_events_queue_processing_path = (
            self.data_dir / "bypass_events.processing"
        )
        self._bypass_events_lock = asyncio.Lock()
        self._bypass_auto_quarantine_timeout_sec = 60.0
        # Persist last bypass event + acknowledgment timestamp per IP.
        self._bypass_events_meta_path = self.data_dir / "bypass_events_meta.json"

        # Network-layer bypass detector: watches per-device firewall REJECT
        # counters and raises an alert when a protected device attempts a blocked
        # bypass channel (VPN/DoH/proxy/Tor/SmartDNS) that never shows up as a DNS
        # query (e.g. a VPN tunnel). {ip: {channel: reject_pkts}} baseline.
        self._bypass_counter_baseline: dict[str, dict[str, int]] = {}
        self._bypass_detect_last_run: float = 0.0
        self._bypass_detect_interval_sec: float = 6.0
        # Short cooldown so that turning a VPN on AGAIN (after the admin allowed
        # internet or dismissed the banner) re-raises the alert almost immediately,
        # instead of staying silent. Still long enough to avoid a new banner on
        # every single 6s detector tick during one continuous attempt.
        self._bypass_alert_cooldown_sec: float = 10.0

        # DNS-shadow detector: protected device has meaningful external WAN
        # traffic while EasyPi sees no recent DNS queries from that device. This
        # catches obfuscated tunnels indirectly, without DPI or TLS inspection.
        self._dns_shadow_detect_last_run: float = 0.0
        self._dns_shadow_detect_interval_sec: float = float(
            os.getenv("EASYPI_DNS_SHADOW_INTERVAL_SEC", "10")
        )
        # How long a resolved answer IP stays "known" (covers DNS caching so we don't flag
        # a device revisiting a long-TTL host it resolved a while ago).
        self._dns_shadow_resolved_window_sec: float = float(
            os.getenv(
                "EASYPI_DNS_SHADOW_RESOLVED_WINDOW_SEC",
                str(DEFAULT_RESOLVED_WINDOW_SEC),
            )
        )
        self._dns_shadow_min_wan_bytes: int = int(
            os.getenv("EASYPI_DNS_SHADOW_MIN_WAN_BYTES", str(DEFAULT_MIN_WAN_BYTES))
        )
        self._dns_shadow_min_external_flows: int = int(
            os.getenv(
                "EASYPI_DNS_SHADOW_MIN_EXTERNAL_FLOWS",
                str(DEFAULT_MIN_UNEXPLAINED_FLOWS),
            )
        )
        self._dns_shadow_huge_wan_bytes: int = int(
            os.getenv(
                "EASYPI_DNS_SHADOW_HUGE_WAN_BYTES", str(DEFAULT_MIN_WAN_BYTES * 6)
            )
        )
        self._dns_shadow_suspect_by_ip: dict[str, dict[str, float | int]] = {}
        # Per-connection byte counters from the previous conntrack snapshot, so WAN traffic
        # is measured as a windowed delta (see compute_windowed_bytes), not a lifetime total.
        self._dns_shadow_prev_counters: dict[tuple, int] = {}
        self._dns_shadow_baseline_ready: bool = False
        self._dns_shadow_acct_warned: bool = False

    # --- Visited-domain classification (Parental Controls "Visited sites") -----------
    # Registrable-domain suffixes that are never a "site you visit" — pure
    # infra / service / CDN / telemetry / ad-network endpoints.
    _VISITED_INFRA_SUFFIXES = (
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "ggpht.com",
        "ytimg.com",
        "googlevideo.com",
        "gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "appspot.com",
        "aliyuncs.com",
        "samsungapis.com",
        "samsungosp.com",
        "samsungcloud.com",
        "xtracloud.net",
        "google-analytics.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "googletagservices.com",
        "googleadservices.com",
        "doubleclick.net",
        "2mdn.net",
        "app-measurement.com",
        "crashlytics.com",
        "firebaseio.com",
        "sentry.io",
        "datadoghq.com",
        "nr-data.net",
        "newrelic.com",
        "bugsnag.com",
        "appmetrica.yandex.net",
        "appmetrica.yandex.ru",
        "vungle.com",
        "applovin.com",
        "unity3d.com",
        "adjust.com",
        "appsflyer.com",
        "branch.io",
        "revenuecat.com",
        "scorecardresearch.com",
        "mixpanel.com",
        "amplitude.com",
        "segment.io",
        "segment.com",
        "demdex.net",
        "omtrdc.net",
        "adnxs.com",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "outbrain.com",
        "kochava.com",
        "adsystem.com",
        "inmobi.com",
        "inmobicdn.net",
        "chartboost.com",
        "liftoff.io",
        "doubleverify.com",
        "mopub.com",
        "adcolony.com",
        "tapjoy.com",
        "fyber.com",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "adsrvr.org",
        "casalemedia.com",
        "smaato.net",
        "supersonicads.com",
        "sonicsads.com",
        "moatads.com",
        "adsafeprotected.com",
        "ironsrc.com",
        "mapbox.com",
        "fbcdn.net",
        "dbankcdn.com",
        "dbankcloud.com",
        "hicloud.com",
        "cloudflare-dns.com",
        "fastly-edge.com",
        "akamaized.net",
        "akamaihd.net",
        "cloudfront.net",
        "ntp.org",
        "goog",
    )
    # Of the infra domains, these read as trackers/ads/analytics (vs neutral CDN/API/push).
    _VISITED_TRACKER_SUFFIXES = (
        "google-analytics.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "googletagservices.com",
        "googleadservices.com",
        "doubleclick.net",
        "2mdn.net",
        "app-measurement.com",
        "crashlytics.com",
        "sentry.io",
        "datadoghq.com",
        "nr-data.net",
        "newrelic.com",
        "bugsnag.com",
        "appmetrica.yandex.net",
        "appmetrica.yandex.ru",
        "vungle.com",
        "applovin.com",
        "adjust.com",
        "appsflyer.com",
        "branch.io",
        "revenuecat.com",
        "scorecardresearch.com",
        "mixpanel.com",
        "amplitude.com",
        "segment.io",
        "segment.com",
        "demdex.net",
        "omtrdc.net",
        "adnxs.com",
        "criteo.com",
        "criteo.net",
        "taboola.com",
        "outbrain.com",
        "kochava.com",
        "adsystem.com",
        "inmobi.com",
        "inmobicdn.net",
        "chartboost.com",
        "liftoff.io",
        "doubleverify.com",
        "mopub.com",
        "adcolony.com",
        "tapjoy.com",
        "fyber.com",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "adsrvr.org",
        "casalemedia.com",
        "smaato.net",
        "supersonicads.com",
        "sonicsads.com",
        "moatads.com",
        "adsafeprotected.com",
        "ironsrc.com",
    )
    # A label (or hyphen sub-part) that marks the whole host as a tracker/ads endpoint.
    _VISITED_TRACKER_LABELS = frozenset(
        {
            "ads",
            "adservice",
            "adservices",
            "adsystem",
            "pagead",
            "doubleclick",
            "mediation",
            "ogads",
            "adnxs",
            "criteo",
            "taboola",
            "outbrain",
            "appmetrica",
            "crashlytics",
            "appsflyer",
            "adjust",
            "vungle",
            "applovin",
            "kochava",
            "metric",
            "metrics",
            "analytics",
            "telemetry",
            "tracking",
            "tracker",
        }
    )
    # Service / background subdomain labels — sub-resources, push, safebrowsing, logs…
    _VISITED_BG_LABELS = frozenset(
        {
            "api",
            "apis",
            "safebrowsing",
            "ocsp",
            "crl",
            "push",
            "gcm",
            "fcm",
            "mtalk",
            "notify",
            "notifications",
            "notification",
            "log",
            "logs",
            "logging",
            "report",
            "reports",
            "crash",
            "beacon",
            "collector",
            "events",
            "event",
            "stats",
            "measurement",
            "instantmessaging",
            "content-autofill",
            "autofill",
            "firebaselogging",
            "firebaseinstallations",
            "firebasedynamiclinks",
            "dynamiclinks",
            "geller",
            "config",
            "settings",
            "update",
            "updates",
            "ota",
            "cdn",
            "static",
            "assets",
            "img",
            "imgs",
            "images",
            "media",
            "fonts",
            "edge",
            "gateway",
            "connectivitycheck",
            "clients1",
            "clients2",
            "clients3",
            "clients4",
            "clients5",
            "clients6",
            "play-fe",
        }
    )
    # Distinctive infra/CDN substrings (catch novel hostnames the suffix list misses).
    _VISITED_BG_SUBSTRINGS = (
        "cdn",
        "dbank",
        "hicloud",
        "aliyuncs",
        "akamai",
        "fastly",
        "cloudfront",
        "edgekey",
        "edgesuite",
        "googlevideo",
        "connectivitycheck",
    )
    # Second-level labels that form a public suffix with the ccTLD (co.uk, edu.cn, com.br…),
    # so the registrable domain keeps 3 labels instead of collapsing to the suffix.
    _VISITED_SECOND_LEVEL = frozenset(
        {
            "co",
            "com",
            "net",
            "org",
            "edu",
            "gov",
            "ac",
            "or",
            "ne",
            "go",
            "nom",
            "gob",
            "mil",
        }
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Network-layer bypass detector (firewall REJECT counter growth)
    # ─────────────────────────────────────────────────────────────────────────

    # Accounting chain that monitor-only rules jump to (see setup_vpn_blocking.sh).
    _BYPASS_MON_CHAIN = "EASYPI_BYPASS_MON"

    # ============ Status & Config ============

    # ============ Service Control ============

    # ============ DNS Configuration ============

    # ============ Protection Control ============

    # ============ Statistics ============

    # ============ Matchers (Rules) ============

    # ============ Parental Control / Clients ============

    # ============ Threat Intelligence ============

    # ============ Schedules (Policy Engine) ============

    # ============ Settings (IPv6, Fail-Safe, Shadow Mode) ============

    # ============ Shadow Domains (from shadow_mode.db) ============


# Singleton instance
netprotection_service = NetProtectionService()
