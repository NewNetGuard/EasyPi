"""VerdictBypassMixin implementation."""

from __future__ import annotations

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

if TYPE_CHECKING:
    from easypi_netprotection.core.resolver import FlowContext


class VerdictBypassMixin:
    def _load_bypass_domain_patterns(self) -> tuple[str, ...]:
        """Load normalized bypass-domain patterns used for fail-closed trigger."""
        raw_patterns = get_domains_for_service("bypass")
        patterns: list[str] = []
        for raw in raw_patterns:
            pattern = str(raw or "").strip().lower().rstrip(".")
            if not pattern:
                continue
            # service_domains may include URL/path-like entries.
            pattern = pattern.split("/", 1)[0].strip()
            if not pattern:
                continue
            patterns.append(pattern)
        return tuple(sorted(set(patterns)))

    # Bypass channels that mean a deliberate tunnel out of the filter. These must raise
    # an alert even in 'warn' (where we block but keep the internet on). A *blocked* DoH
    # lookup is routine background noise — phones probe DoH resolvers on their own — so it
    # is recorded quietly; a real DoH tunnel still surfaces via network-layer REJECT counters.
    _ALERTING_BYPASS_GROUPS = ("vpn", "proxy", "tor", "smartdns")

    def _load_bypass_domain_groups(self) -> dict[str, tuple[str, ...]]:
        """Per-channel bypass patterns, so a VPN attempt can be told from a DoH probe."""
        groups: dict[str, tuple[str, ...]] = {}
        for group in ("vpn", "proxy", "tor", "smartdns", "doh"):
            patterns: list[str] = []
            try:
                raw_patterns = get_domains_for_service(group)
            except Exception:
                raw_patterns = []
            for raw in raw_patterns:
                pattern = str(raw or "").strip().lower().rstrip(".")
                pattern = pattern.split("/", 1)[0].strip()
                if pattern:
                    patterns.append(pattern)
            groups[group] = tuple(sorted(set(patterns)))
        return groups

    def _bypass_domain_group(self, domain: str) -> str | None:
        """Which bypass channel a domain belongs to, or None.

        Checked in priority order so an ambiguous domain counts as the more serious
        channel (a VPN endpoint that also serves DoH is treated as VPN).
        """
        domain = (domain or "").lower().rstrip(".")
        for group in ("vpn", "proxy", "tor", "smartdns", "doh"):
            for pattern in self._bypass_domain_groups.get(group, ()):
                if self._domain_matches_pattern(domain, pattern):
                    return group
        return None

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """Match a domain against exact/suffix/wildcard patterns."""
        if not domain or not pattern:
            return False
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(domain, pattern)
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern or domain.endswith("." + pattern)

    def _is_bypass_domain(self, domain: str) -> bool:
        """Check whether domain is a known bypass (VPN/DoH/proxy/Tor) target."""
        domain = domain.lower().rstrip(".")
        for pattern in self._bypass_domain_patterns:
            if self._domain_matches_pattern(domain, pattern):
                return True
        return False

    def _load_adult_domain_patterns(self) -> tuple[str, ...]:
        """Load normalized adult-domain patterns for fail-closed trigger."""
        patterns: list[str] = []
        for service in ("adult", "pornography"):
            for raw in get_domains_for_service(service):
                pattern = str(raw or "").strip().lower().rstrip(".")
                if not pattern or pattern == "__adult_heuristic__":
                    continue
                pattern = pattern.split("/", 1)[0].strip()
                if pattern:
                    patterns.append(pattern)
        return tuple(sorted(set(patterns)))

    def _is_adult_domain(self, domain: str) -> bool:
        """Check whether domain is in known adult-domain patterns."""
        domain = domain.lower().rstrip(".")
        for pattern in self._adult_domain_patterns:
            if self._domain_matches_pattern(domain, pattern):
                return True
        return False

    def _trigger_fail_closed(self, client_ip: str, flow_id: str, domain: str) -> None:
        """
        Quarantine client by blocking all internet when bypass attempt is detected.

        NetProtection runs with NoNewPrivileges, so it cannot call sudo/iptables directly.
        We enqueue a request file that backend service drains and applies with runner.
        """
        if not client_ip or client_ip in {"0.0.0.0", "127.0.0.1"}:
            return
        if self._is_fail_closed_active(client_ip):
            return

        try:
            self._fail_closed_queue_path.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "ip": client_ip,
                "domain": domain,
                "flow_id": flow_id,
                "ts": time.time(),
            }
            with self._fail_closed_queue_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            logger.warning(
                f"[{flow_id}] FAIL_CLOSED_QUEUED: ip={client_ip}, domain={domain}"
            )
        except Exception as exc:
            logger.error(
                f"[{flow_id}] FAIL_CLOSED_EXCEPTION: ip={client_ip}, domain={domain}, err={exc}"
            )

    def _record_bypass_event(
        self, client_ip: str, flow_id: str, domain: str, leak: bool = True
    ) -> None:
        """
        Record a real bypass leak for UI/diagnostics (does NOT quarantine by itself).

        The backend consumes this queue and shows a banner where admin can pick:
        - Warn (recommended): block bypass channels (DoH/DoT/QUIC/VPN endpoints)
        - Quarantine: full internet off (fail-closed)
        - Monitor only: allow bypass but keep logs
        """
        if not client_ip or client_ip in {"0.0.0.0", "127.0.0.1"}:
            return
        now = time.time()
        last_ts = self._bypass_event_last_by_ip.get(client_ip)
        if (
            last_ts is not None
            and (now - last_ts) < self._bypass_event_min_interval_sec
        ):
            return
        self._bypass_event_last_by_ip[client_ip] = now

        try:
            self._bypass_event_queue_path.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "ip": client_ip,
                "domain": domain,
                "flow_id": flow_id,
                "ts": now,
                # leak=True  -> real leak (bypass allowed through): banner + auto-quarantine.
                # leak=False -> blocked attempt: recorded for stats only, never quarantines.
                "leak": bool(leak),
            }
            with self._bypass_event_queue_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            tag = "BYPASS_LEAK" if leak else "BYPASS_BLOCKED"
            logger.warning(f"[{flow_id}] {tag}: ip={client_ip}, domain={domain}")
        except Exception as exc:
            logger.warning(
                f"[{flow_id}] BYPASS_LEAK_EXCEPTION: ip={client_ip}, domain={domain}, err={exc}"
            )

    def _is_fail_closed_active(self, client_ip: str) -> bool:
        """
        Check whether fail-closed quarantine is currently active for a client IP.

        We intentionally do NOT keep a permanent in-memory "already queued" set, because
        admins can restore internet from UI (unquarantine), and we must allow re-triggering.
        """
        if not client_ip:
            return False
        try:
            path = self._fail_closed_state_path
            try:
                mtime_ns = path.stat().st_mtime_ns
            except FileNotFoundError:
                self._fail_closed_state_mtime_ns = None
                self._fail_closed_state_ips = set()
                self._fail_closed_state_macs = set()
                return False

            if self._fail_closed_state_mtime_ns != mtime_ns:
                data: dict[str, Any] = {}
                try:
                    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    data = {}
                raw_ips = data.get("ips", [])
                if not isinstance(raw_ips, list):
                    raw_ips = []
                self._fail_closed_state_ips = {
                    str(x).strip() for x in raw_ips if str(x).strip()
                }
                raw_devices = data.get("devices", [])
                if not isinstance(raw_devices, list):
                    raw_devices = []
                self._fail_closed_state_macs = {
                    str(item.get("mac") or "").strip().lower()
                    for item in raw_devices
                    if isinstance(item, dict) and item.get("mac")
                }
                self._fail_closed_state_mtime_ns = mtime_ns
            if client_ip in self._fail_closed_state_ips:
                return True
            try:
                with open("/proc/net/arp", encoding="utf-8") as arp_file:
                    next(arp_file, None)
                    for line in arp_file:
                        parts = line.split()
                        if (
                            len(parts) >= 4
                            and parts[0] == client_ip
                            and parts[2] != "0x0"
                        ):
                            return parts[3].lower() in self._fail_closed_state_macs
            except Exception:
                pass
            return False
        except Exception:
            # Best-effort; if state can't be read, do not block re-triggering.
            return False

    def _is_cdn_domain(self, domain: str) -> bool:
        """
        Check if domain is a known CDN/infrastructure domain.

        These domains should NOT trigger CNAME cloaking detection
        because many legitimate sites use them for content delivery.
        """
        domain_lower = domain.lower().rstrip(".")
        for suffix in self._cdn_whitelist_suffixes:
            # Check both: ends with .suffix OR equals suffix (without leading dot)
            if domain_lower.endswith(suffix) or domain_lower == suffix.lstrip("."):
                return True
            # Also check if domain is subdomain of the suffix
            suffix_base = suffix.lstrip(".")
            if domain_lower.endswith("." + suffix_base) or domain_lower == suffix_base:
                return True
        return False
