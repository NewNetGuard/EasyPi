"""VerdictBehavioralMixin implementation."""

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


class VerdictBehavioralMixin:
    def _check_frequency(
        self,
        domain: str,
        client_ip: str,
        ctx: "FlowContext",
        evidence: EvidenceChain,
    ) -> None:
        """
        Behavioral frequency analysis: beaconing (regular intervals), bursts,
        and high-frequency callbacks characteristic of C2 / DNS tunneling.

        Emits OBSERVE evidence only — it never blocks on its own, so it raises
        the score for already-suspicious domains without false-positive blocking
        of legitimate high-frequency services (push, telemetry, NTP-like).
        """
        if not self._frequency:
            return
        try:
            ts = getattr(ctx, "timestamp", None) or time.time()
            result = self._frequency.record_request(domain, ts)
            signals: list[str] = []
            if result.get("is_beaconing"):
                signals.append("regular-interval beaconing")
            if result.get("is_burst"):
                signals.append("request burst")
            if result.get("is_high_frequency"):
                signals.append(
                    f"high frequency ({result.get('requests_in_window')}/window)"
                )
            if not signals:
                return
            evidence.add_raw(
                source=EvidenceSource.INTEL_FREQUENCY,
                signal="Traffic pattern: " + "; ".join(signals),
                confidence=60 if result.get("is_beaconing") else 45,
                suggested_action="observe",
                metadata={
                    "base_domain": result.get("domain"),
                    "requests_in_window": result.get("requests_in_window"),
                    "is_beaconing": bool(result.get("is_beaconing")),
                    "is_burst": bool(result.get("is_burst")),
                    "client_ip": client_ip,
                },
            )
        except Exception as e:
            logger.debug(f"Frequency check failed for {domain}: {e}")

    def _check_ad_genesis(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Ad-Genesis behavioral block — ACTIVE.

        Blocks domains the batch confidently classified as a *parasitic ad
        branch*: never a navigation anchor (NAI), rides under >=2 different
        navigation anchors (cross-site), co-occurs with >=2 distinct already-
        blocked ad domains, not a CDN. Learned purely from existing DNS logs,
        so it catches unlisted/new ad domains. Navigation anchors and
        allowlisted domains are excluded when the set is built (and the
        allowlist is checked earlier), so user content is never blocked here.
        Every block is logged in the query log with reason=advertising.
        """
        if not self._ad_genesis:
            return None
        try:
            hit = self._ad_genesis.lookup(domain)
        except Exception as e:
            logger.debug(f"Ad-Genesis check failed for {domain}: {e}")
            return None
        if not hit:
            return None

        self._heuristics_blocks += 1
        evidence.add_raw(
            source=EvidenceSource.HEURISTICS_AD_GENESIS,
            signal=(
                f"ad-genesis: parasitic cross-site ad branch (never-navigated; "
                f"co-occurs with {hit.get('ad_assoc', 0)} ad domains across "
                f"{hit.get('anchors', 0)} sites)"
            ),
            confidence=int(round(float(hit.get("score", 0.9)) * 100)),
            suggested_action="block",
            metadata={"model": "ad_genesis", **hit},
        )
        logger.info(f"[{flow_id}] AD_GENESIS blocked: {domain} {hit}")
        return self._build_result(
            flow_id=flow_id,
            domain=domain,
            action=VerdictAction.DENY,
            reason=VerdictReason.ADVERTISING,
            evidence=evidence,
            start_time=start_time,
        )

    def _is_local_domain(self, domain: str) -> bool:
        """Domains that may legitimately resolve to private/reserved IPs."""
        d = (domain or "").lower().rstrip(".")
        if not d or "." not in d:
            return True  # bare hostnames are local by nature
        if d == "localhost":
            return True
        local_suffixes = (
            ".local",
            ".lan",
            ".home",
            ".internal",
            ".intranet",
            ".localdomain",
            ".home.arpa",
            ".in-addr.arpa",
            ".ip6.arpa",
        )
        return any(d.endswith(s) for s in local_suffixes)

    @staticmethod
    def _is_private_or_reserved_ip(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
        )

    def _check_rebinding(
        self,
        domain: str,
        resolved_ips: list[str],
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        DNS rebinding protection: a public domain resolving to a private/
        reserved IP is a classic rebinding attack against the LAN. Local and
        allowlisted domains are exempt (split-horizon / internal services).
        """
        if not resolved_ips or self._is_local_domain(domain):
            return None
        if self._blocklist and self._blocklist.is_allowed(domain):
            return None
        private_hits = [
            ip for ip in resolved_ips if self._is_private_or_reserved_ip(ip)
        ]
        if not private_hits:
            return None
        evidence.add_raw(
            source=EvidenceSource.INTEL_REBIND,
            signal=f"DNS rebinding: public domain resolves to private IP {private_hits[0]}",
            confidence=95,
            suggested_action="block",
            metadata={
                "private_ips": private_hits[:5],
                "reason": "public_domain_to_private_ip",
            },
        )
        logger.info(f"[{flow_id}] DNS_REBINDING blocked: {domain} -> {private_hits}")
        return self._build_result(
            flow_id=flow_id,
            domain=domain,
            action=VerdictAction.DENY,
            reason=VerdictReason.DNS_REBINDING,
            evidence=evidence,
            start_time=start_time,
        )
