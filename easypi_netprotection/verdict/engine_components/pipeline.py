"""VerdictPipelineMixin implementation."""

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

from easypi_netprotection.verdict.blocklist_filter import BLOCK_SOURCE_USER

if TYPE_CHECKING:
    from easypi_netprotection.core.resolver import FlowContext


class VerdictPipelineMixin:
    def register_intel_provider(self, provider: IntelProvider) -> None:
        """Register an intel signal provider."""
        self._intel_providers.append(provider)

    def set_shield_provider(self, provider: ShieldProvider) -> None:
        """Set the shield policy provider."""
        self._shield_provider = provider

    def reload_blocklist(self) -> bool:
        """Reload blocklist from file and invalidate related caches."""
        result = self._blocklist._load()

        # Invalidate CNAME analyzer cache since blocklist affects post-resolution
        if verdict_runtime().CNAME_ANALYZER_AVAILABLE:
            try:
                analyzer = verdict_runtime().get_cname_analyzer()
                analyzer._clear_cache()
                logger.debug("CNAME analyzer cache cleared after blocklist reload")
            except Exception as e:
                logger.warning(f"Failed to clear CNAME cache: {e}")

        return result

    def enable_safe_mode(self) -> None:
        """Enable safe mode - allow all traffic."""
        self._safe_mode = True
        logger.warning("Verdict Engine entering SAFE MODE - all traffic allowed")

    def disable_safe_mode(self) -> None:
        """Disable safe mode - resume normal operation."""
        self._safe_mode = False
        logger.info("Verdict Engine exiting safe mode")

    async def evaluate(self, ctx: "FlowContext") -> VerdictResult:
        """
        Evaluate a DNS flow through the verdict pipeline.

        This is the main entry point for verdict decisions.
        """
        start_time = time.monotonic()

        domain = ctx.question.name
        flow_id = ctx.flow_id

        # Check for blocklist/allowlist reload signal (instant reload from UI)
        if self._blocklist:
            self._blocklist.reload_if_changed()

        # Sync VPN blocker with devices.json (parental control)
        # Disabled here - sync happens on startup only to avoid performance impact

        # Initialize evidence chain
        evidence = EvidenceChain(flow_id)

        # Safe mode bypass
        if self._safe_mode:
            evidence.add_raw(
                source=EvidenceSource.SYSTEM_SAFE_MODE,
                signal="safe mode active - allowing all traffic",
                confidence=100,
                suggested_action="allow",
            )
            return self._build_result(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.ALLOW,
                reason=VerdictReason.SAFE_MODE,
                evidence=evidence,
                start_time=start_time,
            )

        try:
            # Stage 0: DNS Rewrites (highest priority)
            # Rewrites override ALL other processing
            rewrite_result = self._check_rewrites(domain, flow_id, evidence, start_time)
            if rewrite_result:
                return rewrite_result

            # Get client info for profile lookup
            client_ip = getattr(ctx, "client_ip", None) or "0.0.0.0"
            client_mac = getattr(ctx, "client_mac", None)

            # Fresh installations quarantine unbound identities at DNS before a
            # permissive Default profile can be used to evade parental rules.
            if (
                self._profiles
                and self._profiles.block_unknown_devices
                and client_ip not in {"127.0.0.1", "::1"}
                and not self._profiles.is_known_device(client_ip, client_mac)
            ):
                evidence.add_raw(
                    source=EvidenceSource.SHIELD_DEVICE,
                    signal="unknown device blocked pending administrator approval",
                    confidence=100,
                    suggested_action="block",
                )
                return self._build_result(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.DENY,
                    reason=VerdictReason.UNKNOWN_DEVICE,
                    evidence=evidence,
                    start_time=start_time,
                )

            # Stage 0.45: Time-based Schedules (from backend UI)
            # Schedules have higher priority than device profiles
            schedule_result = self._check_schedules(
                domain, client_ip, flow_id, evidence, start_time
            )
            if schedule_result:
                return schedule_result

            # Stage 0.5: Device Profile check (per-device filtering)
            profile_result = self._check_device_profile(
                domain, client_ip, client_mac, flow_id, evidence, start_time
            )
            if profile_result:
                return profile_result

            # The protective engine (blocklist + heuristics + ad-genesis, Stages 2+) is a
            # BASELINE for EVERY device. The parental-only stages below (categories,
            # streaming, safe-search) apply ONLY to a device actually under parental
            # control: an enabled, active profile whose filter level is not 'none'. A
            # 'none' device or an unmanaged guest still gets full ad/tracker/malware
            # protection downstream; it just skips these parental restrictions.
            _profile = (
                self._profiles.lookup_profile(client_ip, client_mac)
                if self._profiles
                else None
            )
            _pl = getattr(
                getattr(_profile, "filter_level", None),
                "value",
                getattr(_profile, "filter_level", None),
            )
            _parental_active = bool(
                _profile
                and getattr(_profile, "enabled", False)
                and _profile.is_active_now()
                and _pl != "none"
            )

            # Stage 0.55: Parental Controls (age filter + schedule)
            parental_result = (
                self._check_parental_controls(
                    domain, client_ip, client_mac, flow_id, evidence, start_time
                )
                if _parental_active
                else None
            )
            if parental_result:
                return parental_result

            # Stage 0.56: Streaming Apps Blocker (Netflix, YouTube, DoH kill)
            # Blocks streaming services at DNS level + prevents DoH bypass
            streaming_result = (
                self._check_streaming_blocker(domain, flow_id, evidence, start_time)
                if _parental_active
                else None
            )
            if streaming_result:
                return streaming_result

            # Stage 0.6: Safe Search enforcement (redirect to safe versions)
            # Check if profile has safe_search enabled
            safesearch_result = (
                self._check_safesearch(
                    domain, client_ip, client_mac, flow_id, evidence, start_time
                )
                if _parental_active
                else None
            )
            if safesearch_result:
                return safesearch_result

            # Stage 1: Quick allowlist check in blocklist filter.
            # Everything above is a restriction an administrator enabled for a
            # specific device (quarantine, schedules, device rules, parental
            # controls) and must stay in force. The allowlist is the user's own
            # decision and overrides every network-wide default block below.
            if self._blocklist and self._blocklist.is_allowed(domain):
                evidence.add_raw(
                    source=EvidenceSource.MATCHER_EXACT,
                    signal=f"domain in allowlist: {domain}",
                    confidence=100,
                    suggested_action="allow",
                )
                return self._build_result(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.ALLOW,
                    reason=VerdictReason.WHITELIST,
                    evidence=evidence,
                    start_time=start_time,
                )

            # Stage 2: Matcher evaluation (may have allow rules)
            await self._evaluate_matchers(domain, evidence)

            # Early exit if explicit allow rule matched (overrides blocklist)
            if self._has_explicit_allow(evidence):
                return self._build_result(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.ALLOW,
                    reason=VerdictReason.WHITELIST,
                    evidence=evidence,
                    start_time=start_time,
                )

            # Stage 1.5: Shadow Mode promoted blocks. A network-wide default
            # block, so it runs after the user's allowlist and allow rules.
            shadow_block_result = self._check_shadow_blocked(
                domain, flow_id, evidence, start_time
            )
            if shadow_block_result:
                return shadow_block_result

            # Stage 2: Blocklist check (after allowlist/matchers)
            # check_allowlist=False since we already checked above
            block_source = (
                self._blocklist.block_source(domain, check_allowlist=False)
                if self._blocklist
                else None
            )
            if block_source:
                self._blocklist_blocks += 1
                user_rule = block_source == BLOCK_SOURCE_USER
                evidence.add_raw(
                    source=EvidenceSource.BLOCKLIST,
                    signal=(
                        f"domain in user blacklist: {domain}"
                        if user_rule
                        else f"domain in blocklist: {domain}"
                    ),
                    confidence=100,
                    suggested_action="block",
                )
                return self._build_result(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.DENY,
                    reason=(
                        VerdictReason.BLACKLIST if user_rule else VerdictReason.BLOCKLIST
                    ),
                    evidence=evidence,
                    start_time=start_time,
                )

            # Stage 2.4: Newly-Registered Domain (NRD) feed block (opt-in)
            nrd_result = self._check_nrd(domain, flow_id, evidence, start_time)
            if nrd_result:
                return nrd_result

            # Stage 2.5: Heuristics analysis (DGA, homoglyph, novelty, etc.)
            heuristics_result = await self._check_heuristics(
                domain, client_ip, flow_id, evidence, start_time
            )
            if heuristics_result:
                return heuristics_result

            # Stage 2.6: Behavioral frequency analysis (beaconing / burst / C2)
            self._check_frequency(domain, client_ip, ctx, evidence)

            # Stage 2.7: Ad-Genesis behavioral ad block (active; logged in query log)
            ad_genesis_result = self._check_ad_genesis(
                domain, flow_id, evidence, start_time
            )
            if ad_genesis_result:
                return ad_genesis_result

            # Stage 3: Intel analysis (parallel)
            await self._gather_intel(domain, ctx, evidence)

            # Stage 4: Shield policy check
            await self._check_shield(domain, ctx, evidence)

            # Stage 5: Determine final verdict
            action, reason, redirect = self._determine_verdict(evidence)

            return self._build_result(
                flow_id=flow_id,
                domain=domain,
                action=action,
                reason=reason,
                evidence=evidence,
                redirect_target=redirect,
                start_time=start_time,
            )

        except Exception as e:
            logger.error(f"Verdict pipeline error for {domain}: {e}")

            # On error, default to allow (fail-open)
            evidence.add_raw(
                source=EvidenceSource.SYSTEM_SAFE_MODE,
                signal=f"pipeline error: {e}",
                confidence=0,
                suggested_action="allow",
            )

            return self._build_result(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.OBSERVE,
                reason=VerdictReason.SYSTEM_ERROR,
                evidence=evidence,
                start_time=start_time,
            )
