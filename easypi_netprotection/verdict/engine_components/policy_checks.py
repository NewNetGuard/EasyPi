"""VerdictPolicyChecksMixin implementation."""

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


class VerdictPolicyChecksMixin:
    def _check_rewrites(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check if domain has a rewrite rule.

        Returns VerdictResult if rewrite matches, None otherwise.
        Rewrites have highest priority and bypass all other checks.
        """
        if not self._rewrites:
            return None

        match = self._rewrites.lookup(domain)
        if not match:
            return None

        rule = match.rule
        processing_time_ms = (time.monotonic() - start_time) * 1000

        # Add evidence
        evidence.add_raw(
            source=EvidenceSource.REWRITE,
            signal=f"DNS rewrite: {domain} -> {rule.answer} ({rule.rewrite_type.value})",
            confidence=100,
            suggested_action="rewrite",
            metadata={
                "rule_id": rule.id,
                "pattern": rule.domain,
                "answer": rule.answer,
                "rewrite_type": rule.rewrite_type.value,
                "comment": rule.comment,
            },
        )

        # Determine action based on rewrite type
        if rule.rewrite_type == RewriteType.NXDOMAIN:
            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.DENY,
                confidence=100,
                reason=VerdictReason.REWRITE_NXDOMAIN,
                evidence=evidence,
                redirect_target=None,
                processing_time_ms=processing_time_ms,
            )

        elif rule.rewrite_type in (RewriteType.NODATA, RewriteType.REFUSED):
            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.DENY,
                confidence=100,
                reason=VerdictReason.DNS_REWRITE,
                evidence=evidence,
                redirect_target=None,
                processing_time_ms=processing_time_ms,
            )

        elif rule.rewrite_type == RewriteType.PASSTHROUGH:
            # Passthrough - continue normal resolution
            return None

        elif rule.rewrite_type in (RewriteType.A, RewriteType.AAAA):
            # IP redirect
            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.REDIRECT,
                confidence=100,
                reason=VerdictReason.DNS_REWRITE,
                evidence=evidence,
                redirect_target=rule.answer,
                processing_time_ms=processing_time_ms,
            )

        elif rule.rewrite_type == RewriteType.CNAME:
            # CNAME redirect
            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.REDIRECT,
                confidence=100,
                reason=VerdictReason.DNS_REWRITE,
                evidence=evidence,
                redirect_target=rule.answer,
                processing_time_ms=processing_time_ms,
            )

        return None

    def _check_safesearch(
        self,
        domain: str,
        client_ip: str,
        client_mac: str | None,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check if Safe Search should redirect this domain.

        Safe Search is enforced based on device profile settings.
        When enabled, redirects search engines to their safe/restricted versions.

        Priority: SafeSearch runs AFTER rewrites but before blocklist.
        If user has explicit rewrite for google.com, it takes priority.

        Returns VerdictResult with CNAME redirect if applicable, None otherwise.
        """
        if not self._safesearch:
            return None

        # Determine if safe search is enabled for this client
        safe_search_enabled = False
        if self._profiles:
            profile = self._profiles.lookup_profile(client_ip, client_mac)
            if profile and profile.enabled:
                safe_search_enabled = profile.safe_search

        if not safe_search_enabled:
            return None

        # Check if domain should be redirected
        rewrite = self._safesearch.check(domain, safe_search_enabled=True)

        if not rewrite:
            return None

        # Found a Safe Search match - redirect
        self._safesearch_redirects += 1
        processing_time_ms = (time.monotonic() - start_time) * 1000

        # Evidence without full domain/IP (privacy)
        evidence.add_raw(
            source=EvidenceSource.REWRITE,
            signal=f"SafeSearch: {rewrite.service.value} redirect applied",
            confidence=100,
            suggested_action="redirect",
            metadata={
                "service": rewrite.service.value,
                "ttl": rewrite.ttl,
            },
        )

        return VerdictResult(
            flow_id=flow_id,
            domain=domain,
            action=VerdictAction.REDIRECT,
            confidence=100,
            reason=VerdictReason.SAFE_SEARCH,
            evidence=evidence,
            redirect_target=rewrite.target,
            processing_time_ms=processing_time_ms,
        )

    def _check_parental_controls(
        self,
        domain: str,
        client_ip: str,
        client_mac: str | None,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check parental controls (age filter + schedule).

        Returns VerdictResult if parental controls block the domain,
        None to continue through pipeline.
        """
        if not self._parental:
            return None

        # Get device profile ID for lookup
        if not self._profiles:
            return None

        profile = self._profiles.lookup_profile(client_ip, client_mac)
        if not profile:
            return None

        # Check parental controls for this device profile
        result = self._parental.check(profile.id, domain)

        if not result.allowed:
            processing_time_ms = (time.monotonic() - start_time) * 1000
            self._parental_blocks += 1

            evidence.add_raw(
                source=EvidenceSource.SHIELD_DENY,
                signal=f"parental control: {result.reason}",
                confidence=100,
                suggested_action="block",
                metadata={
                    "blocked_by": result.blocked_by,
                    "category": result.category,
                    "schedule_action": result.schedule_action,
                },
            )

            # Determine reason based on what blocked it
            reason = VerdictReason.PARENTAL_CONTROL
            if result.blocked_by == "schedule":
                reason = VerdictReason.SCHEDULE_BLOCKED
            elif result.blocked_by == "age_filter":
                reason = VerdictReason.AGE_RESTRICTED

            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.DENY,
                confidence=100,
                reason=reason,
                evidence=evidence,
                processing_time_ms=processing_time_ms,
            )

        return None

    def _check_streaming_blocker(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check if domain should be blocked by streaming blocker.

        This blocks streaming services (Netflix, YouTube, TikTok, etc.)
        and DoH/DoT servers to prevent DNS bypass.

        Returns VerdictResult if domain is blocked, None otherwise.
        """
        if not verdict_runtime().STREAMING_BLOCKER_AVAILABLE:
            return None

        try:
            blocker = verdict_runtime().get_streaming_blocker()
            blocked_domains = blocker.get_all_domains_to_block()

            # Check if domain matches any blocked domain
            domain_lower = domain.lower().rstrip(".")

            for blocked in blocked_domains:
                blocked_lower = blocked.lower().strip()

                # Exact match
                if domain_lower == blocked_lower:
                    return self._streaming_block_result(
                        domain,
                        flow_id,
                        evidence,
                        start_time,
                        f"streaming_blocker: exact match {blocked}",
                    )

                # Wildcard match (*.domain.com)
                if blocked_lower.startswith("*."):
                    suffix = blocked_lower[2:]  # Remove *.
                    if domain_lower.endswith("." + suffix) or domain_lower == suffix:
                        return self._streaming_block_result(
                            domain,
                            flow_id,
                            evidence,
                            start_time,
                            f"streaming_blocker: wildcard match {blocked}",
                        )

                # Subdomain match (domain_lower ends with .blocked)
                if domain_lower.endswith("." + blocked_lower):
                    return self._streaming_block_result(
                        domain,
                        flow_id,
                        evidence,
                        start_time,
                        f"streaming_blocker: subdomain of {blocked}",
                    )

            return None

        except Exception as e:
            logger.debug(f"Streaming blocker check failed: {e}")
            return None

    def _streaming_block_result(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
        signal: str,
    ) -> VerdictResult:
        """Build a blocking result for streaming blocker."""
        processing_time_ms = (time.monotonic() - start_time) * 1000

        evidence.add_raw(
            source=EvidenceSource.BLOCKLIST,
            signal=signal,
            confidence=100,
            suggested_action="block",
            metadata={"category": "streaming_apps"},
        )

        return VerdictResult(
            flow_id=flow_id,
            domain=domain,
            action=VerdictAction.DENY,
            confidence=100,
            reason=VerdictReason.APP_BLOCKED,
            evidence=evidence,
            processing_time_ms=processing_time_ms,
        )

    def _check_shadow_blocked(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check if domain was explicitly promoted to a block by an admin in Shadow Mode.

        Shadow Mode only OBSERVES suspicious domains (gray zone, score 30-69) for
        review; it never blocks on its own. A domain blocks here only after an admin
        promotes it (action='promoted'). Legacy 'auto_blocked' rows are intentionally
        NOT honored, so any database poisoned by the old auto-block-on-observe bug
        stops blocking immediately without a migration.

        Returns VerdictResult if domain is admin-promoted, None otherwise.
        """
        try:
            from ...heuristics.shadow_mode import get_shadow_mode

            shadow = get_shadow_mode()
            if not shadow:
                return None

            # Block only what an admin explicitly promoted.
            record = shadow.get_record(domain)
            if record and record.action.value == "promoted":
                # Update hit count for blocked domain
                shadow.increment_hit_count(domain)

                processing_time_ms = (time.monotonic() - start_time) * 1000

                evidence.add_raw(
                    source=EvidenceSource.HEURISTICS_AGGREGATED,
                    signal=f"shadow_mode: admin-promoted block (score={record.max_score:.1f})",
                    confidence=int(min(record.max_score, 100)),
                    suggested_action="block",
                    metadata={
                        "category": "shadow_mode",
                        "max_score": record.max_score,
                        "hit_count": record.hit_count,
                        "action": record.action.value,
                    },
                )

                logger.info(
                    f"[{flow_id}] SHADOW_PROMOTED_BLOCK: {domain} (score={record.max_score:.1f})"
                )

                return VerdictResult(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.DENY,
                    confidence=int(min(record.max_score, 100)),
                    reason=VerdictReason.SHADOW_MODE,
                    evidence=evidence,
                    processing_time_ms=processing_time_ms,
                )

            return None

        except Exception as e:
            logger.debug(f"Shadow mode check failed: {e}")
            return None

    def _check_nrd(
        self,
        domain: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> "VerdictResult | None":
        """Block a domain that is in the Newly-Registered Domain (NRD) feed.

        Opt-in via settings.heuristics.enable_nrd_block. Freshly-registered domains
        are a strong phishing/scam signal before they reach conventional blocklists.
        Fail-open: if the feed file is missing/empty this matches nothing.
        """
        if not verdict_runtime().NRD_AVAILABLE:
            return None
        try:
            cfg = verdict_runtime().get_settings().heuristics
            if not cfg.enable_nrd_block:
                return None
            window = int(cfg.nrd_max_age_days)
        except Exception:
            return None
        try:
            if not verdict_runtime().get_nrd_filter().is_nrd(domain):
                return None
        except Exception:
            return None

        self._blocklist_blocks += 1
        processing_time_ms = (time.monotonic() - start_time) * 1000
        evidence.add_raw(
            source=EvidenceSource.BLOCKLIST,
            signal=f"newly-registered domain (NRD feed, <{window}d)",
            confidence=90,
            suggested_action="block",
            metadata={"category": "nrd", "window_days": window},
        )
        logger.info(f"[{flow_id}] NRD_BLOCK: {domain} (<{window}d)")
        return VerdictResult(
            flow_id=flow_id,
            domain=domain,
            action=VerdictAction.DENY,
            confidence=90,
            reason=VerdictReason.NEWLY_REGISTERED,
            evidence=evidence,
            processing_time_ms=processing_time_ms,
        )

    async def _check_heuristics(
        self,
        domain: str,
        client_ip: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check domain using heuristics engine.

        Analyzes domain for:
        - DGA (botnet) patterns
        - Homoglyph/brand impersonation
        - Domain novelty (first seen)
        - Structural anomalies (length, depth, numbers)

        Returns VerdictResult if heuristics dictates blocking,
        None to continue through pipeline.
        """
        if not self._heuristics:
            return None

        heuristics_settings = self.settings.heuristics

        try:
            heuristics_context: dict[str, Any] = {}

            # Record device query and derive lightweight traffic context for heuristics.
            # This lets the ad/tracker detector use real request pressure instead of context=None.
            if heuristics_settings.enable_device_anomaly:
                try:
                    from ...heuristics import get_device_anomaly_detector

                    detector = get_device_anomaly_detector()
                    detector.record_query(client_ip, domain)
                    device_stats = detector.get_device_stats(client_ip)
                    anomaly_result = detector.analyze(client_ip, domain)
                    heuristics_context.update(
                        {
                            "device_id": client_ip,
                            "request_count": max(
                                device_stats.queries_5min, device_stats.queries_1min
                            ),
                            "third_party_count": max(
                                device_stats.unique_domains_1hour - 1, 0
                            ),
                            "is_device_anomalous": anomaly_result.is_anomalous,
                            "device_anomaly_score": anomaly_result.score,
                            "device_anomaly_confidence": anomaly_result.confidence,
                            "device_anomaly_reasons": anomaly_result.reasons,
                        }
                    )
                    if anomaly_result.is_anomalous:
                        evidence.add_raw(
                            source=EvidenceSource.HEURISTICS_DEVICE,
                            signal=f"Device anomaly: {anomaly_result.anomaly_type}",
                            confidence=int(anomaly_result.score * 100),
                            suggested_action="observe",
                            metadata={
                                "device_id": client_ip,
                                "anomaly_type": anomaly_result.anomaly_type,
                                "reasons": anomaly_result.reasons[:3],
                            },
                        )
                except Exception as e:
                    logger.debug(f"Device anomaly tracking failed: {e}")

            # Run heuristics analysis (sync call, fast enough for DNS)
            result = self._heuristics.analyze(
                domain,
                persist_signals=heuristics_settings.persist_signals,
                quick_mode=False,
                context=heuristics_context or None,
            )

            # Add evidence for significant signals
            if result.is_dga:
                evidence.add_raw(
                    source=EvidenceSource.HEURISTICS_DGA,
                    signal=f"DGA detected: {domain}",
                    confidence=int(result.final_score),
                    suggested_action="block"
                    if result.verdict == "block"
                    else "observe",
                    metadata={
                        "dga_score": result.final_score,
                        "signals": [
                            s.reason
                            for s in result.signals
                            if s.signal_type.value == "dga"
                        ][:3],
                    },
                )

            if result.is_homoglyph:
                evidence.add_raw(
                    source=EvidenceSource.HEURISTICS_HOMOGLYPH,
                    signal=f"Brand impersonation: {result.matched_brand or 'unknown'}",
                    confidence=int(result.final_score),
                    suggested_action="block"
                    if result.verdict == "block"
                    else "observe",
                    metadata={
                        "matched_brand": result.matched_brand,
                        "domain": domain,
                    },
                )

            if result.first_seen_days is not None and result.first_seen_days < 7:
                evidence.add_raw(
                    source=EvidenceSource.HEURISTICS_FIRST_SEEN,
                    signal=f"First observed locally: {result.first_seen_days:.1f} days ago",
                    confidence=min(50, int(25 - result.first_seen_days * 3)),
                    suggested_action="observe",
                    metadata={
                        "local_first_seen_days": result.first_seen_days,
                    },
                )

            # Add aggregated heuristics evidence
            if result.final_score >= heuristics_settings.observe_threshold:
                evidence.add_raw(
                    source=EvidenceSource.HEURISTICS_AGGREGATED,
                    signal=f"Heuristics score: {result.final_score:.1f} ({result.verdict})",
                    confidence=int(result.final_score),
                    suggested_action=result.verdict,
                    metadata={
                        "score": result.final_score,
                        "verdict": result.verdict,
                        "is_dga": result.is_dga,
                        "is_homoglyph": result.is_homoglyph,
                        "signal_count": len(result.signals),
                    },
                )

            # Determine action based on verdict
            if result.verdict == "block":
                self._heuristics_blocks += 1
                processing_time_ms = (time.monotonic() - start_time) * 1000

                # Determine specific reason
                if result.is_dga:
                    reason = VerdictReason.DGA_DETECTED
                elif result.is_homoglyph:
                    reason = VerdictReason.HOMOGLYPH_DETECTED
                elif getattr(result, "is_ad_tracker", False):
                    reason = VerdictReason.ADVERTISING
                elif getattr(result, "is_tracker", False):
                    reason = VerdictReason.TRACKING
                else:
                    reason = VerdictReason.HEURISTICS_BLOCK

                return VerdictResult(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.DENY,
                    confidence=int(result.final_score),
                    reason=reason,
                    evidence=evidence,
                    processing_time_ms=processing_time_ms,
                )

            elif result.verdict == "observe":
                self._heuristics_observes += 1
                # Record in shadow mode for later review
                try:
                    from ...heuristics.shadow_mode import get_shadow_mode

                    shadow = get_shadow_mode()
                    if shadow:
                        reasons = [s.reason for s in result.signals[:5]]
                        shadow.observe(domain, result.final_score, reasons)
                        logger.info(
                            f"[{flow_id}] SHADOW_OBSERVE: {domain} score={result.final_score:.1f}"
                        )
                except Exception as e:
                    logger.debug(f"Shadow mode recording failed: {e}")
                # Domain continues through pipeline

            return None

        except Exception as e:
            logger.warning(f"Heuristics check failed for {domain}: {e}")
            return None

    def _check_schedules(
        self,
        domain: str,
        client_ip: str,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check time-based schedules from backend.

        Schedules are configured via UI and stored in:
        ${NETPROTECTION_DATA_DIR}/schedules.json

        Returns VerdictResult if schedule blocks domain, None otherwise.
        """
        if not self._schedule_checker:
            return None

        try:
            match = self._schedule_checker.check(domain, client_ip)

            if match and match.blocked:
                self._schedule_blocks += 1
                processing_time_ms = (time.monotonic() - start_time) * 1000

                evidence.add_raw(
                    source=EvidenceSource.SHIELD_DENY,
                    signal=f"schedule block: {match.schedule_name}",
                    confidence=100,
                    suggested_action="block",
                    metadata={
                        "schedule_name": match.schedule_name,
                        "rule_target": match.rule_target,
                        "reason": match.reason,
                    },
                )

                logger.info(
                    f"[{flow_id}] SCHEDULE_BLOCK: {domain} by '{match.schedule_name}' ({match.reason})"
                )

                return VerdictResult(
                    flow_id=flow_id,
                    domain=domain,
                    action=VerdictAction.DENY,
                    confidence=100,
                    reason=VerdictReason.SCHEDULE_BLOCKED,
                    evidence=evidence,
                    processing_time_ms=processing_time_ms,
                )

            return None

        except Exception as e:
            logger.warning(f"Schedule check failed for {domain}: {e}")
            return None

    def _check_device_profile(
        self,
        domain: str,
        client_ip: str,
        client_mac: str | None,
        flow_id: str,
        evidence: EvidenceChain,
        start_time: float,
    ) -> VerdictResult | None:
        """
        Check device profile for per-device filtering.

        Returns VerdictResult if profile dictates an immediate decision,
        None to continue through pipeline.
        """
        if not self._profiles:
            logger.info(f"[{flow_id}] PROFILE_CHECK: No profiles manager")
            return None

        profile = self._profiles.lookup_profile(client_ip, client_mac)
        logger.info(
            f"[{flow_id}] PROFILE_CHECK: ip={client_ip}, profile={profile.name if profile else 'None'}"
        )
        if not profile or not profile.enabled:
            return None

        # Check if profile is active (schedule)
        if not profile.is_active_now():
            return None

        domain_lower = domain.lower().rstrip(".")
        processing_time_ms = (time.monotonic() - start_time) * 1000

        managed_parental_profile = (
            str(getattr(profile, "id", "")).startswith(
                self._managed_parental_profile_prefix
            )
            and bool(getattr(profile, "parental_enabled", False))
        )
        bypass_domain = self._is_bypass_domain(domain_lower)

        # Log blacklist check
        is_blacklisted = profile.is_blacklisted(domain_lower)
        logger.info(
            f"[{flow_id}] BLACKLIST_CHECK: domain={domain_lower}, "
            f"is_blacklisted={is_blacklisted}, blacklist_count={len(profile.blacklist)}"
        )

        # 1. Check profile whitelist (always allow)
        is_whitelisted = profile.is_whitelisted(domain_lower)
        if is_whitelisted:
            evidence.add_raw(
                source=EvidenceSource.SHIELD_ALLOW,
                signal=f"profile whitelist: {profile.name}",
                confidence=100,
                suggested_action="allow",
                metadata={
                    "profile_id": profile.id,
                    "profile_name": profile.name,
                    "reason": "whitelist",
                },
            )
            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.ALLOW,
                confidence=100,
                reason=VerdictReason.PROFILE_WHITELIST,
                evidence=evidence,
                processing_time_ms=processing_time_ms,
            )

        # 2. Check profile blacklist (always block)
        if is_blacklisted:
            evidence.add_raw(
                source=EvidenceSource.SHIELD_DENY,
                signal=f"profile blacklist: {profile.name}",
                confidence=100,
                suggested_action="block",
                metadata={
                    "profile_id": profile.id,
                    "profile_name": profile.name,
                    "reason": "blacklist",
                },
            )
            # Record blocked query
            self._profiles.record_query(client_ip, client_mac, blocked=True)

            return VerdictResult(
                flow_id=flow_id,
                domain=domain,
                action=VerdictAction.DENY,
                confidence=100,
                reason=VerdictReason.PROFILE_BLACKLIST,
                evidence=evidence,
                processing_time_ms=processing_time_ms,
            )

        # Real bypass leak detection for managed parental profiles:
        # show alert only when bypass domain was NOT blocked by profile or global blocklist.
        if (
            managed_parental_profile
            and bypass_domain
            and not is_whitelisted
            and not is_blacklisted
        ):
            blocked_by_global = False
            try:
                blocked_by_global = bool(
                    self._blocklist
                    and self._blocklist.is_blocked(domain_lower, check_allowlist=False)
                )
            except Exception:
                blocked_by_global = False

            if not blocked_by_global:
                bypass_mode = (
                    str(getattr(profile, "bypass_mode", "") or "warn").strip().lower()
                )
                if bypass_mode in ("warn", "quarantine"):
                    # Soft-block the bypass endpoint itself (DoH/DoT/VPN/proxy/Tor) so it
                    # can't be used to escape filtering. In 'warn' this IS the whole
                    # enforcement: the device keeps its internet and simply falls back to
                    # filtered DNS (e.g. cloudflare-dns.com -> NXDOMAIN). In 'quarantine'
                    # we additionally cut the device (deliberate fail-closed).
                    #
                    # A device under parental control must never bypass silently: a blocked
                    # VPN/proxy/Tor/SmartDNS lookup raises the alert (banner + notification)
                    # even in 'warn'. Auto-quarantine is separately gated on bypass_mode, so
                    # alerting here can no longer cut a 'warn' device.
                    group = self._bypass_domain_group(domain_lower)
                    self._record_bypass_event(
                        client_ip,
                        flow_id,
                        domain_lower,
                        leak=group in self._ALERTING_BYPASS_GROUPS,
                    )
                    if bypass_mode == "quarantine":
                        self._trigger_fail_closed(client_ip, flow_id, domain_lower)
                    evidence.add_raw(
                        source=EvidenceSource.SHIELD_DENY,
                        signal=f"anti-bypass endpoint: {profile.name}",
                        confidence=100,
                        suggested_action="block",
                        metadata={
                            "profile_id": profile.id,
                            "profile_name": profile.name,
                            "reason": "anti_bypass",
                            "bypass_mode": bypass_mode,
                        },
                    )
                    self._profiles.record_query(client_ip, client_mac, blocked=True)
                    return VerdictResult(
                        flow_id=flow_id,
                        domain=domain,
                        action=VerdictAction.DENY,
                        confidence=100,
                        reason=VerdictReason.PARENTAL_CONTROL,
                        evidence=evidence,
                        processing_time_ms=processing_time_ms,
                    )
                else:
                    # log_only: deliberately let the bypass through, but record the real
                    # leak so admins can monitor it (never auto-cut for log_only).
                    self._record_bypass_event(
                        client_ip, flow_id, domain_lower, leak=True
                    )

        # 3. Filter level.
        # 'none' = no category/parental restrictions. It does NOT mean "no protection":
        # the blocklist + heuristics + ad-genesis run downstream as a BASELINE for EVERY
        # device, so there is nothing to short-circuit here — fall through to `return None`
        # and let the protective engine apply. The parental-only stages (categories /
        # streaming / safe-search) are skipped for a 'none' device in analyze(); standard
        # and strict fall through the same way and additionally get those parental stages.

        # No immediate decision - continue pipeline (protective engine applies to all).
        return None

    async def _evaluate_matchers(
        self,
        domain: str,
        evidence: EvidenceChain,
    ) -> None:
        """Evaluate domain against all matchers."""
        results = self.matchers.evaluate_domain(domain)

        for result in results:
            evidence.add_raw(
                source=self._matcher_source(result.matcher_id),
                signal=result.reason,
                confidence=result.confidence,
                suggested_action=result.action,
                weight=1.0,  # User rules have full weight
                metadata={
                    "matcher_id": result.matcher_id,
                    "pattern": result.pattern,
                    "priority": result.priority,
                    "tags": result.tags,
                    "redirect_target": result.redirect_target,
                },
            )

    def _matcher_source(self, matcher_id: str) -> EvidenceSource:
        """Get evidence source for a matcher."""
        matcher = self.matchers.get(matcher_id)
        if matcher:
            return matcher.evidence_source
        return EvidenceSource.MATCHER_EXACT
