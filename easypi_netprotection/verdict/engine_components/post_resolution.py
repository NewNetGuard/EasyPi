"""VerdictPostResolutionMixin implementation."""

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


class VerdictPostResolutionMixin:
    async def evaluate_post_resolution(
        self,
        flow_id: str,
        domain: str,
        resolved_ips: list[str],
        cname_chain: list[str],
        existing_evidence: EvidenceChain | None = None,
    ) -> VerdictResult | None:
        """
        Post-resolution evaluation for IP and CNAME-based rules.

        Called after upstream resolution to check:
        - IP-based matchers
        - ASN-based matchers
        - CNAME chain analysis (blocklist + known trackers)

        This is critical for CNAME uncloaking - detecting when a first-party
        domain CNAMEs to a known tracker (e.g., analytics.example.com → tracker.doubleclick.net).
        """
        evidence = existing_evidence or EvidenceChain(flow_id)
        start_time = time.monotonic()

        # Allowlisted domains are NEVER blocked post-resolution. This makes
        # allowlisting a site fully effective: a whitelisted shop (e.g. otto.de)
        # keeps working — including first-party subdomains that CNAME to a
        # tracker/CDN — while third-party trackers on OTHER domains stay blocked.
        if self._blocklist and self._blocklist.is_allowed(domain):
            return None

        # DNS rebinding protection (runs for every resolved response)
        rebind_result = self._check_rebinding(
            domain, resolved_ips, flow_id, evidence, start_time
        )
        if rebind_result:
            return rebind_result

        # Check IP matchers
        for ip in resolved_ips:
            results = self.matchers.evaluate_ip(ip)
            for result in results:
                evidence.add_raw(
                    source=EvidenceSource.MATCHER_IP,
                    signal=result.reason,
                    confidence=result.confidence,
                    suggested_action=result.action,
                    metadata={
                        "matcher_id": result.matcher_id,
                        "resolved_ip": ip,
                    },
                )

        # Broad CNAME→blocklist match is OPT-IN (strict mode only). It blocks the
        # FIRST-PARTY domain whenever ANY CNAME in its chain is on a blocklist,
        # which breaks legitimate sites (shop image/CDN/search subdomains that
        # CNAME through a broadly-listed domain). By default we rely on the precise
        # known-tracker analyzer below — trackers are still uncloaked while
        # first-party content keeps working. One rule, all sites.
        if self._blocklist and self._cname_uncloak_strict:
            for cname in cname_chain:
                # Skip CDN domains - they are used by many legitimate sites
                if self._is_cdn_domain(cname):
                    logger.debug(f"CNAME {cname} is CDN, skipping blocklist check")
                    continue

                if self._blocklist.is_blocked(cname, check_allowlist=True):
                    evidence.add_raw(
                        source=EvidenceSource.INTEL_CNAME,
                        signal=f"CNAME cloaking: {domain} → {cname} (blocked)",
                        confidence=95,  # High confidence - in blocklist
                        suggested_action="block",
                        metadata={
                            "cname": cname,
                            "original_domain": domain,
                            "reason": "cname_in_blocklist",
                        },
                    )
                    # Early return for clear blocklist match
                    return self._build_result(
                        flow_id=flow_id,
                        domain=domain,
                        action=VerdictAction.DENY,
                        reason=VerdictReason.CNAME_CLOAKING,
                        evidence=evidence,
                        start_time=start_time,
                    )

        # Check CNAME chain via CNAMEChainAnalyzer (known trackers, patterns)
        # Also skip CDN domains here
        if verdict_runtime().CNAME_ANALYZER_AVAILABLE and cname_chain:
            # Filter out CDN domains before analysis
            non_cdn_chain = [c for c in cname_chain if not self._is_cdn_domain(c)]

            if non_cdn_chain:
                try:
                    analyzer = verdict_runtime().get_cname_analyzer()
                    result = analyzer.analyze_chain(domain, non_cdn_chain)

                    if result.tracker_detected:
                        evidence.add_raw(
                            source=EvidenceSource.INTEL_CNAME,
                            signal=f"CNAME cloaking: {domain} → {result.detected_tracker} (known tracker)",
                            confidence=result.confidence,
                            suggested_action="block",
                            metadata={
                                "cname_chain": result.chain,
                                "original_domain": domain,
                                "detected_tracker": result.detected_tracker,
                                "reason": result.reason,
                            },
                        )
                        return self._build_result(
                            flow_id=flow_id,
                            domain=domain,
                            action=VerdictAction.DENY,
                            reason=VerdictReason.CNAME_CLOAKING,
                            evidence=evidence,
                            start_time=start_time,
                        )
                    elif result.is_cloaked and result.confidence >= 70:
                        # Suspicious CNAME pattern (not known tracker but suspicious)
                        evidence.add_raw(
                            source=EvidenceSource.INTEL_CNAME,
                            signal=f"Suspicious CNAME: {domain} → {result.final_target}",
                            confidence=result.confidence,
                            suggested_action="observe",
                            metadata={
                                "cname_chain": result.chain,
                                "original_domain": domain,
                                "final_target": result.final_target,
                            },
                        )
                except Exception as e:
                    logger.debug(f"CNAME analyzer error: {e}")

        # Check CNAME chain via matchers (additional rules)
        # Also skip CDN domains
        for cname in cname_chain:
            if self._is_cdn_domain(cname):
                continue
            results = self.matchers.evaluate_domain(cname)
            for result in results:
                evidence.add_raw(
                    source=EvidenceSource.INTEL_CNAME,
                    signal=f"CNAME chain reveals: {cname} - {result.reason}",
                    confidence=min(
                        result.confidence, 90
                    ),  # Slightly lower for indirect
                    suggested_action=result.action,
                    metadata={
                        "cname": cname,
                        "original_domain": domain,
                    },
                )

        # Only return if blocking evidence found
        blocking = evidence.get_blocking_evidence()
        if blocking:
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

        return None

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        stats = {
            "total_verdicts": self._total_verdicts,
            "blocked": self._blocked_count,
            "allowed": self._allowed_count,
            "block_rate": (
                self._blocked_count / self._total_verdicts
                if self._total_verdicts > 0
                else 0.0
            ),
            "avg_processing_ms": round(self._avg_processing_ms, 2),
            "safe_mode": self._safe_mode,
            "intel_providers": len(self._intel_providers),
            "matchers": self.matchers.stats(),
            "blocklist_blocks": self._blocklist_blocks,
            "blocklist_domains": len(self._blocklist._domains)
            if self._blocklist
            else 0,
            "blocklist_allowlist": len(self._blocklist._allowlist)
            if self._blocklist
            else 0,
            "blocklist_stats": self._blocklist.get_stats() if self._blocklist else None,
            "safesearch_redirects": self._safesearch_redirects,
            "parental_blocks": self._parental_blocks,
            # Heuristics stats
            "heuristics_blocks": self._heuristics_blocks,
            "heuristics_observes": self._heuristics_observes,
            "heuristics_enabled": verdict_runtime().HEURISTICS_AVAILABLE
            and self._heuristics is not None,
        }

        # Add CNAME analyzer stats if available
        if verdict_runtime().CNAME_ANALYZER_AVAILABLE:
            try:
                analyzer = verdict_runtime().get_cname_analyzer()
                stats["cname_analyzer"] = analyzer.get_stats()
            except Exception:
                pass

        # Add parental control stats if available
        if self._parental:
            try:
                stats["parental_control"] = self._parental.get_stats()
            except Exception:
                pass

        # Add heuristics engine stats if available
        if self._heuristics:
            try:
                stats["heuristics"] = self._heuristics.get_stats()
            except Exception:
                pass

        return stats

    def get_cache_health(self) -> dict[str, Any]:
        """
        Get cache health metrics for monitoring.

        Returns dict with cache hit rates and sizes.
        Useful for alerting when hit rate drops.
        """
        health = {
            "status": "healthy",
            "warnings": [],
        }

        # CNAME analyzer cache
        if verdict_runtime().CNAME_ANALYZER_AVAILABLE:
            try:
                analyzer = verdict_runtime().get_cname_analyzer()
                cname_stats = analyzer.get_stats()
                hit_rate = cname_stats.get("cache_hit_rate", 0)
                cache_size = cname_stats.get("cache_size", 0)

                health["cname_cache"] = {
                    "hit_rate": round(hit_rate * 100, 1),
                    "size": cache_size,
                    "max_size": 10000,  # ANALYSIS_CACHE_SIZE
                }

                # Warn if hit rate is low after significant traffic
                chains_analyzed = cname_stats.get("chains_analyzed", 0)
                if chains_analyzed > 1000 and hit_rate < 0.3:
                    health["warnings"].append(
                        f"CNAME cache hit rate low: {hit_rate * 100:.1f}% "
                        "(consider increasing cache size)"
                    )
                    health["status"] = "degraded"
            except Exception as e:
                health["cname_cache"] = {"error": str(e)}

        return health
