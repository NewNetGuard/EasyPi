"""VerdictDecisionMixin implementation."""

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


class VerdictDecisionMixin:
    async def _gather_intel(
        self,
        domain: str,
        ctx: "FlowContext",
        evidence: EvidenceChain,
    ) -> None:
        """Gather intelligence from all registered providers."""
        if not self._intel_providers:
            return

        context = {
            "client_ip": ctx.client_ip,
            "query_type": ctx.question.rdtype,
            "protocol": ctx.protocol,
        }

        # Run all intel providers in parallel with standard protocol
        tasks = [
            provider.analyze(domain, context) for provider in self._intel_providers
        ]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Intel provider error: {result}")
                    continue

                # Result should be list of Evidence items
                if result is None:
                    continue
                if isinstance(result, list):
                    for item in result:
                        evidence.add(item)
                else:
                    # Single Evidence item (legacy)
                    evidence.add(result)

        except Exception as e:
            logger.error(f"Intel gathering failed: {e}")

    async def _check_shield(
        self,
        domain: str,
        ctx: "FlowContext",
        evidence: EvidenceChain,
    ) -> None:
        """Check shield policies."""
        if not self._shield_provider:
            return

        context = {
            "client_ip": ctx.client_ip,
            "timestamp": ctx.timestamp,
        }

        # Extract device ID from context if available
        device_id = getattr(ctx, "device_id", None)

        try:
            results = await self._shield_provider.evaluate(
                domain,
                device_id,
                context,
            )

            for item in results:
                evidence.add(item)

        except Exception as e:
            logger.error(f"Shield check failed: {e}")

    def _has_explicit_allow(self, evidence: EvidenceChain) -> bool:
        """Check if there's an explicit allow rule with high confidence."""
        for e in evidence.items:
            if (
                e.source.category == "matcher"
                and e.suggested_action == "allow"
                and e.confidence >= 90
            ):
                return True
        return False

    def _determine_verdict(
        self,
        evidence: EvidenceChain,
    ) -> tuple[VerdictAction, VerdictReason, str | None]:
        """Determine final verdict from evidence."""
        if not evidence.items:
            return VerdictAction.OBSERVE, VerdictReason.NO_MATCH, None

        # Get recommended action and confidence
        action_str = evidence.recommended_action
        confidence = evidence.total_confidence

        # Map to VerdictAction
        action_map = {
            "allow": VerdictAction.ALLOW,
            "deny": VerdictAction.DENY,
            "redirect": VerdictAction.REDIRECT,
            "observe": VerdictAction.OBSERVE,
        }
        action = action_map.get(action_str, VerdictAction.OBSERVE)

        # Check confidence threshold for blocking
        if action in (VerdictAction.DENY, VerdictAction.REDIRECT):
            if confidence < self._min_confidence_to_block:
                # Not confident enough to block
                action = VerdictAction.OBSERVE

        # Determine reason
        reason = self._determine_reason(evidence, action)

        # Get redirect target if applicable
        redirect = None
        if action == VerdictAction.REDIRECT:
            redirect = self._get_redirect_target(evidence)

        return action, reason, redirect

    def _determine_reason(
        self,
        evidence: EvidenceChain,
        action: VerdictAction,
    ) -> VerdictReason:
        """Determine the primary reason for the verdict."""
        if action == VerdictAction.ALLOW:
            # Check if it's a whitelist or just no match
            for e in evidence.items:
                if e.suggested_action == "allow" and e.confidence >= 80:
                    if e.source.category == "matcher":
                        return VerdictReason.WHITELIST
                    return VerdictReason.SAFE_DOMAIN
            return VerdictReason.NO_MATCH

        # For blocking actions, find the primary reason
        blocking = evidence.get_blocking_evidence()
        if not blocking:
            return VerdictReason.NO_MATCH

        # Find highest confidence blocking evidence
        primary = max(blocking, key=lambda e: e.weighted_confidence)

        # Map source/metadata to reason
        if "advertising" in str(primary.metadata.get("tags", [])):
            return VerdictReason.ADVERTISING
        if "tracking" in str(primary.metadata.get("tags", [])):
            return VerdictReason.TRACKING
        if "malware" in str(primary.metadata.get("tags", [])):
            return VerdictReason.MALWARE
        if "phishing" in str(primary.metadata.get("tags", [])):
            return VerdictReason.PHISHING

        if primary.source == EvidenceSource.INTEL_ENTROPY:
            return VerdictReason.DNS_TUNNELING
        if primary.source == EvidenceSource.INTEL_CNAME:
            return VerdictReason.CNAME_CLOAKING
        if primary.source == EvidenceSource.SHIELD_SCHEDULE:
            return VerdictReason.SCHEDULE_BLOCKED
        if primary.source == EvidenceSource.SHIELD_DEVICE:
            return VerdictReason.DEVICE_POLICY
        if primary.source == EvidenceSource.SHIELD_PROFILE:
            return VerdictReason.SHIELD_PROFILE
        if primary.source == EvidenceSource.INTEL_DOMAIN:
            return VerdictReason.DOMAIN_ANOMALY

        # Only automatic detection gets here. BLACKLIST is reserved for the
        # user's own list, which the pipeline reports before this stage.
        return VerdictReason.HEURISTICS_BLOCK

    def _get_redirect_target(self, evidence: EvidenceChain) -> str | None:
        """Get redirect target from evidence metadata."""
        for e in evidence.items:
            if e.suggested_action == "redirect":
                target = e.metadata.get("redirect_target")
                if target:
                    return target
        return "0.0.0.0"

    def _build_result(
        self,
        flow_id: str,
        domain: str,
        action: VerdictAction,
        reason: VerdictReason,
        evidence: EvidenceChain,
        redirect_target: str | None = None,
        start_time: float = 0,
    ) -> VerdictResult:
        """Build final verdict result and update stats."""
        processing_time = (time.monotonic() - start_time) * 1000 if start_time else 0

        # Update statistics
        self._total_verdicts += 1
        if action.is_blocking:
            self._blocked_count += 1
        else:
            self._allowed_count += 1

        # Update rolling average
        self._avg_processing_ms = (
            self._avg_processing_ms * 0.95 + processing_time * 0.05
        )

        return VerdictResult(
            flow_id=flow_id,
            domain=domain,
            action=action,
            confidence=evidence.total_confidence,
            reason=reason,
            evidence=evidence,
            redirect_target=redirect_target,
            processing_time_ms=processing_time,
        )
