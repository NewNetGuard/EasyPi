"""NetProtection-focused agent module."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime, timezone

from app.agent.adapters.netprotection import NetProtectionAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class NetProtectionAgent:
    """Explain device, domain, and DNS protection issues."""

    name = "netprotection_agent"
    _DOMAIN_RE = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
        re.IGNORECASE,
    )
    _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _KEYWORDS = (
        "dns",
        "domain",
        "blocked",
        "block",
        "bypass",
        "quarantine",
        "parental",
        "guard",
        "netprotection",
        "internet",
        "shadow",
        "suspicious",
        "heuristic",
        "tracker",
        "rewrite",
        "profile",
        "query log",
        "upstream",
    )
    _ROUTES = ("guard", "dns", "network-activity")
    _TAB_ALIASES = {
        "dashboard": "dashboard",
        "ad-tracker": "ad-tracker",
        "ad-tracker-ai": "ad-tracker",
        "nrd": "nrd",
        "new-domains": "nrd",
        "shadow": "shadow-mode",
        "shadow-mode": "shadow-mode",
        "heuristics": "heuristics",
        "ai-engine": "heuristics",
        "parental": "parental",
        "parental-controls": "parental",
        "schedules": "schedules",
        "devices": "devices",
        "ad-blocking": "ad-blocking",
        "lists": "lists",
        "firewall": "firewall",
        "query-log": "query-log",
        "security": "security",
        "security-monitor": "security",
        "statistics": "statistics",
        "stats": "statistics",
        "dns": "dns",
        "dns-settings": "dns",
        "advanced": "advanced",
    }
    _DNS_STALE_THRESHOLD_SECONDS = 120

    def __init__(self, adapter: NetProtectionAdapter, *, now_provider=None) -> None:
        self.adapter = adapter
        self.now_provider = now_provider or (lambda: datetime.now(timezone.utc))

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if request.target_type in {"device", "domain"}:
            score += 90

        if self._extract_domain(request.target or request.question):
            score += 80
        elif self._extract_ipv4(request.target or request.question):
            score += 70

        keyword_hits = sum(1 for keyword in self._KEYWORDS if keyword in question or keyword in target)
        score += min(75, keyword_hits * 15)
        if "guard" in question or "guard" in target or "netprotection" in question or "netprotection" in target:
            score += 35

        if any(token in route for token in self._ROUTES):
            score += 20

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()

        explicit_target = str(request.target or "").strip()
        if request.target_type == "domain" and explicit_target:
            return await self._diagnose_domain(explicit_target)
        if request.target_type == "device" and explicit_target:
            return await self._diagnose_device(explicit_target, await self.adapter.get_clients())

        domain = self._extract_domain(explicit_target or request.question)
        if domain:
            return await self._diagnose_domain(domain)

        tab = self._normalize_tab(request.tab)
        if tab:
            return await self._diagnose_tab(tab)

        if any(token in question for token in ("shadow", "suspicious", "heuristic", "ad tracker", "tracker ai")):
            return await self._diagnose_shadow_mode()
        if any(token in question for token in ("stats", "statistics", "protection active", "protection disabled", "guard dashboard")):
            return await self._diagnose_status_overview()
        if any(token in question for token in ("encrypted dns", "doh", "dot", "upstream", "dns settings")):
            validate_upstreams = any(token in question for token in ("healthy", "health", "failing", "failed", "failure", "test", "working"))
            return await self._diagnose_dns_settings(validate_upstreams=validate_upstreams)
        if any(token in question for token in ("whitelist", "blacklist", "list update", "lists", "rewrite", "rewrites", "profile", "profiles", "schedule", "rule", "query log", "statistics")):
            return await self._diagnose_policy_layers(question)

        clients = await self.adapter.get_clients()
        intent_type, intent_target = self._resolve_intent(request, clients)

        if intent_type == "device":
            return await self._diagnose_device(intent_target, clients)
        if intent_type == "domain":
            return await self._diagnose_domain(intent_target)
        # No specific sub-topic or device/domain intent matched, but this module
        # was still selected for a Guard Security question — answer with the
        # general protection status overview instead of deferring to the fallback.
        return await self._diagnose_status_overview()

    async def _diagnose_tab(self, tab: str) -> AgentResponse:
        handlers = {
            "dashboard": self._diagnose_status_overview,
            "ad-tracker": self._diagnose_ad_tracker,
            "nrd": self._diagnose_nrd,
            "shadow-mode": self._diagnose_shadow_mode,
            "heuristics": self._diagnose_heuristics,
            "parental": self._diagnose_parental_overview,
            "schedules": self._diagnose_schedules,
            "devices": self._diagnose_devices_overview,
            "ad-blocking": self._diagnose_ad_blocking,
            "lists": self._diagnose_lists,
            "firewall": self._diagnose_firewall,
            "query-log": self._diagnose_query_log,
            "security": self._diagnose_security_monitor,
            "statistics": self._diagnose_statistics,
            "dns": self._diagnose_dns_tab,
            "advanced": self._diagnose_advanced,
        }
        return await handlers[tab]()

    def _tab_response(
        self,
        *,
        tab: str,
        title: str,
        summary: str,
        purpose: str,
        checks: list[str],
        facts: list[AgentFact],
        recommendations: list[str],
        confidence: str = "high",
    ) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=f"guard-security-{tab}",
            matched=True,
            title=title,
            summary=summary,
            confidence=confidence,
            section="guard-security",
            subsection=tab,
            module=self.name,
            checks_run=checks,
            facts=facts,
            reason_chain=[
                purpose,
                "The current state was read from the same local services used by this Guard Security tab.",
            ],
            recommendations=recommendations,
        )

    def _unavailable_tab_response(self, tab: str, checks: list[str]) -> AgentResponse:
        """Return an honest result when every source for a tab is empty."""

        return AgentResponse(
            category="service",
            target=f"guard-security-{tab}",
            matched=True,
            title=f"Guard Security {tab} data unavailable",
            summary=f"Guard Security {tab} data is unavailable, so its current state is unknown.",
            confidence="low",
            section="guard-security",
            subsection=tab,
            module=self.name,
            checks_run=checks,
            facts=[AgentFact("Source data", "Unavailable", "warning")],
            reason_chain=[
                "The configured local sources returned no usable payload.",
                "An empty fallback was not interpreted as a measured zero or disabled state.",
            ],
            recommendations=["Refresh the tab or inspect the underlying service/API error before changing policy."],
        )

    async def _diagnose_status_overview(self) -> AgentResponse:
        try:
            status, stats, dashboard_stats, query_log_stats = await self._gather_status_payloads()
        except Exception as exc:
            return AgentResponse(
                category="service",
                target="guard-security",
                matched=True,
                title="Guard Security source unavailable",
                summary="Guard Security health could not be confirmed because a runtime source failed.",
                confidence="low",
                section="guard-security",
                subsection="dashboard",
                module=self.name,
                source_status="unavailable",
                source_errors=[f"{type(exc).__name__}: {exc}"],
                facts=[AgentFact("Source failure", f"{type(exc).__name__}: {exc}", "warning")],
                reason_chain=["A required NetProtection status source failed before the health comparison completed."],
                recommendations=["Restore the NetProtection status source and retry."],
            )
        if not any((status, stats, dashboard_stats, query_log_stats)):
            return self._unavailable_tab_response(
                "dashboard",
                ["netprotection_status", "netprotection_stats", "dashboard_stats", "query_log_stats"],
            )
        running = bool(status.get("running"))
        protection_enabled = bool(status.get("protection_enabled", running))
        ds = dashboard_stats or {}
        qs = query_log_stats or {}
        st = stats or {}
        # get_dashboard_stats() returns snake_case keys with real values
        # (total_queries, blocked_today, blocked_domains, active_blocklists,
        # block_percentage, active_threats). Read those; fall back to the raw
        # stats / query-log payloads only if a value is missing.
        dashboard_total_present = "total_queries" in ds
        raw_total_present = "total_queries" in st
        total_queries = (
            ds.get("total_queries")
            if dashboard_total_present
            else st.get("total_queries") if raw_total_present else qs.get("total_logged", 0)
        )
        dashboard_blocked_present = "blocked_today" in ds
        blocked_queries = (
            ds.get("blocked_today")
            if dashboard_blocked_present
            else st.get("blocked_queries") if "blocked_queries" in st else qs.get("blocked_total", 0)
        )
        counters_conflict = (
            dashboard_total_present
            and raw_total_present
            and int(ds.get("total_queries") or 0) != int(st.get("total_queries") or 0)
        )
        facts = [
            AgentFact("Service running", self._yes_no(running), "info" if running else "critical"),
            AgentFact("Protection enabled", self._yes_no(protection_enabled), "info" if protection_enabled else "warning"),
            AgentFact("Blocklist domains", str(ds.get("blocked_domains") or 0)),
            AgentFact("Active blocklists", str(ds.get("active_blocklists") or 0)),
            AgentFact("Total queries", str(total_queries)),
            AgentFact("Blocked queries", str(blocked_queries)),
            AgentFact("Block rate", "%.1f%%" % float(ds.get("block_percentage") or 0)),
            AgentFact("Active threats (today)", str(ds.get("active_threats") or 0)),
        ]
        block_rate = float(ds.get("block_percentage") or 0)
        threats = int(ds.get("active_threats") or 0)
        tq = int(total_queries or 0)

        if counters_conflict:
            summary = "Guard Security query counters are inconsistent across dashboard and raw statistics, so filtering effectiveness is unknown."
            confidence = "low"
            reason_chain = [
                "Dashboard and raw statistics returned conflicting total-query counters.",
                "The agent did not silently replace an explicit zero with a different source value.",
            ]
            recommendations = ["Refresh both sources and inspect service restart/reset history before judging filtering health."]
        elif not running:
            summary = "Guard Security is not running — no DNS filtering is happening right now."
            confidence = "high"
            reason_chain = [
                "NetProtection service status was inspected.",
                "The local status reports the service as stopped.",
            ]
            recommendations = [
                "Start NetProtection from Guard Security so DNS filtering resumes.",
                "If it will not start, check the easypi-netprotection service logs.",
            ]
        elif not protection_enabled:
            summary = "Guard Security is running, but protection is disabled — queries currently pass through unfiltered."
            confidence = "high"
            reason_chain = [
                "NetProtection service status was inspected.",
                "The service is running, but protection is not currently enabled.",
            ]
            recommendations = [
                "Re-enable protection in Guard Security to resume ad/tracker/threat blocking.",
            ]
        elif tq < 10:
            summary = "Guard Security has only a small observation sample; a recent restart, short window, or clients bypassing EasyPi DNS could explain it."
            confidence = "medium"
            reason_chain = [
                "The service is running and protection is enabled.",
                "Only %d DNS quer%s were counted, so clients are not sending traffic here." % (tq, "y" if tq == 1 else "ies"),
            ]
            recommendations = [
                "Set this EasyPi as the DNS server on your router so all devices use it.",
                "Or enable Transparent DNS if EasyPi is the gateway / Tailscale exit node.",
                "Then re-check — the query counter should start rising.",
            ]
        elif tq >= 50 and block_rate < 0.5:
            summary = "Guard Security is receiving queries but blocking almost nothing — filtering may be off or the blocklist is not loaded."
            confidence = "high"
            reason_chain = [
                "The service is running and receiving DNS queries.",
                "Block rate is only %.1f%% across %d queries, which is unexpectedly low for an active blocklist." % (block_rate, tq),
            ]
            recommendations = [
                "Confirm a blocklist is active and loaded (Guard Security -> Lists).",
                "Check that protection and heuristics are enabled, not just the service.",
            ]
        elif block_rate <= 0 and int(blocked_queries or 0) == 0:
            summary = "Guard Security is running with protection enabled, but current counters do not confirm filtering effectiveness."
            confidence = "medium"
            reason_chain = [
                "The service and protection flags are enabled.",
                "No blocked result is present in the available observation window, so active filtering is unconfirmed.",
            ]
            recommendations = ["Verify an expected test domain or recent verdict before concluding that filtering is effective."]
        else:
            summary = "Guard Security is running and actively filtering DNS (%.1f%% of queries blocked, %d threat block%s today)." % (block_rate, threats, "" if threats == 1 else "s")
            confidence = "high"
            reason_chain = [
                "The service is running with protection enabled.",
                "%d queries seen with a %.1f%% block rate — filtering is active and working." % (tq, block_rate),
            ]
            recommendations = [
                "No action needed — protection is active and filtering traffic.",
                "Open Guard Security Dashboard for a live view of top blocked domains and clients.",
            ]
        return AgentResponse(
            category="service",
            target="guard-security",
            matched=True,
            title="Guard Security status diagnostics",
            summary=summary,
            confidence=confidence,
            section="guard-security",
            subsection="dashboard",
            module=self.name,
            checks_run=["netprotection_status", "netprotection_stats", "dashboard_stats", "query_log_stats"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    async def _diagnose_ad_tracker(self) -> AgentResponse:
        stats, recent = await asyncio.gather(
            self.adapter.get_ad_tracker_stats(),
            self.adapter.get_recent_ad_tracker_detections(limit=10),
        )
        if not stats and not recent:
            return self._unavailable_tab_response("ad-tracker", ["ad_tracker_stats", "ad_tracker_recent"])
        total = int(stats.get("total_analyzed") or 0)
        ads = int(stats.get("ads_detected") or 0)
        trackers = int(stats.get("trackers_detected") or 0)
        blocked = int(stats.get("blocked_today") or 0)
        methods = stats.get("detection_methods") if isinstance(stats.get("detection_methods"), dict) else {}
        facts = [
            AgentFact("Flows analyzed", str(total)),
            AgentFact("Ad domains detected", str(ads)),
            AgentFact("Tracker domains detected", str(trackers)),
            AgentFact("Blocked today", str(blocked)),
            AgentFact("Detection methods active", str(sum(1 for value in methods.values() if int(value or 0) > 0))),
            AgentFact("Recent detections", str(len(recent))),
        ]
        if recent:
            facts.append(AgentFact("Latest detection", str(recent[0].get("domain") or "Unknown")))
        summary = (
            f"Ad/Tracker AI has analyzed {total} behavioral candidates and recorded {len(recent)} recent detection(s)."
            if total or recent
            else "Ad/Tracker AI is available, but it has not recorded behavioral detections in the current data window."
        )
        return self._tab_response(
            tab="ad-tracker",
            title="Guard Security Ad/Tracker AI diagnostics",
            summary=summary,
            purpose="Ad/Tracker AI correlates persisted behavioral signals with real DNS verdicts instead of treating Shadow Mode as the same feature.",
            checks=["ad_tracker_stats", "ad_tracker_recent"],
            facts=facts,
            recommendations=["Review recent detections and their evidence when an advertisement or tracker is still getting through."],
        )

    async def _diagnose_nrd(self) -> AgentResponse:
        status, blocked = await asyncio.gather(
            self.adapter.get_nrd_status(),
            self.adapter.get_nrd_blocked(limit=10),
        )
        enabled = bool(status.get("enabled"))
        feed_domains = int(status.get("feed_domains") or 0)
        facts = [
            AgentFact("NRD blocking enabled", self._yes_no(enabled), "info" if enabled else "warning"),
            AgentFact("Registration-age window", f"{int(status.get('max_age_days') or 0)} days"),
            AgentFact("Domains in NRD feed", str(feed_domains)),
            AgentFact("Recent NRD blocks", str(len(blocked))),
            AgentFact("Feed last updated", str(status.get("feed_updated_at") or "Never")),
        ]
        if blocked:
            facts.append(AgentFact("Latest NRD block", str(blocked[0].get("domain") or "Unknown")))
        if not enabled:
            summary = "New-Domain Guard is disabled, so newly registered domains are not being blocked by the NRD layer."
        elif feed_domains == 0:
            summary = "New-Domain Guard is enabled, but its local feed is empty and needs to be refreshed."
        else:
            summary = f"New-Domain Guard is enabled with {feed_domains} recently registered domains in its feed."
        return self._tab_response(
            tab="nrd",
            title="Guard Security New Domains diagnostics",
            summary=summary,
            purpose="New Domains blocks domains registered inside the configured age window before ordinary blocklists learn about them.",
            checks=["nrd_status", "nrd_recent_blocks"],
            facts=facts,
            recommendations=["Refresh the NRD feed if it is empty or stale; allowlist any confirmed legitimate new domain."],
        )

    async def _diagnose_heuristics(self) -> AgentResponse:
        stats, config, ml = await asyncio.gather(
            self.adapter.get_heuristics_stats(),
            self.adapter.get_heuristics_config(),
            self.adapter.get_ml_status(),
        )
        enabled = bool(config.get("enabled", stats.get("enabled", False)))
        detectors = config.get("detectors") if isinstance(config.get("detectors"), dict) else {}
        model = ml.get("model") if isinstance(ml.get("model"), dict) else {}
        behavior_model = ml.get("behavior_model") if isinstance(ml.get("behavior_model"), dict) else {}
        facts = [
            AgentFact("AI Engine enabled", self._yes_no(enabled), "info" if enabled else "warning"),
            AgentFact("Enabled detectors", f"{sum(1 for value in detectors.values() if value)}/{len(detectors)}"),
            AgentFact("Total analyzed", str(stats.get("total_analyzed") or 0)),
            AgentFact("Blocked by heuristics", str(stats.get("blocked_by_heuristics") or 0)),
            AgentFact("Observed domains", str(stats.get("observed_domains") or 0)),
            AgentFact("Observe threshold", str(config.get("observe_threshold") or "Unknown")),
            AgentFact("Block threshold", str(config.get("block_threshold") or "Unknown")),
            AgentFact("Domain language model", "Available" if model.get("available") else "Not trained", "info" if model.get("available") else "warning"),
            AgentFact("Flow behavior model", "Available" if behavior_model.get("available") else "Not trained", "info" if behavior_model.get("available") else "warning"),
        ]
        summary = (
            "AI Engine is enabled and its detector and learning-model state was loaded successfully."
            if enabled
            else "AI Engine is disabled; behavioral and domain-language detections will not contribute normal heuristic decisions."
        )
        return self._tab_response(
            tab="heuristics",
            title="Guard Security AI Engine diagnostics",
            summary=summary,
            purpose="AI Engine combines DGA, homoglyph, first-seen, anomaly, ASN, domain-language, and flow-behavior signals into observe or block decisions.",
            checks=["heuristics_stats", "heuristics_config", "ml_status"],
            facts=facts,
            recommendations=["Check disabled detectors, thresholds, and model availability when expected heuristic detections are missing."],
        )

    async def _diagnose_parental_overview(self) -> AgentResponse:
        config, clients, services, fail_closed = await asyncio.gather(
            self.adapter.get_config(),
            self.adapter.get_clients(),
            self.adapter.get_blocked_services(),
            self.adapter.list_fail_closed_clients(),
        )
        bypass_history = self.adapter.get_bypass_history()
        if not any((config, clients, services, fail_closed, bypass_history)):
            return self._unavailable_tab_response(
                "parental",
                ["netprotection_config", "managed_clients", "blocked_services", "bypass_history", "fail_closed_state"],
            )
        parental_clients = [client for client in clients if client.get("parental_enabled") or client.get("parental")]
        safe_search_clients = [client for client in clients if client.get("safesearch") or client.get("safe_search")]
        facts = [
            AgentFact("Global parental control", self._yes_no(bool(config.get("parental_control")))),
            AgentFact("Global SafeSearch", self._yes_no(bool(config.get("safe_search")))),
            AgentFact("Managed clients", str(len(clients))),
            AgentFact("Clients with parental control", str(len(parental_clients))),
            AgentFact("Clients with SafeSearch", str(len(safe_search_clients))),
            AgentFact("Blockable services/categories", str(len(services))),
            AgentFact("Bypass history entries", str(len(bypass_history))),
            AgentFact("Fail-closed clients", str(len(fail_closed)), "warning" if fail_closed else "info"),
        ]
        summary = f"Parental Controls currently manages {len(clients)} device(s), with {len(fail_closed)} device(s) in fail-closed state."
        return self._tab_response(
            tab="parental",
            title="Guard Security Parental Controls diagnostics",
            summary=summary,
            purpose="Parental Controls applies per-device profiles, SafeSearch, service blocking, bypass detection, and fail-closed quarantine.",
            checks=["netprotection_config", "managed_clients", "blocked_services", "bypass_history", "fail_closed_state"],
            facts=facts,
            recommendations=["Select a specific device for detailed policy, DNS activity, bypass, and quarantine diagnostics."],
        )

    async def _diagnose_schedules(self) -> AgentResponse:
        schedules, enforcement = await asyncio.gather(
            self.adapter.get_schedules(),
            self.adapter.get_schedule_enforcement_status(),
        )
        if not schedules and not enforcement:
            return self._unavailable_tab_response("schedules", ["schedules", "schedule_enforcement_status"])
        enabled = [schedule for schedule in schedules if schedule.get("enabled", True)]
        targeted = [schedule for schedule in schedules if schedule.get("device_ips") or schedule.get("device_macs")]
        mode = str(enforcement.get("mode") or "unknown")
        facts = [
            AgentFact("Schedules", str(len(schedules))),
            AgentFact("Enabled schedules", str(len(enabled))),
            AgentFact("Device-targeted schedules", str(len(targeted))),
            AgentFact("Enforcement mode", mode, "warning" if mode == "dns-only" else "info"),
            AgentFact("IPv4 forwarding", self._yes_no(bool(enforcement.get("ip_forward")))),
            AgentFact("iptables available", self._yes_no(bool(enforcement.get("iptables")))),
        ]
        summary = f"Schedules has {len(enabled)} enabled rule set(s); enforcement is currently {mode}."
        return self._tab_response(
            tab="schedules",
            title="Guard Security Schedules diagnostics",
            summary=summary,
            purpose="Schedules activates time-based category or internet restrictions globally or for selected devices.",
            checks=["schedules", "schedule_enforcement_status"],
            facts=facts,
            recommendations=["Use gateway enforcement for restrictions that must survive a client changing its DNS server."],
        )

    async def _diagnose_devices_overview(self) -> AgentResponse:
        clients, baseline = await asyncio.gather(
            self.adapter.get_clients(),
            self.adapter.get_devices_with_baseline(),
        )
        if not clients and not baseline:
            return self._unavailable_tab_response("devices", ["managed_clients", "device_baselines"])
        baseline_items = baseline.get("items") if isinstance(baseline.get("items"), list) else []
        baseline_available = bool(baseline.get("baseline_available", True))
        baseline_count = len(baseline_items) if baseline_available else 0
        enabled_clients = [client for client in clients if client.get("enabled", True)]
        facts = [
            AgentFact("Managed devices", str(len(clients))),
            AgentFact("Enabled devices", str(len(enabled_clients))),
            AgentFact("Devices with behavior baseline", str(baseline_count)),
            AgentFact("Baseline inventory total", str(baseline.get("total") or len(baseline_items))),
            AgentFact("Behavior baseline available", self._yes_no(baseline_available)),
        ]
        summary = (
            f"Devices contains {len(clients)} managed device(s) and {baseline_count} loaded behavior baseline record(s)."
            if baseline_available
            else f"Devices contains {len(clients)} managed device(s); this installation exposes the device inventory without behavior baselines."
        )
        return self._tab_response(
            tab="devices",
            title="Guard Security Devices diagnostics",
            summary=summary,
            purpose="Devices binds names and addresses to protection profiles, per-device rules, traffic history, and anomaly baselines.",
            checks=["managed_clients", "device_baselines"],
            facts=facts,
            recommendations=["Select a device to inspect its DNS freshness, profile, blocked services, bypass state, and recent query counts."],
        )

    async def _diagnose_ad_blocking(self) -> AgentResponse:
        status, verified, custom, progress = await asyncio.gather(
            self.adapter.get_blocklist_status(),
            self.adapter.get_verified_sources(),
            self.adapter.get_custom_sources(),
            self.adapter.get_blocklist_progress(),
        )
        selected = self.adapter.get_use_custom_blocklist()
        if not any((status, verified, custom, progress, selected)):
            return self._unavailable_tab_response(
                "ad-blocking",
                ["blocklist_status", "verified_sources", "custom_sources", "blocklist_selection", "generation_progress"],
            )
        effective = status.get("effective") if isinstance(status.get("effective"), dict) else {}
        total_domains = int(effective.get("total_domains") or status.get("total_domains") or 0)
        enabled_verified = sum(1 for source in verified if source.get("enabled"))
        enabled_custom = sum(1 for source in custom if source.get("enabled", True))
        phase = str(progress.get("phase") or "idle")
        facts = [
            AgentFact("Effective blocked domains", str(total_domains), "warning" if total_domains == 0 else "info"),
            AgentFact("Enabled verified sources", f"{enabled_verified}/{len(verified)}"),
            AgentFact("Enabled custom sources", f"{enabled_custom}/{len(custom)}"),
            AgentFact("Active blocklist", "Custom" if selected.get("use_custom") else "Verified"),
            AgentFact("Generation state", phase),
            AgentFact("Last generated", str(effective.get("generated_at") or "Unknown")),
        ]
        summary = (
            f"Ad Blocking has {total_domains} effective domains loaded from {enabled_verified + enabled_custom} enabled source(s)."
            if total_domains
            else "Ad Blocking currently has no effective domains loaded."
        )
        return self._tab_response(
            tab="ad-blocking",
            title="Guard Security Ad Blocking diagnostics",
            summary=summary,
            purpose="Ad Blocking builds the effective DNS blocklist from verified and explicitly enabled custom sources.",
            checks=["blocklist_status", "verified_sources", "custom_sources", "blocklist_selection", "generation_progress"],
            facts=facts,
            recommendations=["Regenerate blocklists when enabled sources exist but the effective domain count is zero or stale."],
        )

    async def _diagnose_lists(self) -> AgentResponse:
        whitelist, blacklist, matchers = await asyncio.gather(
            self.adapter.get_whitelist(),
            self.adapter.get_blacklist(),
            self.adapter.get_matchers(),
        )
        if not any((whitelist, blacklist, matchers)):
            return self._unavailable_tab_response("lists", ["whitelist", "blacklist", "matchers"])
        enabled_matchers = sum(1 for matcher in matchers if matcher.get("enabled", True))
        summary = f"Lists contains {len(whitelist)} allow entry(s), {len(blacklist)} block entry(s), and {enabled_matchers} enabled matcher(s)."
        return self._tab_response(
            tab="lists",
            title="Guard Security Lists diagnostics",
            summary=summary,
            purpose="Lists stores explicit allow and block exceptions plus matcher rules that override or complement downloaded sources.",
            checks=["whitelist", "blacklist", "matchers"],
            facts=[
                AgentFact("Whitelist entries", str(len(whitelist))),
                AgentFact("Blacklist entries", str(len(blacklist))),
                AgentFact("Matchers", str(len(matchers))),
                AgentFact("Enabled matchers", str(enabled_matchers)),
            ],
            recommendations=["Inspect rule priority and scope when an explicit list entry does not produce the expected verdict."],
        )

    async def _diagnose_firewall(self) -> AgentResponse:
        rules = await self.adapter.get_firewall_rules()
        if not rules:
            return self._unavailable_tab_response("firewall", ["firewall_rules"])
        allow = sum(1 for rule in rules if str(rule.get("action") or "").lower() == "allow")
        deny = sum(1 for rule in rules if str(rule.get("action") or "").lower() in {"deny", "reject"})
        hits = sum(int(rule.get("hits") or 0) for rule in rules)
        summary = f"Firewall currently exposes {len(rules)} rule(s): {allow} allow and {deny} deny/reject."
        return self._tab_response(
            tab="firewall",
            title="Guard Security Firewall diagnostics",
            summary=summary,
            purpose="Firewall controls IP, port, protocol, source, and destination traffic separately from DNS-domain filtering.",
            checks=["firewall_rules"],
            facts=[
                AgentFact("Rules", str(len(rules))),
                AgentFact("Allow rules", str(allow)),
                AgentFact("Deny/reject rules", str(deny)),
                AgentFact("Recorded rule hits", str(hits)),
            ],
            recommendations=["Review exact protocol, port, source, destination, and rule ordering when traffic is unexpectedly allowed or denied."],
        )

    async def _diagnose_query_log(self) -> AgentResponse:
        stats, config, recent = await asyncio.gather(
            self.adapter.get_query_log_stats(),
            self.adapter.get_query_log_config(),
            self.adapter.get_recent_verdicts(limit=10),
        )
        if not any((stats, config, recent)):
            return self._unavailable_tab_response(
                "query-log",
                ["query_log_stats", "query_log_config", "recent_verdicts"],
            )
        entries = int(stats.get("entries") or stats.get("total_logged") or len(recent))
        blocked = int(stats.get("blocked_total") or sum(1 for item in recent if self._is_blocked_entry(item)))
        enabled = bool(config.get("enabled", True))
        facts = [
            AgentFact("Query logging enabled", self._yes_no(enabled), "info" if enabled else "warning"),
            AgentFact("Stored entries", str(entries)),
            AgentFact("Blocked entries", str(blocked)),
            AgentFact("Recent verdicts loaded", str(len(recent))),
            AgentFact("Client IP anonymization", self._yes_no(bool(config.get("anonymize_client_ip")))),
        ]
        if recent:
            facts.append(AgentFact("Latest queried domain", str(recent[0].get("domain") or "Unknown")))
        summary = (
            f"Query Log is enabled and currently reports {entries} stored DNS verdict(s)."
            if enabled
            else "Query Log is disabled, so new DNS verdicts are not expected to appear."
        )
        return self._tab_response(
            tab="query-log",
            title="Guard Security Query Log diagnostics",
            summary=summary,
            purpose="Query Log records per-domain allow, deny, redirect, and observe decisions together with client and evidence data.",
            checks=["query_log_stats", "query_log_config", "recent_verdicts"],
            facts=facts,
            recommendations=["Select or name a domain for a verdict-specific explanation and matching allow/block action."],
        )

    async def _diagnose_security_monitor(self) -> AgentResponse:
        status, threats, banned = await asyncio.gather(
            self.adapter.get_threat_monitor_status(),
            self.adapter.get_threats(limit=100),
            self.adapter.get_banned_threats(),
        )
        if not any((status, threats, banned)):
            return self._unavailable_tab_response(
                "security",
                ["threat_monitor_status", "active_threats", "banned_threats"],
            )
        enabled = bool(status.get("enabled"))
        critical = sum(1 for threat in threats if str(threat.get("severity") or "").lower() == "critical")
        summary = (
            f"Security Monitor is enabled with {len(threats)} active threat record(s) and {len(banned)} banned IP(s)."
            if enabled
            else "Security Monitor is disabled and is not collecting new SSH, port-scan, or connection threat signals."
        )
        return self._tab_response(
            tab="security",
            title="Guard Security Security Monitor diagnostics",
            summary=summary,
            purpose="Security Monitor detects host-facing threats such as SSH brute force and port scans, and tracks firewall bans.",
            checks=["threat_monitor_status", "active_threats", "banned_threats"],
            facts=[
                AgentFact("Monitoring enabled", self._yes_no(enabled), "info" if enabled else "warning"),
                AgentFact("Active threats", str(len(threats))),
                AgentFact("Critical threats", str(critical), "critical" if critical else "info"),
                AgentFact("Banned IPs", str(len(banned))),
                AgentFact("SSH failure threshold", str(status.get("ssh_threshold") or "Unknown")),
                AgentFact("Automatic banning", self._yes_no(bool(status.get("auto_ban")))),
            ],
            recommendations=["Review active threats before banning an address, and never ban a private management address."],
        )

    async def _diagnose_statistics(self) -> AgentResponse:
        stats = await self.adapter.get_period_stats("24h")
        if not stats:
            return self._unavailable_tab_response("statistics", ["period_stats_24h"])
        total = int(stats.get("totalQueries") or 0)
        blocked = int(stats.get("blocked") or 0)
        rate = float(stats.get("blockRate") or (blocked / total * 100 if total else 0))
        summary = f"Statistics reports {total} DNS queries and {blocked} blocks over the last 24 hours ({rate:.1f}%)."
        return self._tab_response(
            tab="statistics",
            title="Guard Security Statistics diagnostics",
            summary=summary,
            purpose="Statistics aggregates Guard Security trends, top queried and blocked domains, client activity, and response time over a selected period.",
            checks=["period_stats_24h"],
            facts=[
                AgentFact("Queries (24h)", str(total)),
                AgentFact("Blocked (24h)", str(blocked)),
                AgentFact("Block rate", f"{rate:.1f}%"),
                AgentFact("Trend buckets", str(len(stats.get("queryTrend") or []))),
                AgentFact("Top blocked domains", str(len(stats.get("topBlocked") or []))),
                AgentFact("Top clients", str(len(stats.get("topClients") or []))),
                AgentFact("Average response time", str(stats.get("avgResponseTime") or "Unavailable")),
            ],
            recommendations=["If totals are zero while devices are active, verify they are sending DNS through EasyPi and that query logging is enabled."],
        )

    async def _diagnose_dns_tab(self) -> AgentResponse:
        upstream, dns_config, encrypted, rewrites = await asyncio.gather(
            self.adapter.get_upstream_servers(),
            self.adapter.get_dns_config(),
            self.adapter.get_encrypted_dns_settings(),
            self.adapter.get_rewrites(),
        )
        if not any((upstream, dns_config, encrypted, rewrites)):
            return self._unavailable_tab_response(
                "dns",
                ["upstream_servers", "dns_config", "encrypted_dns_settings", "dns_rewrites"],
            )
        servers = [str(item) for item in upstream.get("servers") or dns_config.get("upstream_dns") or [] if item]
        facts = [
            AgentFact("Upstream resolvers", str(len(servers)), "warning" if not servers else "info"),
            AgentFact("DNSSEC enabled", self._yes_no(bool(dns_config.get("dnssec_enabled")))),
            AgentFact("DoH listener enabled", self._yes_no(bool(encrypted.get("doh_enabled")))),
            AgentFact("DoT listener enabled", self._yes_no(bool(encrypted.get("dot_enabled")))),
            AgentFact("TLS ready", self._yes_no(bool(encrypted.get("tls_ready") or encrypted.get("tls_cert_path")))),
            AgentFact("Custom DNS rewrites", str(len(rewrites))),
            AgentFact("Cache size", str(dns_config.get("cache_size") or "Unknown")),
            AgentFact("Cache TTL", str(dns_config.get("cache_ttl") or "Unknown")),
        ]
        summary = (
            f"DNS Settings has {len(servers)} upstream resolver(s), {len(rewrites)} custom rewrite(s), and encrypted listener configuration loaded."
            if servers
            else "DNS Settings has no active upstream resolver configured."
        )
        return self._tab_response(
            tab="dns",
            title="Guard Security DNS Settings diagnostics",
            summary=summary,
            purpose="DNS Settings controls real upstream resolvers, encrypted DNS listeners, DNSSEC, cache behavior, and local rewrites.",
            checks=["upstream_servers", "dns_config", "encrypted_dns_settings", "dns_rewrites"],
            facts=facts,
            recommendations=["Test upstream resolvers when lookups fail; check rewrite precedence when a local hostname resolves incorrectly."],
        )

    async def _diagnose_advanced(self) -> AgentResponse:
        settings, ipv6, failsafe, query_config, shadow_settings = await asyncio.gather(
            self.adapter.get_all_settings(),
            self.adapter.get_ipv6_status(),
            self.adapter.get_failsafe_settings(),
            self.adapter.get_query_log_config(),
            self.adapter.get_shadow_mode_settings(),
        )
        if not any((settings, ipv6, failsafe, query_config, shadow_settings)):
            return self._unavailable_tab_response(
                "advanced",
                ["all_settings", "ipv6_status", "failsafe_settings", "query_log_config", "shadow_mode_settings"],
            )
        failsafe_enabled = bool(failsafe.get("enabled", True))
        facts = [
            AgentFact("IPv6 protected", self._yes_no(bool(ipv6.get("protected"))), "info" if ipv6.get("protected") else "warning"),
            AgentFact("Global IPv6 present", self._yes_no(bool(ipv6.get("has_global_ipv6")))),
            AgentFact("Fail-Safe enabled", self._yes_no(failsafe_enabled), "info" if failsafe_enabled else "warning"),
            AgentFact("Fail-Safe active", self._yes_no(bool(failsafe.get("is_active"))), "warning" if failsafe.get("is_active") else "info"),
            AgentFact("Fail-Safe restart count", str(failsafe.get("restart_count") or 0)),
            AgentFact("Query logging enabled", self._yes_no(bool(query_config.get("enabled", True)))),
            AgentFact("Shadow Mode enabled", self._yes_no(bool(shadow_settings.get("enabled")))),
            AgentFact("Settings groups", str(len(settings))),
        ]
        summary = "Advanced Guard Security runtime settings were loaded, including IPv6 exposure, Fail-Safe, query logging, and Shadow Mode state."
        return self._tab_response(
            tab="advanced",
            title="Guard Security Advanced diagnostics",
            summary=summary,
            purpose="Advanced contains recovery, IPv6 exposure, logging, notifications, maintenance, reset, and lower-level runtime controls.",
            checks=["all_settings", "ipv6_status", "failsafe_settings", "query_log_config", "shadow_mode_settings"],
            facts=facts,
            recommendations=["Treat reset and maintenance controls as destructive; verify backups and current service health before using them."],
        )

    async def _diagnose_dns_settings(self, *, validate_upstreams: bool = False) -> AgentResponse:
        settings = await self.adapter.get_encrypted_dns_settings()
        upstreams = [str(server) for server in settings.get("upstream_dns") or [] if server]
        upstream_test: dict[str, object] = {}
        if upstreams and validate_upstreams:
            upstream_test = dict(await self.adapter.test_upstream_dns(upstreams))
            if not isinstance(upstream_test.get("success"), bool):
                per_upstream = [value for value in upstream_test.values() if isinstance(value, dict)]
                if per_upstream:
                    upstream_test["success"] = all(value.get("success") is True for value in per_upstream)
        facts = [
            AgentFact("Encrypted DNS enabled", self._yes_no(bool(settings.get("enabled")))),
            AgentFact("DoH enabled", self._yes_no(bool(settings.get("doh_enabled")))),
            AgentFact("DoT enabled", self._yes_no(bool(settings.get("dot_enabled")))),
            AgentFact("TLS certificate present", self._yes_no(bool(settings.get("tls_cert_path")))),
            AgentFact("Upstream servers", str(len(upstreams))),
        ]
        if upstream_test:
            facts.append(
                AgentFact(
                    "Upstream test success",
                    self._yes_no(bool(upstream_test.get("success"))),
                    "info" if upstream_test.get("success") else "warning",
                )
            )

        if upstreams and upstream_test and not bool(upstream_test.get("success")):
            summary = "Guard Security encrypted DNS is configured, but upstream DNS validation failed."
            confidence = "high"
            reason_chain = [
                "Encrypted DNS settings were loaded from NetProtection.",
                "A local upstream DNS test was attempted with the configured servers.",
                "The upstream validation did not succeed.",
            ]
        elif not settings.get("enabled") and not settings.get("doh_enabled") and not settings.get("dot_enabled"):
            summary = "Guard Security encrypted DNS features are currently disabled."
            confidence = "high"
            reason_chain = [
                "Encrypted DNS settings were loaded from NetProtection.",
                "DoH and DoT are both disabled in the current configuration.",
            ]
        else:
            summary = "Guard Security DNS settings were loaded successfully."
            confidence = "medium"
            reason_chain = [
                "Encrypted DNS settings were loaded from NetProtection.",
                "No immediate encrypted-DNS configuration failure was confirmed from local facts.",
            ]
        return AgentResponse(
            category="service",
            target="guard-security-dns",
            matched=True,
            title="Guard Security DNS diagnostics",
            summary=summary,
            confidence=confidence,
            section="guard-security",
            subsection="dns-settings",
            module=self.name,
            source_status="partial" if upstream_test and not bool(upstream_test.get("success")) else "ok",
            checks_run=["encrypted_dns_settings", "upstream_dns_test"] if upstream_test else ["encrypted_dns_settings"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Review upstream DNS servers and certificate paths if encrypted DNS should be active.",
                "If DoH or DoT is expected publicly, validate firewall and listener exposure separately.",
            ],
        )

    async def _diagnose_policy_layers(self, question: str) -> AgentResponse:
        whitelist, blacklist, rewrites, profiles, rules, matchers = await self._gather_policy_payloads()
        query_log_stats = await self.adapter.get_query_log_stats()
        facts = [
            AgentFact("Whitelist entries", str(len(whitelist))),
            AgentFact("Blacklist entries", str(len(blacklist))),
            AgentFact("Rewrites", str(len(rewrites))),
            AgentFact("Shield profiles", str(len(profiles))),
            AgentFact("User rules", str(len(rules))),
            AgentFact("Matchers", str(len(matchers))),
            AgentFact("Query log entries", str(query_log_stats.get("entries") or 0)),
        ]
        summary = "Guard Security policy layers were loaded successfully."
        confidence = "medium"
        reason_chain = [
            "Local Guard Security list, profile, rewrite, and rule layers were inspected.",
        ]
        lowered = question.lower()
        if "query log" in lowered or "statistics" in lowered:
            entries = int(query_log_stats.get("entries") or 0)
            if entries == 0:
                summary = "Guard Security query log statistics are currently empty."
                confidence = "high"
                reason_chain.append("No local query-log entries are currently available.")
            else:
                summary = "Guard Security query log statistics are available locally."
                confidence = "high"
                reason_chain.append("Local query-log counters are populated.")
        elif ("profile" in lowered or "profiles" in lowered or "schedule" in lowered) and not profiles:
            summary = "Guard Security currently has no shield profiles available in local policy data."
            confidence = "high"
            reason_chain.append("No local shield profiles were returned.")
        elif ("rewrite" in lowered or "rewrites" in lowered) and not rewrites:
            summary = "Guard Security currently has no local rewrite rules available."
            confidence = "high"
            reason_chain.append("No local DNS rewrite entries were returned.")
        elif ("list" in lowered or "whitelist" in lowered or "blacklist" in lowered) and not whitelist and not blacklist:
            summary = "Guard Security currently has no local whitelist or blacklist entries available."
            confidence = "high"
            reason_chain.append("No local custom allow-list or block-list entries were returned.")
        elif ("firewall" in lowered or "rule" in lowered) and not rules and not matchers:
            summary = "Guard Security currently has no local matcher or user-rule entries for the requested policy scope."
            confidence = "high"
            reason_chain.append("No local matcher or user-rule entries were returned.")
        elif not any((whitelist, blacklist, rewrites, profiles, rules, matchers)):
            summary = "Guard Security policy layers are currently empty or unavailable."
            confidence = "high"
            reason_chain.append("No local list, rewrite, profile, or matcher entries were returned.")
        return AgentResponse(
            category="service",
            target="guard-security-policy",
            matched=True,
            title="Guard Security policy diagnostics",
            summary=summary,
            confidence=confidence,
            section="guard-security",
            subsection="advanced",
            module=self.name,
            checks_run=["whitelist", "blacklist", "rewrites", "shield_profiles", "user_rules", "matchers", "query_log_stats"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Inspect the specific list, rewrite, or profile entry if a rule is not applying as expected.",
            ],
        )

    async def _diagnose_shadow_mode(self) -> AgentResponse:
        shadow_stats = await self.adapter.get_shadow_stats()
        shadow_domains = await self.adapter.get_shadow_domains(limit=10)
        if not shadow_stats and not shadow_domains:
            return self._unavailable_tab_response("shadow-mode", ["shadow_stats", "shadow_domains"])
        facts = [
            AgentFact("Observed shadow domains", str(len(shadow_domains))),
            AgentFact("Shadow total observed", str(shadow_stats.get("total_observed") or shadow_stats.get("total") or 0)),
            AgentFact("Shadow promoted", str(shadow_stats.get("promoted") or 0)),
            AgentFact("Shadow ignored", str(shadow_stats.get("ignored") or 0)),
        ]
        if shadow_domains:
            sample = shadow_domains[0]
            facts.append(AgentFact("Latest shadow domain", str(sample.get("domain") or "Unknown")))
            facts.append(AgentFact("Latest confidence", str(sample.get("confidence") or sample.get("score") or "Unknown")))
            summary = "Shadow Mode has recent observed domains available for review."
            confidence = "high"
            reason_chain = [
                "Shadow statistics and recent observed domains were loaded from NetProtection.",
                "At least one observed domain is available for operator review.",
            ]
        else:
            summary = "Shadow Mode currently has no recent observed domains."
            confidence = "medium"
            reason_chain = [
                "Shadow statistics and recent observed domains were loaded from NetProtection.",
                "No recent shadow observations were returned.",
            ]
        return AgentResponse(
            category="service",
            target="guard-security-shadow",
            matched=True,
            title="Guard Security Shadow Mode diagnostics",
            summary=summary,
            confidence=confidence,
            section="guard-security",
            subsection="shadow-mode",
            module=self.name,
            checks_run=["shadow_stats", "shadow_domains"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Review suspicious domains in Shadow Mode before promoting them into blocking policy.",
            ],
        )

    async def _diagnose_device(
        self,
        target: str,
        clients: list[dict[str, object]],
    ) -> AgentResponse:
        client = self._find_client(target, clients)
        if client is None:
            return AgentResponse(
                category="device",
                target=target,
                matched=False,
                title="Managed device not found",
                summary=f'EasyPi could not find a managed device matching "{target}".',
                confidence="low",
                section="guard-security",
                subsection="devices",
                module=self.name,
                recommendations=[
                    "Check the exact device name or IP address in Guard Security.",
                    "Run a LAN scan if the device has never been added to EasyPi.",
                ],
            )

        client_name = str(client.get("name") or client.get("ip") or target).strip()
        client_ip = self._first_client_ip(client)
        activity = {}
        if client_ip:
            activity_map = await self.adapter.get_client_activity([client_ip])
            activity = activity_map.get(client_ip, {}) if isinstance(activity_map, dict) else {}

        bypass_events = self.adapter.get_bypass_events()
        fail_closed_triggers = self.adapter.get_fail_closed_triggers()
        fail_closed_clients = await self.adapter.list_fail_closed_clients()

        bypass_event = bypass_events.get(client_ip, {}) if isinstance(bypass_events, dict) else {}
        fail_closed_trigger = (
            fail_closed_triggers.get(client_ip, {}) if isinstance(fail_closed_triggers, dict) else {}
        )
        dns_last_seen = self._coalesce_timestamp(client.get("dns_last_seen"), activity.get("lastSeen"))
        dns_state = self._get_dns_state(dns_last_seen)
        fail_closed_active = bool(client_ip and client_ip in fail_closed_clients) or bool(client.get("fail_closed"))
        blocked_services = client.get("blocked_services") or []
        profile_name = client.get("profile_name") or client.get("profile_id")

        facts = [
            AgentFact("Device", client_name),
            AgentFact("IP", client_ip or "Unknown"),
            AgentFact("Parental control", self._yes_no(bool(client.get("parental_enabled", False)))),
            AgentFact("DNS status", dns_state["label"], dns_state["severity"]),
            AgentFact("Blocked services", str(len(blocked_services))),
        ]
        if profile_name:
            facts.append(AgentFact("Profile", str(profile_name)))
        if activity:
            facts.append(AgentFact("DNS requests", str(activity.get("requestsCount", 0))))
            facts.append(AgentFact("Blocked queries", str(activity.get("blockedCount", 0))))

        trigger_domain = fail_closed_trigger.get("domain") or bypass_event.get("domain")
        trigger_time = fail_closed_trigger.get("triggered_at") or bypass_event.get("triggered_at")
        trigger_groups = fail_closed_trigger.get("groups") or bypass_event.get("groups") or []

        if fail_closed_active:
            if trigger_domain:
                facts.append(AgentFact("Trigger domain", str(trigger_domain), "critical"))
            if trigger_groups:
                facts.append(AgentFact("Trigger category", ", ".join(str(item) for item in trigger_groups)))
            if trigger_time:
                facts.append(AgentFact("Trigger time", str(trigger_time)))
            return AgentResponse(
                category="device",
                target=client_name,
                matched=True,
                title=f"Internet is blocked for {client_name}",
                summary=(
                    f"{client_name} is currently in fail-closed quarantine. "
                    f"EasyPi blocked internet access after a detected bypass attempt."
                ),
                confidence="high",
                section="guard-security",
                subsection="parental-controls",
                module=self.name,
                checks_run=["managed_clients", "client_activity", "bypass_events", "fail_closed_state"],
                facts=facts,
                reason_chain=[
                    "A bypass attempt was detected for the device.",
                    "Fail-closed quarantine is currently active.",
                    "Internet access was blocked to protect the policy.",
                ],
                recommendations=[
                    "Check the device for manual DNS, VPN, proxy, or private relay settings.",
                    "Use Restore Internet only after the device is back on EasyPi DNS.",
                ],
            )

        if bypass_event:
            if trigger_domain:
                facts.append(AgentFact("Recent bypass domain", str(trigger_domain), "warning"))
            if trigger_groups:
                facts.append(AgentFact("Recent bypass category", ", ".join(str(item) for item in trigger_groups)))
            if trigger_time:
                facts.append(AgentFact("Recent bypass time", str(trigger_time)))
            return AgentResponse(
                category="device",
                target=client_name,
                matched=True,
                title=f"Bypass activity detected for {client_name}",
                summary=(
                    f"EasyPi detected recent bypass activity from {client_name}, "
                    f"but the device is not currently quarantined."
                ),
                confidence="high",
                section="guard-security",
                subsection="parental-controls",
                module=self.name,
                checks_run=["managed_clients", "client_activity", "bypass_events"],
                facts=facts,
                reason_chain=[
                    "A bypass-related endpoint was contacted by the device.",
                    "The device remains managed by EasyPi.",
                    "No active quarantine is currently applied.",
                ],
                recommendations=[
                    "Review the device DNS and VPN settings.",
                    "Keep bypass protection enabled for this device profile.",
                ],
            )

        if dns_state["code"] == "not_seen":
            return AgentResponse(
                category="device",
                target=client_name,
                matched=True,
                title=f"No DNS activity seen for {client_name}",
                summary=(
                    f"EasyPi has not seen DNS traffic from {client_name} yet. "
                    f"The device may be offline or not using EasyPi DNS."
                ),
                confidence="medium",
                section="guard-security",
                subsection="devices",
                module=self.name,
                checks_run=["managed_clients", "client_activity"],
                facts=facts,
                reason_chain=[
                    "The device exists in the managed client list.",
                    "EasyPi has not recorded DNS activity for it.",
                ],
                recommendations=[
                    "Verify the device is online and using EasyPi as its DNS server or gateway.",
                    "Open the device network settings and check for manual DNS overrides.",
                ],
            )

        if dns_state["code"] == "stale":
            return AgentResponse(
                category="device",
                target=client_name,
                matched=True,
                title=f"DNS activity is stale for {client_name}",
                summary=(
                    f"{client_name} is a managed device, but its recent DNS activity is stale. "
                    f"It may be offline or bypassing EasyPi DNS."
                ),
                confidence="high",
                section="guard-security",
                subsection="devices",
                module=self.name,
                checks_run=["managed_clients", "client_activity"],
                facts=facts,
                reason_chain=[
                    "The device was seen before by EasyPi DNS.",
                    "Recent DNS activity is older than the healthy threshold.",
                ],
                recommendations=[
                    "Check whether the device is still connected to the network.",
                    "Review manual DNS, VPN, encrypted DNS, or private relay settings on the device.",
                ],
            )

        return AgentResponse(
            category="device",
            target=client_name,
            matched=True,
            title=f"No local policy block found for {client_name}",
            summary=(
                f"EasyPi did not find a local NetProtection block or quarantine affecting {client_name}. "
                f"DNS activity looks healthy."
            ),
            confidence="medium",
            section="guard-security",
            subsection="devices",
            module=self.name,
            checks_run=["managed_clients", "client_activity", "bypass_events", "fail_closed_state"],
            facts=facts,
            reason_chain=[
                "The device is managed by EasyPi.",
                "DNS activity is currently healthy.",
                "No active bypass or quarantine state was found.",
            ],
            recommendations=[
                "If internet access still fails, check Wi-Fi connectivity, upstream internet, and gateway health.",
                "Review service status for NetProtection and Remote Access if the issue is network-wide.",
            ],
        )

    async def _diagnose_domain(self, target: str) -> AgentResponse:
        domain = self._normalize_domain(target)
        if not domain:
            return AgentResponse(
                category="domain",
                target=target,
                matched=False,
                title="Invalid domain",
                summary="EasyPi could not identify a valid domain to inspect.",
                confidence="low",
                section="guard-security",
                subsection="query-log",
                module=self.name,
                recommendations=["Enter a full domain name such as example.com."],
            )

        entries = await self.adapter.get_verdicts(search=domain, limit=25)
        relevant_entries = [
            entry for entry in entries if self._domain_matches(str(entry.get("domain") or ""), domain)
        ]
        if not relevant_entries:
            return AgentResponse(
                category="domain",
                target=domain,
                matched=False,
                title=f"No recent local verdicts for {domain}",
                summary=f"EasyPi did not find recent DNS verdicts for {domain} in the local query log.",
                confidence="medium",
                section="guard-security",
                subsection="query-log",
                module=self.name,
                checks_run=["query_log"],
                facts=[AgentFact("Domain", domain)],
                recommendations=[
                    "Open Query Log and repeat the lookup from a managed device.",
                    "If you expected a block, review the active rules and lists.",
                ],
            )

        latest = relevant_entries[0]
        latest_status = str(latest.get("status") or "").strip().lower()
        latest_verdict = str(latest.get("verdict") or "").strip().lower()
        client_name = latest.get("client_name") or latest.get("client_ip") or "Unknown device"
        blocked_count = sum(1 for entry in relevant_entries if self._is_blocked_entry(entry))
        allowed_count = sum(1 for entry in relevant_entries if not self._is_blocked_entry(entry))
        evidence_summary = str(latest.get("evidence_summary") or "").strip()
        facts = [
            AgentFact("Domain", domain),
            AgentFact("Latest action", self._render_domain_action(latest_status, latest_verdict)),
            AgentFact("Latest device", str(client_name)),
            AgentFact("Latest time", str(latest.get("time") or "Unknown")),
            AgentFact("Recent blocked verdicts", str(blocked_count)),
            AgentFact("Recent allowed verdicts", str(allowed_count)),
        ]
        if evidence_summary:
            facts.append(AgentFact("Evidence", evidence_summary))

        if self._is_blocked_entry(latest):
            return AgentResponse(
                category="domain",
                target=domain,
                matched=True,
                title=f"{domain} is currently blocked",
                summary=(
                    f"EasyPi blocked recent requests for {domain}. "
                    f"The latest local verdict was issued for {client_name}."
                ),
                confidence="high",
                section="guard-security",
                subsection="query-log",
                module=self.name,
                checks_run=["query_log"],
                facts=facts,
                reason_chain=[
                    "The domain appears in the local query log.",
                    "The latest verdict is blocked or denied.",
                ],
                recommendations=[
                    f"If {domain} should not be blocked, add it to the allowlist to unblock it immediately.",
                    "Open Query Log to see which list or rule blocked it and the device profile involved.",
                ],
            )

        return AgentResponse(
            category="domain",
            target=domain,
            matched=True,
            title=f"{domain} is not currently blocked",
            summary=f"EasyPi has seen {domain}, but the latest local verdict was allowed.",
            confidence="high",
            section="guard-security",
            subsection="query-log",
            module=self.name,
            checks_run=["query_log"],
            facts=facts,
            reason_chain=[
                "The domain appears in the local query log.",
                "The latest verdict is allowed.",
            ],
            recommendations=[
                "If you expected a block, review the matching rule scope and recent device profile changes.",
                "Repeat the lookup from the affected managed device and compare the next verdict.",
            ],
        )

    def _resolve_intent(
        self,
        request: AgentRequest,
        clients: list[dict[str, object]],
    ) -> tuple[str, str]:
        explicit_target = str(request.target or "").strip()

        if request.target_type in {"device", "domain"} and explicit_target:
            return request.target_type, explicit_target

        domain = self._extract_domain(explicit_target or request.question)
        if domain:
            return "domain", domain

        ipv4 = self._extract_ipv4(explicit_target or request.question)
        if ipv4:
            return "device", ipv4

        client = self._match_client_by_question(request.question, clients)
        if client is not None:
            return "device", str(client.get("name") or self._first_client_ip(client)).strip()

        return "unknown", explicit_target or request.question

    def _normalize_tab(self, value: str | None) -> str | None:
        normalized = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
        return self._TAB_ALIASES.get(normalized)

    async def _gather_status_payloads(self) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        status = await self.adapter.get_status()
        stats = await self.adapter.get_stats()
        dashboard_stats = await self.adapter.get_dashboard_stats()
        query_log_stats = await self.adapter.get_query_log_stats()
        return status, stats, dashboard_stats, query_log_stats

    async def _gather_policy_payloads(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[str], list[dict[str, object]]]:
        whitelist = await self.adapter.get_whitelist()
        blacklist = await self.adapter.get_blacklist()
        rewrites = await self.adapter.get_rewrites()
        profiles = await self.adapter.get_shield_profiles()
        rules = await self.adapter.get_user_rules()
        matchers = await self.adapter.get_matchers()
        return whitelist, blacklist, rewrites, profiles, rules, matchers

    def _find_client(self, target: str, clients: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(target or "").strip().lower()
        if not normalized:
            return None

        for client in clients:
            if normalized == str(client.get("name") or "").strip().lower():
                return client
            if normalized == self._first_client_ip(client).lower():
                return client

        return None

    def _match_client_by_question(
        self,
        question: str,
        clients: list[dict[str, object]],
    ) -> dict[str, object] | None:
        lowered = question.lower()
        best_match = None
        best_length = 0

        for client in clients:
            name = str(client.get("name") or "").strip().lower()
            if len(name) < 3:
                continue
            if name in lowered and len(name) > best_length:
                best_match = client
                best_length = len(name)

        return best_match

    def _extract_domain(self, value: str) -> str | None:
        match = self._DOMAIN_RE.search(str(value or ""))
        if not match:
            return None
        return self._normalize_domain(match.group(0))

    def _extract_ipv4(self, value: str) -> str | None:
        match = self._IPV4_RE.search(str(value or ""))
        if not match:
            return None
        candidate = match.group(0)
        try:
            ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            return None
        return candidate

    def _normalize_domain(self, domain: str) -> str | None:
        value = str(domain or "").strip().lower().rstrip(".")
        if not value:
            return None
        if not self._DOMAIN_RE.fullmatch(value):
            return None
        return value

    def _domain_matches(self, candidate: str, expected: str) -> bool:
        left = self._normalize_domain(candidate)
        right = self._normalize_domain(expected)
        if not left or not right:
            return False
        return left == right or left.endswith("." + right) or right.endswith("." + left)

    def _coalesce_timestamp(self, *values: object) -> datetime | None:
        for value in values:
            parsed = self._parse_timestamp(value)
            if parsed is not None:
                return parsed
        return None

    def _parse_timestamp(self, value: object) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _get_dns_state(self, last_seen: datetime | None) -> dict[str, str]:
        if last_seen is None:
            return {"code": "not_seen", "label": "DNS not seen", "severity": "warning"}

        age_seconds = max(0, int((self.now_provider() - last_seen).total_seconds()))
        if age_seconds < self._DNS_STALE_THRESHOLD_SECONDS:
            return {
                "code": "active",
                "label": f"DNS active ({self._format_duration(age_seconds)} ago)",
                "severity": "info",
            }
        return {
            "code": "stale",
            "label": f"DNS stale ({self._format_duration(age_seconds)} ago)",
            "severity": "warning",
        }

    def _is_blocked_entry(self, entry: dict[str, object]) -> bool:
        status = str(entry.get("status") or "").strip().lower()
        verdict = str(entry.get("verdict") or "").strip().lower()
        return status == "blocked" or verdict == "deny"

    def _render_domain_action(self, status: str, verdict: str) -> str:
        if status == "blocked" or verdict == "deny":
            return "Blocked"
        if status == "redirected" or verdict == "redirect":
            return "Redirected"
        if verdict == "observe":
            return "Observed"
        return "Allowed"

    def _first_client_ip(self, client: dict[str, object]) -> str:
        ip_value = str(client.get("ip") or "").strip()
        if ip_value:
            return ip_value

        ids = client.get("ids") or []
        if isinstance(ids, list):
            for value in ids:
                candidate = str(value or "").strip()
                if candidate:
                    return candidate
        return ""

    def _format_duration(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h"
        return f"{hours // 24}d"

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
