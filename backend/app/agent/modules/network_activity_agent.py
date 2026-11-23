"""Network activity agent module."""

from __future__ import annotations

import ipaddress

from app.agent.adapters.network_activity import NetworkActivityAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class NetworkActivityAgent:
    """Explain network activity, devices, and live query state."""

    name = "network_activity_agent"
    _KEYWORDS = (
        "network activity",
        "query",
        "queries",
        "blocked domain",
        "blocked queries",
        "device traffic",
        "top domain",
        "top talker",
        "top device",
        "graph",
        "empty graph",
        "spike",
        "visible",
    )
    _ROUTES = ("network-activity",)

    def __init__(self, adapter: NetworkActivityAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 100
        if any(token in route for token in self._ROUTES):
            score += 40
        if self._extract_ip(request.target or request.question):
            score += 30
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        tab = str(request.tab or "").strip().lower()
        question = " ".join(part for part in (request.question.lower(), tab) if part)
        route = (request.route or "").lower()
        target = str(request.target or "").strip()
        if not any(keyword in question or keyword in target.lower() for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        status = await self.adapter.get_status()
        stats = await self.adapter.get_stats()
        devices = await self.adapter.get_devices()
        queries = await self.adapter.get_live_queries(limit=20)
        device = self._find_device(target or request.question, devices)
        requested_ip = self._extract_ip(target or request.question)

        if device is not None:
            return await self._device_response(device, queries, question)
        if target or requested_ip:
            if not devices and int(stats.get("activeDevices") or 0) > 0:
                return AgentResponse(
                    category="device", target=target or requested_ip or "Unknown device", matched=True,
                    title="Network activity lookup unavailable",
                    summary="The device lookup source is unavailable, so absence from the current result cannot be confirmed.",
                    confidence="low", section="network-activity", subsection="devices", module=self.name,
                    checks_run=["network_devices", "live_queries"],
                    facts=[AgentFact("Active device aggregate", str(stats.get("activeDevices")), "warning")],
                    recommendations=["Refresh the device inventory before concluding that the device is absent."],
                )
            return self._missing_device_response(target or requested_ip or "Unknown device", stats, queries)

        block_rate = float(stats.get("blockRate") or 0)
        top_device = str(stats.get("topDevice") or "N/A")
        top_domain = str(stats.get("topDomain") or "N/A")
        top_live_domain = self._top_domain_from_queries(queries)
        top_blocked_domain = self._top_domain_from_queries(queries, blocked_only=True)
        facts = [
            AgentFact("Protection running", self._yes_no(bool(status.get("running")))),
            AgentFact("Active devices", str(stats.get("activeDevices") or 0)),
            AgentFact("Total queries", str(stats.get("totalQueries") or 0)),
            AgentFact("Blocked queries", str(stats.get("blockedQueries") or 0)),
            AgentFact("Block rate", f"{block_rate:.2f}%"),
            AgentFact("Live queries", str(len(queries))),
            AgentFact("Top device", top_device),
            AgentFact("Top domain", top_domain if top_domain != "N/A" else str(top_live_domain or "N/A")),
        ]
        if top_blocked_domain:
            facts.append(AgentFact("Top blocked domain", top_blocked_domain))
        if not bool(status.get("running")):
            summary = "Network Activity protection/status is stopped, so recent traffic conclusions are incomplete."
            confidence = "high"
            reason_chain = ["The network status source reports protection is not running."]
        elif any(token in question for token in ("top talker", "top device")) and top_device != "N/A":
            summary = f"The current top talker in Network Activity is {top_device}."
            confidence = "high"
            reason_chain = [
                "Overall network statistics were inspected.",
                "The current activity snapshot exposes a top device for recent query volume.",
            ]
        elif "top domain" in question and (top_domain != "N/A" or top_live_domain):
            resolved_top_domain = top_domain if top_domain != "N/A" else str(top_live_domain)
            summary = f"The current top queried domain is {resolved_top_domain}."
            confidence = "high"
            reason_chain = [
                "Overall network statistics and recent live queries were inspected.",
                "A dominant queried domain is visible in the current local snapshot.",
            ]
        elif ("graph" in question or "empty" in question) and not queries and int(stats.get("totalQueries") or 0) > 0:
            summary = "The live Network Activity graph is empty because no recent queries are in the current short live window, even though aggregate query counters already exist."
            confidence = "high"
            reason_chain = [
                "Overall network counters show stored DNS activity.",
                "The recent live-query window returned no fresh entries right now.",
            ]
        elif ("blocked" in question or "spike" in question) and block_rate >= 40:
            summary = (
                f"Network Activity shows a blocked-query spike, currently led by {top_blocked_domain}."
                if top_blocked_domain
                else "Network Activity shows a high blocked-query spike."
            )
            confidence = "high"
            reason_chain = [
                "Overall network statistics were inspected.",
                "The current block rate is significantly elevated.",
                "Recent live queries were checked for dominant blocked domains.",
            ]
        elif not queries:
            summary = "No recent live DNS queries are visible right now — either the network is quiet, or your devices are not using EasyPi as their DNS server."
            confidence = "medium"
            reason_chain = [
                "The network activity module queried recent local verdicts.",
                "No recent queries were returned for the live stream.",
            ]
        elif block_rate >= 40:
            summary = "Network activity shows a high blocked-query rate — EasyPi is stopping a lot of ads/trackers/threats (usually good), unless a single device looks compromised."
            confidence = "high"
            reason_chain = [
                "Overall network statistics were inspected.",
                "The current block rate is significantly elevated.",
            ]
        else:
            summary = "Network activity looks normal based on recent local query data."
            confidence = "medium"
            reason_chain = [
                "Overall network statistics and live queries were inspected.",
            ]

        return AgentResponse(
            category="service",
            target="network-activity",
            matched=True,
            title="Network activity diagnostics",
            summary=summary,
            confidence=confidence,
            section="network-activity",
            subsection="query-log" if tab in {"query-log", "verdicts"} else "devices" if tab == "devices" else "overview",
            module=self.name,
            checks_run=["network_status", "network_stats", "live_queries"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open Query Log to see exactly which domains are being queried and blocked.",
                "Ask about a specific device (by name or IP) for a per-device breakdown of its traffic.",
            ],
        )

    async def _device_response(self, device: dict[str, object], queries: list[dict[str, object]], question: str) -> AgentResponse:
        ip_address = str(device.get("ip") or "Unknown")
        requests = int(device.get("requestsCount") or 0)
        blocked = int(device.get("blockedCount") or 0)
        visible_queries = [query for query in queries if str(query.get("device")) == ip_address]
        details = await self._get_device_traffic(ip_address)
        top_domains = details.get("topDomains") or []
        top_blocked_domains = details.get("topBlockedDomains") or []
        facts = [
            AgentFact("Device", str(device.get("name") or ip_address)),
            AgentFact("IP", ip_address),
            AgentFact("Status", str(device.get("status") or "unknown")),
            AgentFact("Requests", str(requests)),
            AgentFact("Blocked queries", str(blocked)),
            AgentFact("Last seen", str(device.get("lastSeen") or "Unknown")),
        ]
        if top_domains:
            facts.append(AgentFact("Top domain", str(top_domains[0].get("domain") or "Unknown")))
        if top_blocked_domains:
            facts.append(AgentFact("Top blocked domain", str(top_blocked_domains[0].get("domain") or "Unknown")))
        if requests == 0:
            summary = f"EasyPi currently sees no recent query activity for {device.get('name') or ip_address}."
            reason_chain = [
                "The device was found in the activity inventory.",
                "Its request counter is currently zero.",
            ]
            recommendations = [
                "Check whether the device is online and still using EasyPi DNS.",
            ]
            confidence = "high"
        elif ("blocked" in question or "top domain" in question or "traffic" in question) and top_blocked_domains:
            summary = (
                f"{device.get('name') or ip_address} is visible in Network Activity, and its top blocked domain is "
                f"{top_blocked_domains[0].get('domain') or 'Unknown'}."
            )
            reason_chain = [
                "The device was found in the activity inventory.",
                "Per-device traffic details were loaded from local verdict history.",
                "Blocked domain counters identify the dominant blocked destination for this device.",
            ]
            recommendations = [
                "Open Query Log or the device details panel if you need the exact blocked timestamps.",
            ]
            confidence = "high"
        elif ("top" in question or "domain" in question or "traffic" in question) and top_domains:
            summary = (
                f"{device.get('name') or ip_address} is visible in Network Activity, and its busiest domain is "
                f"{top_domains[0].get('domain') or 'Unknown'}."
            )
            reason_chain = [
                "The device was found in the activity inventory.",
                "Per-device traffic details were loaded from local verdict history.",
                "Top-domain counters identify the dominant destination for this device.",
            ]
            recommendations = [
                "Open Query Log if you need the exact recent queries behind this domain ranking.",
            ]
            confidence = "high"
        else:
            summary = f"EasyPi is currently tracking DNS activity for {device.get('name') or ip_address}."
            reason_chain = [
                "The device was found in the activity inventory.",
                "Recent request counters show active DNS usage through EasyPi.",
            ]
            recommendations = [
                "If traffic still looks wrong, inspect the device details or query log for that device.",
            ]
            confidence = "medium"
        if visible_queries:
            facts.append(AgentFact("Recent live queries", str(len(visible_queries))))
        return AgentResponse(
            category="device",
            target=str(device.get("name") or ip_address),
            matched=True,
            title=f"Network activity for {device.get('name') or ip_address}",
            summary=summary,
            confidence=confidence,
            section="network-activity",
            subsection="devices",
            module=self.name,
            checks_run=["network_devices", "live_queries"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _missing_device_response(self, target: str, stats: dict[str, object], queries: list[dict[str, object]]) -> AgentResponse:
        return AgentResponse(
            category="device",
            target=target,
            matched=True,
            title="Network activity device lookup",
            summary=f"EasyPi did not find a currently tracked device matching '{target}' in Network Activity.",
            confidence="high",
            section="network-activity",
            subsection="devices",
            module=self.name,
            checks_run=["network_devices", "live_queries"],
            facts=[
                AgentFact("Requested device", target),
                AgentFact("Active devices", str(stats.get("activeDevices") or 0)),
                AgentFact("Live queries", str(len(queries))),
            ],
            reason_chain=[
                "The local Network Activity device inventory was queried.",
                "No tracked device currently matches the requested name or IP.",
            ],
            recommendations=[
                "Check the exact device name or IP shown in Network Activity.",
                "If the device should be visible, verify that it still uses EasyPi DNS.",
            ],
        )

    def _find_device(self, value: str, devices: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        ip_hint = self._extract_ip(value)
        for device in devices:
            name = str(device.get("name") or "").strip().lower()
            ip_address = str(device.get("ip") or "").strip().lower()
            if normalized in {name, ip_address}:
                return device
            if ip_hint and ip_address == ip_hint:
                return device
            if name and name in normalized:
                return device
        return None

    def _extract_ip(self, value: str) -> str | None:
        for token in str(value or "").replace(",", " ").split():
            try:
                return str(ipaddress.ip_address(token))
            except ValueError:
                continue
        return None

    def _top_domain_from_queries(self, queries: list[dict[str, object]], *, blocked_only: bool = False) -> str | None:
        counts: dict[str, int] = {}
        for query in queries:
            if blocked_only and str(query.get("status") or "").lower() != "blocked":
                continue
            domain = str(query.get("domain") or "").strip()
            if not domain:
                continue
            counts[domain] = counts.get(domain, 0) + 1
        if not counts:
            return None
        return max(counts.items(), key=lambda item: item[1])[0]

    async def _get_device_traffic(self, device_ip: str) -> dict[str, object]:
        method = getattr(self.adapter, "get_device_traffic", None)
        if not callable(method):
            return {}
        result = await method(device_ip, limit=50)
        return result if isinstance(result, dict) else {}

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
