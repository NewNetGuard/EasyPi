"""Network toolkit agent module."""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network

from app.agent.adapters.network_toolkit import NetworkToolkitAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class NetworkToolkitAgent:
    """Explain network toolkit state and gateway diagnostics."""

    name = "network_toolkit_agent"
    _KEYWORDS = (
        "toolkit",
        "lan scan",
        "port scan",
        "speed test",
        "connection",
        "connections",
        "arp",
        "gateway mode",
        "slow internet",
        "traffic",
        "port alert",
        "host not found",
        "router exclusion",
        "throughput",
    )
    _ROUTES = ("toolkit",)

    def __init__(self, adapter: NetworkToolkitAdapter) -> None:
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
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        tab = (request.tab or "").strip().lower()
        if tab == "lan-scanner":
            return await self._lan_scan_response(question, target)
        if tab == "port-scanner":
            return await self._port_scanner_response()
        if tab == "speed-test":
            return await self._speed_test_response()
        if tab == "traffic-graph":
            return await self._traffic_samples_response()
        if tab == "active-connections":
            return await self._connections_response()
        if tab == "arp-scanner":
            return await self._arp_response()
        if tab == "open-ports-alert":
            return await self._port_alert_response(question, target)

        if any(token in question for token in ("lan scan", "host", "discover", "router exclusion", "new device")):
            return await self._lan_scan_response(question, target)
        if "gateway" in question or "gateway" in target:
            return await self._gateway_response()
        if any(token in question for token in ("speed test", "slow internet", "internet slow", "ping", "jitter")):
            return await self._speed_test_response()
        if any(token in question for token in ("traffic graph", "throughput", "dropped", "spike")):
            return await self._traffic_samples_response()
        if any(token in question for token in ("speed", "slow", "traffic")):
            return await self._traffic_response()
        if "port alert" in question or "port scan" in question or "port" in target:
            return await self._port_alert_response(question, target)
        if "connection" in question or "process" in question:
            return await self._connections_response()
        if "arp" in question:
            return await self._arp_response()
        return await self._overview_response()

    async def _port_scanner_response(self) -> AgentResponse:
        connections = await self.adapter.get_connections()
        listening = [connection for connection in connections if str(connection.get("state")) == "LISTENING"]
        exposed = [
            connection
            for connection in listening
            if str(connection.get("localAddress") or "").startswith(("0.0.0.0:", "[::]:", ":::"))
        ]
        facts = [
            AgentFact("Listening sockets", str(len(listening))),
            AgentFact("All-interface listeners", str(len(exposed)), "warning" if exposed else "info"),
        ]
        if exposed:
            first = exposed[0]
            facts.append(
                AgentFact(
                    "Example listener",
                    str(first.get("localAddress") or first.get("local_address") or "Unknown"),
                    "warning",
                )
            )
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Port scanner diagnostics",
            summary=(
                "The Port Scanner is selected; current socket data includes services listening on all interfaces."
                if exposed
                else "The Port Scanner is selected; no all-interface listeners were found in current socket data."
            ),
            confidence="medium",
            section="network-toolkit",
            subsection="port-scanner",
            module=self.name,
            checks_run=["active_connections"],
            facts=facts,
            reason_chain=[
                "The agent used the selected Network Toolkit subsection from the page context.",
                "It inspected current local listening sockets without starting a new port scan.",
            ],
            recommendations=[
                "Run the scanner for a specific target to obtain host-specific open, closed, and filtered port results.",
            ],
        )

    async def _lan_scan_response(self, question: str, target: str) -> AgentResponse:
        payload = await self.adapter.get_cached_devices()
        devices = payload.get("devices") or []
        gateway_ip = str(payload.get("gateway_ip") or "Unknown")
        router_count = sum(1 for device in devices if bool(device.get("is_router")))
        query = self._extract_host_query(question, target)
        matched = self._find_cached_device(query, devices)
        facts = [
            AgentFact("Cached devices", str(len(devices))),
            AgentFact("Router candidates", str(router_count), "warning" if router_count else "info"),
            AgentFact("Gateway IP", gateway_ip),
        ]
        if payload.get("last_scan_time"):
            facts.append(AgentFact("Last LAN scan", str(payload.get("last_scan_time"))))
        if matched is not None:
            facts.append(AgentFact("Matched host", str(matched.get("hostname") or matched.get("ip") or "Unknown")))
            facts.append(AgentFact("Matched IP", str(matched.get("ip") or "Unknown")))
            if matched.get("vendor"):
                facts.append(AgentFact("Vendor", str(matched.get("vendor"))))
            if matched.get("device_type"):
                facts.append(AgentFact("Device type", str(matched.get("device_type"))))

        if not devices:
            summary = "No cached LAN scan is available yet, so the toolkit cannot explain host discovery from local facts."
            confidence = "medium"
            reason_chain = [
                "The toolkit checked the cached LAN scan device list.",
                "No cached LAN scan results are currently stored.",
            ]
        elif matched is None and query:
            summary = f"The last cached LAN scan does not include '{query}'."
            confidence = "high"
            reason_chain = [
                "The toolkit checked the cached LAN scan device list.",
                f"No cached device matched '{query}'.",
            ]
        elif "router exclusion" in question and router_count:
            summary = "Router auto-detection is active in the cached LAN scan results."
            confidence = "high"
            reason_chain = [
                "The toolkit checked the cached LAN scan device list.",
                "At least one cached device matches the current gateway IP and is marked as the router.",
            ]
        elif matched is not None:
            if bool(matched.get("is_router")):
                summary = "The requested host matches the current gateway and is treated as the router in LAN scan results."
            else:
                summary = "The requested host exists in the latest cached LAN scan results."
            confidence = "high"
            reason_chain = [
                "The toolkit checked the cached LAN scan device list.",
                "A cached device match was found for the requested host.",
            ]
        else:
            summary = "The latest cached LAN scan contains discovered devices and router detection data."
            confidence = "medium"
            reason_chain = [
                "The toolkit checked the cached LAN scan device list.",
                "Cached LAN scan results are available for device discovery reasoning.",
            ]

        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="LAN scan diagnostics",
            summary=summary,
            confidence=confidence,
            section="network-toolkit",
            subsection="lan-scan",
            module=self.name,
            checks_run=["cached_devices"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Run a fresh LAN scan if the cached inventory is stale or the expected host is missing.",
                "Use router auto-detection to avoid treating the gateway as a normal client device.",
            ],
        )

    async def _gateway_response(self) -> AgentResponse:
        status = await self.adapter.get_gateway_mode_status()
        enabled = bool(status.get("enabled"))
        facts = [
            AgentFact("Enabled", self._yes_no(enabled), "info" if enabled else "warning"),
            AgentFact("Interface", str(status.get("interface") or "Unknown")),
            AgentFact("Current IP", str(status.get("current_ip") or "Unknown")),
            AgentFact("Current gateway", str(status.get("current_gateway") or "Unknown")),
            AgentFact("IP forward", self._yes_no(bool(status.get("ip_forward")))),
            AgentFact("NAT enabled", self._yes_no(bool(status.get("nat_enabled")))),
        ]
        if enabled and (not bool(status.get("ip_forward")) or not bool(status.get("nat_enabled"))):
            summary = "Gateway mode is incomplete/degraded: its flag is on, but IP forwarding or NAT is not active."
        else:
            summary = "Gateway mode is enabled." if enabled else "Gateway mode is currently disabled or incomplete."
        return AgentResponse(
            category="service",
            target="gateway-mode",
            matched=True,
            title="Gateway mode diagnostics",
            summary=summary,
            confidence="high",
            section="network-toolkit",
            subsection="gateway-mode",
            module=self.name,
            checks_run=["gateway_mode_status"],
            facts=facts,
            reason_chain=[
                "The local gateway mode status was queried.",
                "IP forwarding, NAT, and interface state were inspected.",
            ],
            recommendations=[
                "If gateway mode should be active, inspect NAT, forwarding, and static IP configuration.",
            ],
        )

    async def _speed_test_response(self) -> AgentResponse:
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Speed test diagnostics",
            summary="No cached speed-test result is available; diagnostics did not start a bandwidth-consuming test without explicit consent.",
            confidence="low",
            section="network-toolkit",
            subsection="speed-test",
            module=self.name,
            checks_run=["speed_test_capability"],
            facts=[AgentFact("Active speed test", "Not run", "warning")],
            reason_chain=[
                "A speed test creates network load and is not a read-only observation.",
                "The explain endpoint therefore did not start one automatically.",
            ],
            recommendations=[
                "Run the explicit Speed Test control if you consent to active bandwidth measurement.",
            ],
        )

    async def _traffic_samples_response(self) -> AgentResponse:
        samples = await self.adapter.get_traffic_samples(duration=30)
        if not samples:
            return AgentResponse(
                category="service",
                target="network-toolkit",
                matched=True,
                title="Traffic graph diagnostics",
                summary="No traffic samples were returned for the current graph window.",
                confidence="low",
                section="network-toolkit",
                subsection="traffic-graph",
                module=self.name,
                checks_run=["traffic_samples"],
                facts=[],
                reason_chain=[
                    "The toolkit tried to collect live traffic samples.",
                    "No sample points were returned for the requested window.",
                ],
                recommendations=[
                    "Retry the traffic graph while the interface is actively carrying traffic.",
                ],
            )

        downloads = [float(sample.get("download") or 0) for sample in samples]
        uploads = [float(sample.get("upload") or 0) for sample in samples]
        current_download = downloads[-1]
        current_upload = uploads[-1]
        average_download = sum(downloads) / len(downloads)
        average_upload = sum(uploads) / len(uploads)
        peak_download = max(downloads)
        peak_upload = max(uploads)
        summary = "Live traffic samples were collected successfully."
        if current_download < average_download * 0.5 and peak_download > 0:
            summary = "Live traffic samples show a recent drop in download throughput."
        elif current_upload < average_upload * 0.5 and peak_upload > 0:
            summary = "Live traffic samples show a recent drop in upload throughput."

        facts = [
            AgentFact("Traffic samples", str(len(samples))),
            AgentFact("Current download", f"{current_download:.2f} KB/s"),
            AgentFact("Current upload", f"{current_upload:.2f} KB/s"),
            AgentFact("Average download", f"{average_download:.2f} KB/s"),
            AgentFact("Average upload", f"{average_upload:.2f} KB/s"),
            AgentFact("Peak download", f"{peak_download:.2f} KB/s"),
            AgentFact("Peak upload", f"{peak_upload:.2f} KB/s"),
        ]
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Traffic graph diagnostics",
            summary=summary,
            confidence="medium",
            section="network-toolkit",
            subsection="traffic-graph",
            module=self.name,
            checks_run=["traffic_samples"],
            facts=facts,
            reason_chain=[
                "The toolkit collected live traffic samples for the current window.",
                "Current, average, and peak transfer rates were compared.",
            ],
            recommendations=[
                "Correlate traffic drops with speed test, gateway mode, or service restart events if the slowdown repeats.",
            ],
        )

    async def _traffic_response(self) -> AgentResponse:
        info = await self.adapter.get_network_info()
        traffic = await self.adapter.get_traffic_stats()
        facts = [
            AgentFact("Local IP", str(info.get("localIp") or "Unknown")),
            AgentFact("Gateway", str(info.get("gateway") or "Unknown")),
            AgentFact("Current download", f"{float(traffic.get('currentDownload') or 0):.2f} KB/s"),
            AgentFact("Current upload", f"{float(traffic.get('currentUpload') or 0):.2f} KB/s"),
            AgentFact("Peak download", f"{float(traffic.get('peakDownload') or 0):.2f} KB/s"),
            AgentFact("Peak upload", f"{float(traffic.get('peakUpload') or 0):.2f} KB/s"),
        ]
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Traffic diagnostics",
            summary="Current traffic counters were collected successfully.",
            confidence="medium",
            section="network-toolkit",
            subsection="traffic",
            module=self.name,
            checks_run=["network_info", "traffic_stats"],
            facts=facts,
            reason_chain=[
                "The toolkit collected current interface and traffic counters.",
            ],
            recommendations=[
                "Run a speed test from the UI if you need end-to-end internet performance.",
            ],
        )

    async def _port_alert_response(self, question: str, target: str) -> AgentResponse:
        alerts = await self.adapter.get_port_alerts()
        high_risk = sum(1 for alert in alerts if str(alert.get("riskLevel")) in {"high", "critical"})
        requested_port = self._extract_port(question, target)
        requested_alert = None
        if requested_port is not None:
            requested_alert = next((alert for alert in alerts if int(alert.get("port") or 0) == requested_port), None)
        facts = [
            AgentFact("Open port alerts", str(len(alerts))),
            AgentFact("High-risk alerts", str(high_risk), "warning" if high_risk else "info"),
        ]
        if requested_alert is not None:
            facts.append(
                AgentFact(
                    "Requested port",
                    f"{requested_alert.get('port')} ({requested_alert.get('service') or 'unknown'})",
                    "warning" if str(requested_alert.get("riskLevel")) in {"high", "critical"} else "info",
                )
            )
        elif alerts:
            first = alerts[0]
            facts.append(AgentFact("Latest alert", f"Port {first.get('port')} {first.get('service') or 'unknown'}"))
        if requested_alert is not None:
            summary = (
                f"Port {requested_port} currently has an active toolkit alert."
                if str(requested_alert.get("riskLevel")) in {"high", "critical"}
                else f"Port {requested_port} is present in toolkit alerts but is not marked high risk."
            )
        else:
            summary = "Port alert status was collected successfully." if alerts else "No active port alerts were found."
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Port alert diagnostics",
            summary=summary,
            confidence="high",
            section="network-toolkit",
            subsection="port-alerts",
            module=self.name,
            checks_run=["port_alerts"],
            facts=facts,
            reason_chain=[
                "The toolkit inspected current port alerts.",
            ],
            recommendations=[
                "Review unexpected listening ports and disable services you do not need.",
            ],
        )

    async def _connections_response(self) -> AgentResponse:
        connections = await self.adapter.get_connections()
        listening = sum(1 for connection in connections if str(connection.get("state")) == "LISTENING")
        established = sum(1 for connection in connections if str(connection.get("state")) == "ESTABLISHED")
        internet_facing = sum(
            1
            for connection in connections
            if self._looks_internet_facing(str(connection.get("remoteAddress") or ""))
        )
        top_process = self._top_process(connections)
        facts = [
            AgentFact("Connections", str(len(connections))),
            AgentFact("Listening sockets", str(listening)),
            AgentFact("Established sockets", str(established)),
            AgentFact("Internet-facing connections", str(internet_facing), "warning" if internet_facing else "info"),
        ]
        if top_process:
            facts.append(AgentFact("Top process", top_process))
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Active connections diagnostics",
            summary=(
                "Active connection data shows internet-facing sockets."
                if internet_facing
                else "Active connection data was collected successfully."
            ),
            confidence="medium",
            section="network-toolkit",
            subsection="connections",
            module=self.name,
            checks_run=["active_connections"],
            facts=facts,
            reason_chain=[
                "The toolkit inspected active local network sockets.",
            ],
            recommendations=[
                "Filter by process or protocol in the UI if you need a narrower connection view.",
            ],
        )

    async def _arp_response(self) -> AgentResponse:
        entries = await self.adapter.get_arp_entries()
        new_entries = sum(1 for entry in entries if bool(entry.get("isNew")))
        facts = [
            AgentFact("ARP entries", str(len(entries))),
            AgentFact("New ARP entries", str(new_entries), "warning" if new_entries else "info"),
        ]
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="ARP diagnostics",
            summary=(
                "ARP table data includes newly observed entries."
                if new_entries
                else "ARP table data was collected successfully."
            )
            if entries
            else "No ARP entries were returned.",
            confidence="medium",
            section="network-toolkit",
            subsection="arp-scan",
            module=self.name,
            checks_run=["arp_scan"],
            facts=facts,
            reason_chain=[
                "The toolkit inspected the local ARP table.",
            ],
            recommendations=[
                "Run a LAN scan if you need a fuller network inventory than ARP alone provides.",
            ],
        )

    async def _overview_response(self) -> AgentResponse:
        info = await self.adapter.get_network_info()
        gateway = await self.adapter.get_gateway_mode_status()
        cached = await self.adapter.get_cached_devices()
        if not any((info, gateway, cached)):
            return AgentResponse(
                category="service", target="network-toolkit", matched=True,
                title="Network toolkit data unavailable",
                summary="Network Toolkit status is unavailable, so local IP, gateway, and scan state are unknown.",
                confidence="low", section="network-toolkit", subsection="overview", module=self.name,
                checks_run=["network_info", "gateway_mode_status", "cached_devices"],
                facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Restore the toolkit status APIs before running active diagnostics."],
            )
        facts = [
            AgentFact("Local IP", str(info.get("localIp") or "Unknown")),
            AgentFact("Gateway", str(info.get("gateway") or "Unknown")),
            AgentFact("Interface", str(info.get("interface") or "Unknown")),
            AgentFact("Gateway mode", self._yes_no(bool(gateway.get("enabled")))),
            AgentFact("Cached LAN devices", str(len(cached.get("devices") or []))),
        ]
        local_ip = str(info.get("localIp") or "Unknown")
        gw = str(info.get("gateway") or "Unknown")
        iface = str(info.get("interface") or "Unknown")
        gw_mode = bool(gateway.get("enabled"))
        device_count = len(cached.get("devices") or [])
        summary = f"EasyPi is at {local_ip} on {iface} via gateway {gw}; gateway mode is {'on' if gw_mode else 'off'}."
        recommendations = [
            "Run a LAN scan to discover devices, or a speed test to check your internet."
            if device_count == 0
            else "Ask about a specific device, open ports, connections, or run a speed test for more detail.",
        ]
        if gw_mode:
            recommendations.append(
                "Gateway mode is on — EasyPi routes the LAN and can transparently filter DNS for every device."
            )
        return AgentResponse(
            category="service",
            target="network-toolkit",
            matched=True,
            title="Network toolkit overview",
            summary=summary,
            confidence="high",
            section="network-toolkit",
            subsection="overview",
            module=self.name,
            checks_run=["network_info", "gateway_mode_status"],
            facts=facts,
            reason_chain=[
                f"Base network info collected: {local_ip} on {iface}, gateway {gw}.",
                f"Gateway mode is {'enabled' if gw_mode else 'disabled'}; {device_count} cached LAN device(s).",
            ],
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _extract_port(self, question: str, target: str) -> int | None:
        match = re.search(r"\b(\d{1,5})\b", f"{question} {target}")
        if match is None:
            return None
        value = int(match.group(1))
        if 0 <= value <= 65535:
            return value
        return None

    def _extract_host_query(self, question: str, target: str) -> str:
        if target.strip():
            return target.strip()
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", question)
        if ip_match:
            return ip_match.group(0)
        tokens = re.findall(r"[A-Za-z0-9._-]+", question)
        ignore = {"why", "is", "was", "my", "the", "host", "not", "found", "lan", "scan", "router", "exclusion", "active", "device", "new"}
        for token in reversed(tokens):
            if token.lower() not in ignore and len(token) > 2:
                return token
        return ""

    def _find_cached_device(self, query: str, devices: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(query or "").strip().lower()
        if not normalized:
            return None
        for device in devices:
            haystacks = [
                str(device.get("ip") or "").strip().lower(),
                str(device.get("hostname") or "").strip().lower(),
                str(device.get("vendor") or "").strip().lower(),
            ]
            if normalized in haystacks:
                return device
        return None

    def _looks_internet_facing(self, remote_address: str) -> bool:
        value = str(remote_address or "").strip()
        if not value:
            return False
        try:
            ip = ip_address(value)
        except ValueError:
            return False
        private_networks = (
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
            ip_network("127.0.0.0/8"),
            ip_network("169.254.0.0/16"),
        )
        return not any(ip in network for network in private_networks)

    def _top_process(self, connections: list[dict[str, object]]) -> str | None:
        scores: dict[str, int] = {}
        for connection in connections:
            name = str(connection.get("processName") or "unknown").strip()
            if not name:
                continue
            scores[name] = scores.get(name, 0) + 1
        if not scores:
            return None
        process_name, count = max(scores.items(), key=lambda item: item[1])
        return f"{process_name} ({count} sockets)"
