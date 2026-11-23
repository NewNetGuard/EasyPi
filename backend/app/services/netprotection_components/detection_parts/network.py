"""Detection operations for NetProtection."""

from app.services.netprotection_components.runtime_context import (
    Any,
    DNS_SHADOW_DOMAIN,
    DNS_SHADOW_GROUP,
    DNS_SHADOW_AVAILABLE,
    Dict,
    _compute_windowed_bytes,
    _detect_dns_shadow,
    _parse_conntrack_snapshot,
    _read_recent_resolved_ips,
    _short_err,
    asyncio,
    datetime,
    json,
    logger,
    sanitize_mac,
    subprocess,
    time,
    timezone,
)


class DetectionNetworkMixin:
    def _classify_reject_channel(self, line: str) -> "str | None":
        """Classify an iptables REJECT line into a bypass channel, or None.

        Plain QUIC (udp dpt:443) is intentionally NOT treated as a bypass signal:
        ordinary HTTP/3 traffic to normal sites also lands on that reject rule.
        DoH to a known resolver IP is matched by the doh-provider ipset rule.
        """
        low = line.lower()
        if "dpt:443" in low and "match-set" not in low:
            return None
        matchers = (
            ("doh", ("easypi_doh_providers", "dpt:853")),
            (
                "vpn",
                (
                    "dpt:1194",
                    "dpt:1195",
                    "dpt:500",
                    "dpt:4500",
                    "dpt:1723",
                    "dpt:1701",
                    "dpt:8388",
                ),
            ),
            (
                "proxy",
                (
                    "easypi_proxy_endpoints",
                    "dpt:1080",
                    "dpt:1081",
                    "dpt:8080",
                    "dpt:3128",
                    "dpt:8118",
                ),
            ),
            (
                "tor",
                (
                    "easypi_tor_nodes",
                    "dpt:9001",
                    "dpt:9030",
                    "dpt:9050",
                    "dpt:9051",
                    "dpt:9150",
                ),
            ),
            ("smartdns", ("easypi_smartdns_providers",)),
        )
        for channel, needles in matchers:
            if any(n in low for n in needles):
                return channel
        return None

    async def _read_bypass_reject_counters(self) -> "dict[str, dict[str, int]]":
        """Return {ip: {channel: pkts}} parsed from EASYPI_VPN_* chains.

        Counts both blocked (REJECT) and monitored (EASYPI_BYPASS_MON) hits, so bypass is
        detected even for channels the admin chose not to block.
        """
        import subprocess

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                ["sudo", "-n", "iptables", "-L", "-n", "-v", "-x"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception as e:
            logger.debug(f"bypass detector: iptables read failed: {e}")
            return {}
        if proc.returncode != 0:
            return {}
        mac_to_ip: dict[str, str] = {}
        try:
            devices_payload = json.loads(
                (self.data_dir / "devices.json").read_text(
                    encoding="utf-8", errors="ignore"
                )
            )
            devices = (
                devices_payload
                if isinstance(devices_payload, list)
                else devices_payload.get("devices", [])
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = sanitize_mac(device.get("mac"))
                ip = str(device.get("ip") or "").strip()
                if mac:
                    ip = self._resolve_ipv4_from_mac(mac) or ip
                if mac and self._is_valid_ipv4(ip):
                    mac_to_ip[mac] = ip
        except Exception as exc:
            logger.warning("Bypass detector could not map configured devices: %s", exc)
        result: dict[str, dict[str, int]] = {}
        cur_ip = None
        for raw in proc.stdout.splitlines():
            line = raw.rstrip()
            if line.startswith("Chain EASYPI_VPNM_"):
                try:
                    raw_mac = line.split()[1][len("EASYPI_VPNM_") :]
                    mac = ":".join(raw_mac[i : i + 2] for i in range(0, 12, 2))
                    cur_ip = mac_to_ip.get(mac)
                except Exception:
                    cur_ip = None
                continue
            if line.startswith("Chain EASYPI_VPN_"):
                try:
                    name = line.split()[1]
                    octets = name[len("EASYPI_VPN_") :].split("_")
                    cand = ".".join(octets) if len(octets) == 4 else ""
                    cur_ip = cand if self._is_valid_ipv4(cand) else None
                except Exception:
                    cur_ip = None
                continue
            if line.startswith("Chain "):
                cur_ip = None
                continue
            # Count both enforcement hits (REJECT) and monitor hits (jump to the empty
            # EASYPI_BYPASS_MON accounting chain). Monitor rules exist for channels the
            # admin did NOT tick: the traffic passes, but it is still detected so the
            # banner can fire and the admin can decide from there.
            if not cur_ip or (
                "REJECT" not in line and self._BYPASS_MON_CHAIN not in line
            ):
                continue
            parts = line.split()
            if not parts or not parts[0].isdigit():
                continue
            channel = self._classify_reject_channel(line)
            if channel is None:
                continue
            bucket = result.setdefault(cur_ip, {})
            bucket[channel] = bucket.get(channel, 0) + int(parts[0])
        return result

    async def _read_conntrack_wan_flows(self) -> list:
        """Read the current conntrack snapshot into a list of external WAN flows."""
        if not DNS_SHADOW_AVAILABLE or _parse_conntrack_snapshot is None:
            return []
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                ["sudo", "-n", "conntrack", "-L", "-o", "extended"],
                capture_output=True,
                text=True,
                timeout=12,
            )
        except Exception as e:
            logger.debug(f"dns-shadow detector: conntrack read failed: {e}")
            return []
        if proc.returncode != 0:
            logger.debug(
                f"dns-shadow detector: conntrack returned {proc.returncode}: {_short_err(proc.stderr)}"
            )
            return []
        stdout = proc.stdout or ""
        # Byte counters require nf_conntrack_acct. Without it conntrack still lists flows but
        # emits no bytes=, so the detector can never fire. Warn once instead of silently no-op.
        if (
            not self._dns_shadow_acct_warned
            and ("bytes=" not in stdout)
            and (" tcp " in stdout or " udp " in stdout)
        ):
            logger.warning(
                "dns-shadow detector: conntrack has no byte counters — enable "
                "net.netfilter.nf_conntrack_acct=1 (detection is disabled until then)."
            )
            self._dns_shadow_acct_warned = True
        try:
            return _parse_conntrack_snapshot(stdout.splitlines())
        except Exception as e:
            logger.debug(f"dns-shadow detector: conntrack parse failed: {e}")
            return []

    def _inject_dns_shadow_alert(self, observation: Any) -> bool:
        """Create/refresh a DNS-shadow bypass alert. Returns False when suppressed."""
        ip = str(getattr(observation, "ip", "") or "").strip()
        if not self._is_valid_ipv4(ip):
            return False

        now = time.time()
        groups = self._policy_relevant_bypass_groups(ip, [DNS_SHADOW_GROUP])
        if not groups:
            return False
        state = self._load_bypass_events_meta()
        by_ip = state.get("by_ip")
        if not isinstance(by_ip, dict):
            by_ip = {}
        existing = by_ip.get(ip) if isinstance(by_ip.get(ip), dict) else None

        unexplained_flows = int(getattr(observation, "unexplained_flows", 0) or 0)
        # Shape separates the two things that both look "unexplained": a real tunnel
        # concentrates heavy bytes on 1-2 destinations, whereas a device using an unlisted
        # encrypted DNS (DoH/DoT) spreads ordinary browsing across many. Tagging it lets the
        # known DoH false-positive class be counted separately when calibrating on real
        # installs, and makes the alert wording honest about which case this looks like.
        shape = "concentrated" if unexplained_flows <= 2 else "diffuse"
        detail = {
            "unexplained_bytes": int(getattr(observation, "unexplained_bytes", 0) or 0),
            "unexplained_flows": unexplained_flows,
            "resolved_count": int(getattr(observation, "resolved_count", 0) or 0),
            "shape": shape,
            "confidence": float(getattr(observation, "confidence", 0.0) or 0.0),
        }
        if shape == "concentrated":
            hint = (
                "Heavy WAN concentrated on 1-2 destinations EasyPi never resolved for this "
                "device — likely an encrypted tunnel or proxy"
            )
        else:
            hint = (
                "WAN to many destinations EasyPi never resolved for this device — possibly an "
                "unlisted encrypted DNS (DoH/DoT), or a tunnel"
            )

        if existing:
            try:
                ack_val = (
                    float(existing.get("ack_ts"))
                    if existing.get("ack_ts") is not None
                    else None
                )
            except Exception:
                ack_val = None
            try:
                ts_prev = (
                    float(existing.get("ts"))
                    if existing.get("ts") is not None
                    else None
                )
            except Exception:
                ts_prev = None
            if (
                bool(existing.get("leak"))
                and ts_prev is not None
                and (ack_val is None or ack_val < ts_prev)
            ):
                existing_groups = list(existing.get("groups") or []) + groups
                existing["groups"] = self._policy_relevant_bypass_groups(
                    ip, existing_groups
                )
                existing["source_hint"] = hint
                existing["dns_shadow"] = detail
                existing["policy_enforced"] = True
                by_ip[ip] = existing
                state["by_ip"] = by_ip
                self._save_bypass_events_meta(state)
                return True
            if (
                ack_val is not None
                and (now - ack_val) < self._bypass_alert_cooldown_sec
            ):
                return False

        by_ip[ip] = {
            "ip": ip,
            "domain": DNS_SHADOW_DOMAIN,
            "flow_id": f"dns-shadow:{ip}:{int(now)}",
            "leak": True,
            "ts": now,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "groups": groups,
            "tor_bridge": False,
            "source_hint": hint,
            "dns_shadow": detail,
            "policy_enforced": True,
            "ack_ts": existing.get("ack_ts") if existing else None,
            "acknowledged_at": existing.get("acknowledged_at") if existing else None,
        }
        state["by_ip"] = by_ip
        self._save_bypass_events_meta(state)
        logger.warning(
            "DNS-shadow bypass detected for %s: unexplained_bytes=%s unexplained_flows=%s resolved=%s",
            ip,
            detail["unexplained_bytes"],
            detail["unexplained_flows"],
            detail["resolved_count"],
        )
        return True

    def _stealth_covered(self) -> tuple[bool, set[str]]:
        """(covers_all, ips) currently routed through OUR Stealth tunnel.

        Those devices are using EasyPi's own anti-DPI path, not bypassing it, so every
        bypass producer must exempt them — otherwise EasyPi flags its own stealth traffic.
        Read from the in-process StealthService singleton (same backend), lazily imported
        to avoid an import cycle; any failure fails open (exempt nothing)."""
        try:
            from app.services.stealth_service import get_stealth_service

            return get_stealth_service().covered_ips()
        except Exception:
            return (False, set())

    async def detect_dns_shadow_bypass(self) -> Dict[str, Any]:
        """Flag protected devices whose WAN goes to IPs EasyPi never resolved for them."""
        if (
            not DNS_SHADOW_AVAILABLE
            or _detect_dns_shadow is None
            or _read_recent_resolved_ips is None
        ):
            return {"checked": 0, "alerts": [], "applied": [], "skipped": "unavailable"}

        now = time.time()
        if (
            now - self._dns_shadow_detect_last_run
        ) < self._dns_shadow_detect_interval_sec:
            return {"checked": 0, "alerts": [], "applied": [], "skipped": "throttled"}
        self._dns_shadow_detect_last_run = now

        if not self.flow_log_path.exists():
            return {
                "checked": 0,
                "alerts": [],
                "applied": [],
                "skipped": "flow_log_missing",
            }

        protected = self._get_protected_device_ips()
        if not protected:
            return {
                "checked": 0,
                "alerts": [],
                "applied": [],
                "skipped": "no_protected_devices",
            }

        # Devices we route through OUR Stealth tunnel push heavy WAN to IPs EasyPi never
        # resolved (that IS the tunnel) — sanctioned traffic, not a bypass. Drop them from
        # the protected set so the detector never bans our own stealth path.
        covers_all, covered = self._stealth_covered()
        if covers_all:
            return {
                "checked": 0,
                "alerts": [],
                "applied": [],
                "skipped": "stealth_active",
            }
        if covered:
            protected = {ip for ip in protected if ip not in covered}
            if not protected:
                return {
                    "checked": 0,
                    "alerts": [],
                    "applied": [],
                    "skipped": "stealth_active",
                }

        flows = await self._read_conntrack_wan_flows()

        # Measure WAN as a delta between snapshots (per client, per destination), not
        # cumulative connection totals.
        per_client_dst_bytes, new_counters = _compute_windowed_bytes(
            flows, self._dns_shadow_prev_counters
        )
        self._dns_shadow_prev_counters = new_counters

        # The first pass has no previous snapshot, so every flow looks new and its whole
        # lifetime total would count as "this window". Establish the baseline and skip.
        if not self._dns_shadow_baseline_ready:
            self._dns_shadow_baseline_ready = True
            return {
                "checked": len(protected),
                "alerts": [],
                "applied": [],
                "skipped": "baseline",
            }

        if not per_client_dst_bytes:
            return {"checked": len(protected), "alerts": [], "applied": []}

        # Which destination IPs EasyPi actually resolved for each device recently. WAN to any
        # other IP is "unexplained" — obtained out-of-band (tunnel endpoint / hardcoded proxy),
        # which a decoy DNS lookup cannot mask.
        resolved_ips = await asyncio.to_thread(
            _read_recent_resolved_ips,
            self.flow_log_path,
            protected,
            now=now,
            window_seconds=self._dns_shadow_resolved_window_sec,
        )
        observations = _detect_dns_shadow(
            per_client_dst_bytes,
            resolved_ips,
            protected_ips=protected,
            min_wan_bytes=self._dns_shadow_min_wan_bytes,
            min_unexplained_flows=self._dns_shadow_min_external_flows,
        )

        stale_after = max(60.0, self._dns_shadow_detect_interval_sec * 6.0)
        for ip, state in list(self._dns_shadow_suspect_by_ip.items()):
            try:
                last_seen = float(state.get("last_seen", 0.0))
            except Exception:
                last_seen = 0.0
            if (now - last_seen) > stale_after:
                self._dns_shadow_suspect_by_ip.pop(ip, None)

        fail_closed_ips = set(await self.list_fail_closed_clients())
        alerts: list[str] = []
        applied: list[str] = []
        failed: list[str] = []
        for observation in observations:
            ip = str(observation.ip)
            previous = self._dns_shadow_suspect_by_ip.get(ip) or {}
            try:
                prev_last = float(previous.get("last_seen", 0.0))
                prev_count = int(previous.get("count", 0))
            except Exception:
                prev_last = 0.0
                prev_count = 0

            continuous = prev_last > 0 and (now - prev_last) <= stale_after
            count = prev_count + 1 if continuous else 1
            self._dns_shadow_suspect_by_ip[ip] = {
                "first_seen": float(previous.get("first_seen", now))
                if continuous
                else now,
                "last_seen": now,
                "count": count,
            }

            huge = int(observation.unexplained_bytes) >= self._dns_shadow_huge_wan_bytes
            if count < 2 and not huge:
                continue

            if not self._inject_dns_shadow_alert(observation):
                continue
            alerts.append(ip)

            if self._get_bypass_mode_by_ip(ip) != "quarantine" or ip in fail_closed_ips:
                continue

            result = await self.quarantine_client(ip)
            if result.get("success"):
                applied.append(ip)
                fail_closed_ips.add(ip)
                try:
                    self.record_fail_closed_trigger(
                        client_ip=ip,
                        domain=DNS_SHADOW_DOMAIN,
                        flow_id=f"dns-shadow:{ip}:{int(now)}",
                        ts=now,
                        applied=True,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to persist DNS-shadow quarantine trigger for %s: %s",
                        ip,
                        exc,
                    )
            else:
                err = _short_err(
                    result.get("error")
                    or result.get("stderr")
                    or result.get("stdout")
                    or "quarantine failed"
                )
                failed.append(f"{ip}: {err}")
                try:
                    self.record_fail_closed_trigger(
                        client_ip=ip,
                        domain=DNS_SHADOW_DOMAIN,
                        flow_id=f"dns-shadow:{ip}:{int(now)}",
                        ts=now,
                        applied=False,
                        error=err,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to persist failed DNS-shadow trigger for %s: %s",
                        ip,
                        exc,
                    )

        if applied:
            try:
                triggers = {
                    ip: {
                        "domain": DNS_SHADOW_DOMAIN,
                        "flow_id": f"dns-shadow:{ip}:{int(now)}",
                    }
                    for ip in applied
                }
                asyncio.create_task(self._notify_fail_closed(applied, triggers))
            except Exception as exc:
                logger.warning(
                    "Could not schedule DNS-shadow quarantine notification: %s", exc
                )
        if failed:
            logger.warning("DNS-shadow auto-quarantine failures: %s", failed)

        return {
            "checked": len(observations),
            "alerts": alerts,
            "applied": applied,
            "failed": failed,
        }

    def _get_blocked_bypass_channels(self, ip: str) -> "set[str]":
        """Bypass channels actually BLOCKED (ticked) for a device, per devices.json.

        Mirrors the channel derivation in setup_vpn_blocking.sh: 'bypass'/'strict_parental'
        select every channel, otherwise each service alias maps to its channel. Channels not
        returned here are only monitored — bypass over them is detected, not blocked.
        """
        aliases = {
            "vpn": {"vpn", "vpn_services"},
            "doh": {"doh", "dns_over_https", "dot", "dns_over_tls"},
            "proxy": {"proxy", "web_proxy", "web_proxies"},
            "tor": {"tor"},
            "smartdns": {"smartdns", "smart_dns"},
        }
        channels: set[str] = set()
        ip = str(ip or "").strip()
        observed_mac = self._resolve_mac_from_arp(ip)
        if self._get_bypass_mode_by_ip(ip) == "log_only":
            return channels
        try:
            devices_path = self.data_dir / "devices.json"
            if not devices_path.exists():
                return channels
            data = json.loads(devices_path.read_text(encoding="utf-8", errors="ignore"))
            devices = data if isinstance(data, list) else data.get("devices", [])
            for d in devices:
                if not isinstance(d, dict):
                    continue
                matches_ip = str(d.get("ip") or "").strip() == ip
                matches_mac = bool(
                    observed_mac and sanitize_mac(d.get("mac")) == observed_mac
                )
                if not matches_ip and not matches_mac:
                    continue
                if not d.get("enabled", True):
                    return set()
                if str(d.get("bypass_mode") or "warn").strip().lower() == "log_only":
                    return set()
                services = {
                    str(s).strip().lower()
                    for s in (d.get("blocked_services") or [])
                    if isinstance(s, str) and str(s).strip()
                }
                if "bypass" in services or "strict_parental" in services:
                    channels.update(aliases.keys())
                for channel, names in aliases.items():
                    if services & names:
                        channels.add(channel)
                break
        except Exception as exc:
            logger.warning("Could not read blocked bypass policy for %s: %s", ip, exc)
        return channels

    def _policy_relevant_bypass_groups(
        self, ip: str, groups: "list[str] | set[str] | tuple[str, ...]"
    ) -> "list[str]":
        """Keep only detected channels prohibited for this device.

        DNS-shadow is channel-agnostic. It is relevant when at least one bypass
        channel is prohibited, without claiming which protocol carried it.
        """
        blocked_channels = self._get_blocked_bypass_channels(ip)
        if not blocked_channels:
            return []
        normalized = {
            str(group).strip().lower() for group in groups if str(group).strip()
        }
        relevant = normalized & blocked_channels
        if DNS_SHADOW_GROUP in normalized:
            relevant.add(DNS_SHADOW_GROUP)
        return sorted(relevant)

    def _get_protected_device_ips(self) -> "set[str]":
        """IPs with at least one enabled bypass prohibition."""
        ips: set[str] = set()
        try:
            devices_path = self.data_dir / "devices.json"
            if not devices_path.exists():
                return ips
            data = json.loads(devices_path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, list):
                devices = data
            elif isinstance(data, dict):
                devices = data.get("devices", [])
            else:
                devices = []
            for d in devices:
                if not isinstance(d, dict) or not d.get("enabled", True):
                    continue
                if str(d.get("bypass_mode") or "warn").strip().lower() == "log_only":
                    continue
                mac = sanitize_mac(d.get("mac"))
                ip = self._resolve_ipv4_from_mac(mac) if mac else ""
                if not ip:
                    ip = str(d.get("ip") or "").strip()
                if self._is_valid_ipv4(ip) and self._get_blocked_bypass_channels(ip):
                    ips.add(ip)
        except Exception as exc:
            logger.warning("Could not enumerate protected device IPs: %s", exc)
        return ips

    def _get_bypass_mode_by_ip(self, ip: str) -> str:
        """Return a device's anti-bypass response mode.

        One of 'warn' | 'quarantine' | 'log_only'. Looks the client up by IP in
        clients.json (the canonical store written by set_bypass_mode_by_ip) and
        defaults to 'warn' when the device or field is unknown.
        """
        ip = str(ip or "").strip()
        observed_mac = self._resolve_mac_from_arp(ip)
        try:
            clients_path = self.data_dir / "clients.json"
            if not clients_path.exists():
                return "warn"
            data = json.loads(clients_path.read_text(encoding="utf-8", errors="ignore"))
            for client in data.get("clients", []) or []:
                if not isinstance(client, dict):
                    continue
                ids = client.get("ids") if isinstance(client.get("ids"), list) else []
                legacy_ip = str(client.get("ip") or "").strip()
                matches_mac = bool(
                    observed_mac and sanitize_mac(client.get("mac")) == observed_mac
                )
                if (
                    matches_mac
                    or ip == legacy_ip
                    or ip in [str(x or "").strip() for x in ids]
                ):
                    mode = str(client.get("bypass_mode") or "warn").strip().lower()
                    return (
                        mode if mode in {"warn", "quarantine", "log_only"} else "warn"
                    )
        except Exception as exc:
            logger.warning(
                "Could not read anti-bypass response mode for %s: %s", ip, exc
            )
        return "warn"

    async def detect_network_bypass(self) -> None:
        """Raise a bypass alert when a protected device attempts blocked bypass
        channels (VPN/DoH/proxy/Tor/SmartDNS), detected via firewall REJECT
        counter growth. The existing pipeline then shows the banner and, if the
        admin does not act within 60s, auto-quarantines the device."""
        now = time.time()
        if (now - self._bypass_detect_last_run) < self._bypass_detect_interval_sec:
            return
        self._bypass_detect_last_run = now

        counters = await self._read_bypass_reject_counters()
        if not counters:
            return
        protected = self._get_protected_device_ips()

        for ip, channels in counters.items():
            baseline = self._bypass_counter_baseline.get(ip, {})
            grown: list[str] = []
            for channel, pkts in channels.items():
                prev = baseline.get(channel)
                if prev is None:
                    continue  # first observation: establish baseline, do not alert
                if pkts < prev:
                    continue  # chain rebuilt -> counters reset
                threshold = 10 if channel == "doh" else 2
                if (pkts - prev) >= threshold:
                    grown.append(channel)
            self._bypass_counter_baseline[ip] = dict(channels)
            if grown and ip in protected:
                relevant_groups = self._policy_relevant_bypass_groups(ip, grown)
                if relevant_groups:
                    self._inject_network_bypass_alert(ip, relevant_groups)

    def _inject_network_bypass_alert(self, ip: str, groups: "list[str]") -> None:
        """Create/refresh a network-layer bypass alert for the UI banner.

        Preserves the original timestamp of an active, unacknowledged alert so the
        60-second auto-quarantine countdown is not reset by repeated detections,
        and honours a post-acknowledgement cooldown to avoid immediate re-alerts.
        """
        now = time.time()
        groups = self._policy_relevant_bypass_groups(ip, groups)
        if not groups:
            return
        hint = "Blocked bypass attempt detected at network layer"
        state = self._load_bypass_events_meta()
        by_ip = state.get("by_ip")
        if not isinstance(by_ip, dict):
            by_ip = {}
        existing = by_ip.get(ip) if isinstance(by_ip.get(ip), dict) else None

        if existing:
            try:
                ack_val = (
                    float(existing.get("ack_ts"))
                    if existing.get("ack_ts") is not None
                    else None
                )
            except Exception:
                ack_val = None
            try:
                ts_prev = (
                    float(existing.get("ts"))
                    if existing.get("ts") is not None
                    else None
                )
            except Exception:
                ts_prev = None
            # Active, unacknowledged alert: keep ts (preserve countdown), merge groups.
            if (
                bool(existing.get("leak"))
                and ts_prev is not None
                and (ack_val is None or ack_val < ts_prev)
            ):
                existing_groups = self._policy_relevant_bypass_groups(
                    ip, existing.get("groups") or []
                )
                existing["groups"] = sorted(set(existing_groups + list(groups)))
                existing["source_hint"] = hint
                existing["policy_enforced"] = True
                by_ip[ip] = existing
                state["by_ip"] = by_ip
                self._save_bypass_events_meta(state)
                return
            # Recently acknowledged/observed: cooldown before re-alerting.
            if (
                ack_val is not None
                and (now - ack_val) < self._bypass_alert_cooldown_sec
            ):
                return

        by_ip[ip] = {
            "ip": ip,
            "domain": None,
            "flow_id": None,
            "leak": True,
            "ts": now,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "groups": list(groups),
            "tor_bridge": "tor" in groups,
            "source_hint": hint,
            "policy_enforced": True,
            "ack_ts": existing.get("ack_ts") if existing else None,
            "acknowledged_at": existing.get("acknowledged_at") if existing else None,
        }
        state["by_ip"] = by_ip
        self._save_bypass_events_meta(state)
        logger.warning(f"Network-layer bypass detected for {ip}: {groups}")

    def _reset_bypass_state(self, client_ip: str) -> None:
        """Forget the bypass alert + counter baseline for a device so a fresh
        bypass (e.g. VPN switched on again after internet was restored) is
        detected and re-alerted immediately, not silenced by an old acknowledgement."""
        ip = str(client_ip or "").strip()
        if not ip:
            return
        self._bypass_counter_baseline.pop(ip, None)
        try:
            state = self._load_bypass_events_meta()
            by_ip = state.get("by_ip")
            if isinstance(by_ip, dict) and ip in by_ip:
                by_ip.pop(ip, None)
                state["by_ip"] = by_ip
                self._save_bypass_events_meta(state)
        except Exception as exc:
            logger.warning("Could not reset anti-bypass state for %s: %s", ip, exc)
