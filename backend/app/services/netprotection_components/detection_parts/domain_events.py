"""Detection operations for NetProtection."""

from app.services.netprotection_components.runtime_context import (
    Any,
    Dict,
    NETPROTECTION_AVAILABLE,
    _short_err,
    datetime,
    fnmatch,
    json,
    logger,
    re,
    time,
    timezone,
)


class DetectionDomainEventsMixin:
    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Match a domain against exact/suffix/wildcard patterns.

        Compatible with patterns in easypi_netprotection.service_domains.
        """
        domain = str(domain or "").strip().lower().rstrip(".")
        pattern = str(pattern or "").strip().lower().rstrip(".")
        if not domain or not pattern:
            return False
        # service_domains may include path-like entries (e.g. "hide.me/proxy")
        pattern = pattern.split("/", 1)[0].strip()
        if not pattern:
            return False

        # Prefer suffix semantics for "*.example.com" (fnmatch("example.com", "*.example.com") == False).
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)

        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(domain, pattern)

        return domain == pattern or domain.endswith("." + pattern)

    def _classify_visited_domain(self, domain: str) -> str:
        """Classify a queried host as 'site' | 'tracker' | 'background'.

        DNS alone can't prove browsing intent, so this is a best-effort heuristic used
        only to *organise* the Visited-sites view (nothing is hidden — trackers and
        background are shown in their own tab).
        """
        d = (domain or "").strip().lower().rstrip(".")
        if not d or "." not in d:
            return "background"
        if d.endswith(".arpa"):  # reverse-DNS PTR lookups, not a site
            return "background"
        labels = d.split(".")

        # 1) Known infra/tracker registrable suffix.
        if any(d == s or d.endswith("." + s) for s in self._VISITED_INFRA_SUFFIXES):
            if any(
                d == s or d.endswith("." + s) for s in self._VISITED_TRACKER_SUFFIXES
            ):
                return "tracker"
            return "background"
        if (
            "datadog" in d
        ):  # datadog uses novel per-region intake domains (browser-intake-*)
            return "tracker"

        # 2) Tracker label anywhere (word-boundary via labels + hyphen sub-parts).
        parts = set(labels)
        for lb in labels:
            for seg in lb.split("-"):
                parts.add(seg)
        if parts & self._VISITED_TRACKER_LABELS:
            return "tracker"
        if any(
            lb.endswith("-pa") or "-pa-" in lb for lb in labels
        ):  # Google private APIs
            return "background"

        # 3) Background service subdomain / CDN / infra.
        if parts & self._VISITED_BG_LABELS:
            return "background"
        if any(sub in d for sub in self._VISITED_BG_SUBSTRINGS):
            return "background"
        if any(
            lb.startswith("lh") and lb[2:].isdigit() for lb in labels
        ):  # Google image CDN
            return "background"

        # 4) Otherwise: a site the user actually visited.
        return "site"

    def _registrable_domain(self, host: str) -> str:
        """Best-effort eTLD+1 (registrable domain) so subdomains of the same site
        collapse into one 'site' entry (e.g. www./inbox.google.com -> google.com;
        a.b.sjtu.edu.cn -> sjtu.edu.cn)."""
        d = (host or "").strip().lower().rstrip(".")
        labels = [label for label in d.split(".") if label]
        if len(labels) <= 2:
            return d
        if labels[-2] in self._VISITED_SECOND_LEVEL:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def _classify_bypass_domain(self, domain: str) -> list[str]:
        """
        Best-effort classification for bypass triggers (for UI).

        Returns a list because some domains belong to multiple groups (e.g. Opera).
        """
        if not domain:
            return []
        if not NETPROTECTION_AVAILABLE:
            return []

        from easypi_netprotection.service_domains import get_domains_for_service

        groups = ("doh", "vpn", "proxy", "tor", "smartdns")
        domain_l = str(domain).strip().lower().rstrip(".")
        matched: list[str] = []
        for g in groups:
            patterns = self._fail_closed_bypass_pattern_cache.get(g)
            if patterns is None:
                patterns = tuple(get_domains_for_service(g))
                self._fail_closed_bypass_pattern_cache[g] = patterns
            for p in patterns:
                if self._domain_matches_pattern(domain_l, p):
                    matched.append(g)
                    break
        # A mundane '<public-domain>.onion' (DNS-diagnostic probe, e.g.
        # google.com.onion) is not a real onion address — don't report it as Tor.
        if (
            "tor" in matched
            and domain_l.endswith(".onion")
            and not self._is_valid_onion_address(domain_l)
        ):
            matched = [g for g in matched if g != "tor"]
        if self._is_tor_bridge_domain(domain_l) and "tor" not in matched:
            matched.append("tor")
        return matched

    def _is_tor_bridge_domain(self, domain: str | None) -> bool:
        d = str(domain or "").strip().lower().rstrip(".")
        if not d:
            return False
        for pattern in self._TOR_BRIDGE_PATTERNS:
            if self._domain_matches_pattern(d, pattern):
                return True
        # Conservative fallback for Tor bridge/snowflake hostnames.
        if "torproject" in d and ("bridge" in d or "snowflake" in d):
            return True
        return False

    def _is_valid_onion_address(self, domain: str | None) -> bool:
        """True only for a real Tor onion address: a v2 (16-char) or v3 (56-char)
        base32 label immediately before '.onion'. A mundane '<public-domain>.onion'
        (e.g. google.com.onion, which DNS diagnostics probe) is NOT a real onion and
        must not be treated as Tor bypass."""
        d = str(domain or "").strip().lower().rstrip(".")
        if not d.endswith(".onion"):
            return False
        label = d[: -len(".onion")].split(".")[-1]
        return bool(
            re.fullmatch(r"[a-z2-7]{16}", label) or re.fullmatch(r"[a-z2-7]{56}", label)
        )

    def _load_fail_closed_meta(self) -> dict:
        path = self._fail_closed_meta_path
        if not path.exists():
            return {"version": 1, "updated_at": None, "by_ip": {}}
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return {"version": 1, "updated_at": None, "by_ip": {}}

        by_ip_raw = payload.get("by_ip", {})
        if not isinstance(by_ip_raw, dict):
            by_ip_raw = {}

        by_ip: dict[str, dict] = {}
        for ip, entry in by_ip_raw.items():
            ip_s = str(ip or "").strip()
            if not self._is_valid_ipv4(ip_s):
                continue
            if not isinstance(entry, dict):
                continue
            by_ip[ip_s] = entry

        return {"version": 1, "updated_at": payload.get("updated_at"), "by_ip": by_ip}

    def _save_fail_closed_meta(self, state: dict) -> None:
        state = dict(state or {})
        state["version"] = 1
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        path = self._fail_closed_meta_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        tmp.replace(path)

    def record_fail_closed_trigger(
        self,
        client_ip: str,
        domain: str | None,
        flow_id: str | None,
        ts: float | None,
        applied: bool,
        error: str | None = None,
    ) -> None:
        """Persist last fail-closed trigger for a client IP (UI diagnostics)."""
        ip = str(client_ip or "").strip()
        if not self._is_valid_ipv4(ip):
            return
        domain_s = str(domain or "").strip().lower().rstrip(".")
        flow_s = str(flow_id or "").strip()
        try:
            tsv = float(ts) if ts is not None else None
        except Exception:
            tsv = None

        triggered_at = None
        if tsv is not None:
            try:
                triggered_at = datetime.fromtimestamp(tsv, tz=timezone.utc).isoformat()
            except Exception:
                triggered_at = None

        groups = self._classify_bypass_domain(domain_s) if domain_s else []
        tor_bridge = self._is_tor_bridge_domain(domain_s) if domain_s else False

        state = self._load_fail_closed_meta()
        by_ip = state.get("by_ip", {})
        if not isinstance(by_ip, dict):
            by_ip = {}

        by_ip[ip] = {
            "ip": ip,
            "domain": domain_s or None,
            "flow_id": flow_s or None,
            "ts": tsv,
            "triggered_at": triggered_at,
            "groups": groups,
            "tor_bridge": tor_bridge,
            "applied": bool(applied),
            "applied_at": datetime.now(timezone.utc).isoformat() if applied else None,
            "error": _short_err(error or "") if error else None,
        }
        state["by_ip"] = by_ip
        self._save_fail_closed_meta(state)

    def get_fail_closed_triggers(self) -> dict[str, dict]:
        """Get persisted last fail-closed trigger per IP (best-effort)."""
        state = self._load_fail_closed_meta()
        by_ip = state.get("by_ip", {})
        return by_ip if isinstance(by_ip, dict) else {}

    def _load_bypass_events_meta(self) -> dict:
        path = self._bypass_events_meta_path
        if not path.exists():
            return {"version": 1, "updated_at": None, "by_ip": {}}
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return {"version": 1, "updated_at": None, "by_ip": {}}

        by_ip_raw = payload.get("by_ip", {})
        if not isinstance(by_ip_raw, dict):
            by_ip_raw = {}

        by_ip: dict[str, dict] = {}
        for ip, entry in by_ip_raw.items():
            ip_s = str(ip or "").strip()
            if not self._is_valid_ipv4(ip_s):
                continue
            if not isinstance(entry, dict):
                continue
            by_ip[ip_s] = entry

        return {"version": 1, "updated_at": payload.get("updated_at"), "by_ip": by_ip}

    def _save_bypass_events_meta(self, state: dict) -> None:
        state = dict(state or {})
        state["version"] = 1
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        path = self._bypass_events_meta_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        tmp.replace(path)

    def _infer_bypass_source_hint(self, domain: str | None) -> str | None:
        """
        Best-effort hint for UI (not guaranteed).

        We cannot reliably detect the exact browser/app without MITM, so we only
        provide a conservative hint based on known endpoint patterns.
        """
        d = str(domain or "").strip().lower().rstrip(".")
        if not d:
            return None
        if self._is_tor_bridge_domain(d):
            return "Possible source: Tor Browser Bridges"
        if "torproject" in d:
            return "Possible source: Tor Browser"
        if "mozilla" in d or "firefox" in d:
            return "Possible source: Firefox Secure DNS (DoH)"
        if "opera" in d:
            return "Possible source: Opera Secure DNS / VPN"
        if d in {"dns.google", "dns.google.com"} or ".google" in d:
            return "Possible source: Chrome/Android Secure DNS"
        if "cloudflare" in d:
            return "Possible source: Cloudflare Secure DNS / WARP"
        if "adguard" in d:
            return "Possible source: AdGuard DNS"
        if "quad9" in d:
            return "Possible source: Quad9 DNS"
        if "nextdns" in d:
            return "Possible source: NextDNS"
        return None

    async def process_bypass_events(self) -> Dict[str, Any]:
        """
        Drain bypass-events queue from netprotection engine and persist last event per IP.

        Queue format: JSON-lines with at least {"ip": "...", "domain": "..."}.
        """
        async with self._bypass_events_lock:
            queue_path = self._bypass_events_queue_path
            processing_path = self._bypass_events_queue_processing_path

            if not queue_path.exists() and not processing_path.exists():
                return {"processed": 0, "updated": []}

            if queue_path.exists():
                try:
                    queue_path.replace(processing_path)
                except FileNotFoundError:
                    pass
                except Exception as e:
                    logger.warning(f"Failed to rotate bypass-events queue: {e}")
                    return {"processed": 0, "updated": [], "failed": [str(e)]}

            if not processing_path.exists():
                return {"processed": 0, "updated": []}

            try:
                lines = processing_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except Exception as e:
                logger.warning(f"Failed to read bypass-events queue: {e}")
                lines = []
            finally:
                try:
                    processing_path.unlink(missing_ok=True)
                except Exception as exc:
                    logger.warning(
                        "Could not remove processed bypass queue %s: %s",
                        processing_path,
                        exc,
                    )

            # Keep the latest event per IP.
            latest_by_ip: dict[str, dict[str, Any]] = {}

            for raw in lines:
                line = (raw or "").strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                ip = str(payload.get("ip") or "").strip()
                if not self._is_valid_ipv4(ip):
                    continue
                domain = (
                    str(payload.get("domain") or "").strip().lower().rstrip(".") or None
                )
                flow_id = str(payload.get("flow_id") or "").strip() or None
                leak = bool(payload.get("leak", False))
                ts_raw = payload.get("ts")
                try:
                    ts_val = float(ts_raw) if ts_raw is not None else None
                except Exception:
                    ts_val = None

                prev = latest_by_ip.get(ip)
                prev_ts = prev.get("ts") if isinstance(prev, dict) else None
                try:
                    prev_ts_val = float(prev_ts) if prev_ts is not None else None
                except Exception:
                    prev_ts_val = None

                if prev is None or (
                    ts_val is not None
                    and (prev_ts_val is None or ts_val >= prev_ts_val)
                ):
                    latest_by_ip[ip] = {
                        "ip": ip,
                        "domain": domain,
                        "flow_id": flow_id,
                        "leak": leak,
                        "ts": ts_val,
                    }

            if not latest_by_ip:
                return {"processed": len(lines), "updated": []}

            state = self._load_bypass_events_meta()
            by_ip = state.get("by_ip", {})
            if not isinstance(by_ip, dict):
                by_ip = {}

            # Devices routed through OUR Stealth tunnel are using EasyPi's own anti-DPI
            # path, not bypassing it — never raise a bypass alert for them.
            covers_all, covered = self._stealth_covered()

            updated: list[str] = []
            for ip, event in latest_by_ip.items():
                existing = by_ip.get(ip, {}) if isinstance(by_ip.get(ip), dict) else {}
                ack_ts = existing.get("ack_ts")
                acked_at = existing.get("acknowledged_at")
                domain = event.get("domain")
                groups = self._classify_bypass_domain(domain or "") if domain else []
                tor_bridge = self._is_tor_bridge_domain(domain) if domain else False
                source_hint = self._infer_bypass_source_hint(domain)
                leak = bool(event.get("leak", False))

                # A mundane '<public-domain>.onion' (e.g. google.com.onion, which
                # DNS diagnostics probe) is NOT a real onion address and NOT a real
                # bypass — neutralize it so it raises no Tor alert and doesn't pollute
                # the history. DNS still blocks the domain as usual.
                if (
                    domain
                    and str(domain).lower().rstrip(".").endswith(".onion")
                    and not self._is_valid_onion_address(domain)
                ):
                    groups = []
                    tor_bridge = False
                    leak = False

                # Stealth-covered device: its egress is our sanctioned anti-DPI tunnel,
                # not a bypass. Neutralize so no banner fires and it stays out of history.
                if leak and (covers_all or ip in covered):
                    groups = []
                    tor_bridge = False
                    leak = False

                groups = self._policy_relevant_bypass_groups(ip, groups)
                leak = leak and bool(groups)
                tor_bridge = tor_bridge and "tor" in groups

                triggered_at = None
                ts_val = event.get("ts")
                if ts_val is not None:
                    try:
                        triggered_at = datetime.fromtimestamp(
                            float(ts_val), tz=timezone.utc
                        ).isoformat()
                    except Exception:
                        triggered_at = None

                by_ip[ip] = {
                    "ip": ip,
                    "domain": domain,
                    "flow_id": event.get("flow_id"),
                    "leak": leak,
                    "ts": ts_val,
                    "triggered_at": triggered_at,
                    "groups": groups,
                    "tor_bridge": tor_bridge,
                    "source_hint": source_hint,
                    "policy_enforced": leak,
                    "ack_ts": ack_ts,
                    "acknowledged_at": acked_at,
                }

                # Persistent per-device / per-channel history — only for real,
                # classified bypasses (unlike the live firewall REJECT counters,
                # this accumulates over time and survives reboots). It's what the
                # "bypass history" card shows: who tried which channel, how many
                # times, first/last seen.
                if leak and groups:
                    hist = state.get("history")
                    if not isinstance(hist, dict):
                        hist = {}
                    h = hist.get(ip) if isinstance(hist.get(ip), dict) else {}
                    seen_iso = triggered_at or datetime.now(timezone.utc).isoformat()
                    h.setdefault("first_seen", seen_iso)
                    h["last_seen"] = seen_iso
                    if domain:
                        h["last_domain"] = domain
                    chans = (
                        h.get("channels") if isinstance(h.get("channels"), dict) else {}
                    )
                    for ch in groups:
                        chans[str(ch)] = int(chans.get(str(ch), 0)) + 1
                    h["channels"] = chans
                    h["total"] = int(h.get("total", 0)) + 1
                    hist[ip] = h
                    state["history"] = hist

                updated.append(ip)

            state["by_ip"] = by_ip
            self._save_bypass_events_meta(state)
            return {"processed": len(lines), "updated": updated}

    async def process_bypass_leak_timeouts(self) -> Dict[str, Any]:
        """
        Auto-quarantine devices after unattended leak alerts.

        Policy: if a confirmed leak alert is not acknowledged for 60 seconds,
        quarantine device internet (fail-closed) and mark event as acknowledged
        to avoid immediate re-trigger loops after manual restore.
        """
        state = self._load_bypass_events_meta()
        by_ip = state.get("by_ip", {})
        if not isinstance(by_ip, dict) or not by_ip:
            return {"checked": 0, "applied": [], "failed": []}

        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        fail_closed_ips = set(await self.list_fail_closed_clients())
        applied: list[str] = []
        failed: list[str] = []
        changed = False

        for ip, entry in by_ip.items():
            if not self._is_valid_ipv4(ip) or not isinstance(entry, dict):
                continue
            if not bool(entry.get("leak", False)):
                continue
            if ip in fail_closed_ips:
                continue
            groups = (
                entry.get("groups") if isinstance(entry.get("groups"), list) else []
            )
            if entry.get("policy_enforced") is not True:
                continue
            if not self._policy_relevant_bypass_groups(ip, groups):
                continue
            # Respect the per-device response policy: only 'quarantine' mode may auto-cut
            # internet here. 'warn' and 'log_only' devices must NEVER be fail-closed by this
            # loop (warn already soft-blocks the bypass endpoint at the DNS layer, so a
            # background DoH probe can't cut a device that never actually escaped filtering).
            if self._get_bypass_mode_by_ip(ip) != "quarantine":
                continue

            ts_raw = entry.get("ts")
            try:
                ts_val = float(ts_raw) if ts_raw is not None else None
            except Exception:
                ts_val = None
            if ts_val is None:
                continue

            ack_ts_raw = entry.get("ack_ts")
            try:
                ack_ts_val = float(ack_ts_raw) if ack_ts_raw is not None else None
            except Exception:
                ack_ts_val = None
            if ack_ts_val is not None and ack_ts_val >= ts_val:
                continue

            if (now_ts - ts_val) < self._bypass_auto_quarantine_timeout_sec:
                continue

            result = await self.quarantine_client(ip)
            if result.get("success"):
                applied.append(ip)
                fail_closed_ips.add(ip)
                entry["ack_ts"] = now_ts
                entry["acknowledged_at"] = now_iso
                entry["auto_quarantined_at"] = now_iso
                by_ip[ip] = entry
                changed = True
                try:
                    self.record_fail_closed_trigger(
                        client_ip=ip,
                        domain=entry.get("domain"),
                        flow_id=entry.get("flow_id"),
                        ts=ts_val,
                        applied=True,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to persist auto-quarantine trigger for %s: %s", ip, exc
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
                        domain=entry.get("domain"),
                        flow_id=entry.get("flow_id"),
                        ts=ts_val,
                        applied=False,
                        error=err,
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to persist failed auto-quarantine trigger for %s: %s",
                        ip,
                        exc,
                    )

        if changed:
            state["by_ip"] = by_ip
            self._save_bypass_events_meta(state)

        if applied:
            logger.warning(
                "Auto-quarantine applied for unattended leak alerts: %s",
                ", ".join(applied),
            )
        if failed:
            logger.warning("Auto-quarantine failures: %s", failed)

        return {"checked": len(by_ip), "applied": applied, "failed": failed}

    def get_bypass_events(self) -> dict[str, dict]:
        """Get persisted last bypass event per IP (best-effort)."""
        state = self._load_bypass_events_meta()
        by_ip = state.get("by_ip", {})
        return by_ip if isinstance(by_ip, dict) else {}

    def acknowledge_bypass_event(self, client_ip: str) -> bool:
        ip = str(client_ip or "").strip()
        if not self._is_valid_ipv4(ip):
            return False
        state = self._load_bypass_events_meta()
        by_ip = state.get("by_ip", {})
        if not isinstance(by_ip, dict):
            by_ip = {}
        entry = by_ip.get(ip) if isinstance(by_ip.get(ip), dict) else {"ip": ip}
        now_ts = datetime.now(timezone.utc)
        entry["ack_ts"] = now_ts.timestamp()
        entry["acknowledged_at"] = now_ts.isoformat()
        by_ip[ip] = entry
        state["by_ip"] = by_ip
        self._save_bypass_events_meta(state)
        return True

    def get_bypass_history(self) -> dict[str, dict]:
        """Persistent per-device/per-channel bypass history (accumulated over time,
        survives reboots and firewall-counter resets). See process_bypass_events."""
        state = self._load_bypass_events_meta()
        hist = state.get("history", {})
        return hist if isinstance(hist, dict) else {}

    def clear_bypass_history(self) -> bool:
        """Reset the accumulated bypass history (does not touch live alerts)."""
        state = self._load_bypass_events_meta()
        state["history"] = {}
        self._save_bypass_events_meta(state)
        return True
