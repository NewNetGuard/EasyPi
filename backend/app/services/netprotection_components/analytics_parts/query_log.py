"""Analytics operations for NetProtection."""

import asyncio
import aiosqlite
import hashlib
import ipaddress
import json
import math
import os
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.netprotection_components.runtime_context import (
    FLOW_LOGGER_AVAILABLE,
    FLOW_REASON_PREFIX,
    FlowStatus,
    QueryType,
    logger,
)


class AnalyticsQueryLogMixin:
    _PRISM_ACTIVITY_READ_BYTES = 8 * 1024 * 1024
    _PRISM_ACTIVITY_MAX_LINE_BYTES = 512 * 1024
    _BROWSING_DNS_MAX_ROWS = 5000
    _BROWSING_DEDUPE_SECONDS = 10.0
    _BROWSING_CACHE_SECONDS = 30.0
    _BROWSING_FORCE_REFRESH_COOLDOWN_SECONDS = 10.0
    _BROWSING_CACHE_MAX_DEVICES = 128
    _BROWSING_EXACT_SERVICE_HOSTS = frozenset(
        {
            "g.whatsapp.net",
            "accounts.google.com",
            "graph.facebook.com",
            "inbox.google.com",
            "mail.google.com",
            "startup.mobile.yandex.net",
            "time.cloudflare.com",
        }
    )
    _BROWSING_SERVICE_SITES = frozenset(
        {
            "network-lc.ru",
            "yastatic.net",
            "simpalsid.com",
            "simpalsmedia.com",
        }
    )

    # Keep these rules on the analytics mixin that owns
    # ``_classify_block_source``.  They used to live on the monolithic
    # NetProtectionService class and were accidentally lost when analytics was
    # split into focused mixins.  A missing table must never make the complete
    # query log look empty.
    # Fallback for flow-log rows written before the engine recorded its
    # decisive reason. Matched against the evidence summary in this order.
    _BLOCK_SOURCE_RULES = (
        ("dga detected", ("dga", "DGA")),
        ("brand impersonation", ("homoglyph", "Brand spoof")),
        ("homoglyph", ("homoglyph", "Brand spoof")),
        ("parental control", ("parental", "Parental")),
        ("profile blacklist", ("profile", "Device rule")),
        ("profile whitelist", ("profile", "Device rule")),
        ("schedule block", ("schedule", "Schedule")),
        ("safesearch", ("safesearch", "SafeSearch")),
        ("streaming_blocker", ("app", "App block")),
        ("shadow_mode", ("shadow", "Shadow Mode")),
        ("ad-genesis", ("ad_ai", "Ad/Tracker AI")),
        ("device anomaly", ("behavioral", "Device anomaly")),
        ("newly-registered", ("nrd", "New (NRD)")),
        ("new domain", ("heuristic", "New domain")),
        # Older releases blocked on words in the domain name alone.
        ("known malicious", ("name", "Name check")),
        ("associated with malware", ("name", "Name check")),
        ("associated with phishing", ("name", "Name check")),
        ("categorized as", ("name", "Name check")),
        ("name suggests", ("name", "Name check")),
        ("looks machine-generated", ("name", "Name check")),
        ("suspicious indicators", ("heuristic", "Heuristics")),
        ("heuristics score", ("heuristic", "Heuristics")),
        ("heuristic", ("heuristic", "Heuristics")),
        ("cname cloaking", ("cname", "CNAME cloaking")),
        ("dns rebinding", ("rebinding", "DNS rebinding")),
        ("dns rewrite", ("rewrite", "DNS rewrite")),
        ("user blacklist", ("blacklist", "Your blacklist")),
        ("domain in blocklist", ("blocklist", "Blocklist")),
        ("blocklist", ("blocklist", "Blocklist")),
        ("user rule", ("rule", "User rule")),
        ("matcher", ("rule", "User rule")),
    )

    # The engine's decisive reason, recorded as "reason:<value>" in the flow
    # log's categories column. Authoritative whenever present.
    _BLOCK_REASON_SOURCES = {
        "blocklist": ("blocklist", "Blocklist"),
        "blacklist": ("blacklist", "Your blacklist"),
        "shadow_mode": ("shadow", "Shadow Mode"),
        "newly_registered": ("nrd", "New (NRD)"),
        "advertising": ("ad_ai", "Ad/Tracker AI"),
        "tracking": ("ad_ai", "Ad/Tracker AI"),
        "heuristics_block": ("heuristic", "Heuristics"),
        # The name check: a name shaped like a machine-generated one.
        "domain_anomaly": ("name", "Name check"),
        "suspicious_tld": ("heuristic", "Heuristics"),
        "dga_detected": ("dga", "DGA"),
        "homoglyph_detected": ("homoglyph", "Brand spoof"),
        "device_anomaly": ("behavioral", "Device anomaly"),
        "dns_tunneling": ("behavioral", "Traffic pattern"),
        "cname_cloaking": ("cname", "CNAME cloaking"),
        "dns_rebinding": ("rebinding", "DNS rebinding"),
        "malware": ("threat", "Threat intel"),
        "phishing": ("threat", "Threat intel"),
        "cryptomining": ("threat", "Threat intel"),
        "asn_reputation": ("threat", "Threat intel"),
        "dns_rewrite": ("rewrite", "DNS rewrite"),
        "rewrite_nxdomain": ("rewrite", "DNS rewrite"),
        "parental_control": ("parental", "Parental"),
        "age_restricted": ("parental", "Parental"),
        "bedtime_blocked": ("parental", "Parental"),
        "daily_limit": ("parental", "Parental"),
        "adult_content": ("parental", "Parental"),
        "schedule_blocked": ("schedule", "Schedule"),
        "profile_blacklist": ("profile", "Device rule"),
        "profile_blocked": ("profile", "Device rule"),
        "device_policy": ("profile", "Device rule"),
        "unknown_device": ("unknown_device", "Unknown device"),
        "app_blocked": ("app", "App block"),
        "safe_search": ("safesearch", "SafeSearch"),
        "shield_profile": ("profile", "Device rule"),
    }

    # Sources that an administrator enables for specific devices. They are not
    # part of the network-wide default blocking.
    DEVICE_RESTRICTION_SOURCES = frozenset(
        {"parental", "schedule", "profile", "unknown_device", "app", "safesearch"}
    )

    async def get_verdicts(
        self,
        offset: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        verdict_type: Optional[str] = None,
        client_ip: Optional[str] = None,
        today_only: bool = False,
        include_system: bool = True,
    ) -> Dict[str, Any]:
        """
        Get DNS verdict log directly from NetProtection's flow_log.db.

        Reads SQLite database written by NetProtection service.

        Args:
            today_only: Filter only today's entries (since midnight)
        """
        import aiosqlite

        db_path = self.flow_log_path

        if not db_path.exists():
            return {"data": [], "oldest": None, "total": 0}

        try:
            client_map = await self._build_flowlog_client_map()
            async with aiosqlite.connect(str(db_path)) as db:
                # Build query with filters
                where_clauses = []
                params = []

                if today_only:
                    where_clauses.append(
                        "datetime(timestamp) >= datetime('now', 'start of day')"
                    )

                if search:
                    where_clauses.append("domain LIKE ?")
                    params.append(f"%{search}%")

                if client_ip:
                    where_clauses.append("client_id = ?")
                    params.append(self._hash_client_ip(client_ip))

                if not include_system:
                    loopback_ids = (
                        self._hash_client_ip("127.0.0.1"),
                        self._hash_client_ip("::1"),
                        self._hash_client_ip("::ffff:127.0.0.1"),
                    )
                    where_clauses.append("client_id NOT IN (?, ?, ?)")
                    params.extend(loopback_ids)

                if verdict_type:
                    # flow_log.db stores both status (allowed/blocked/redirected) and verdict (allow/deny/redirect/observe).
                    # The NetProtection API uses verdict_type, so filter by verdict for correctness (e.g. "observe").
                    where_clauses.append("verdict = ?")
                    params.append(verdict_type)

                where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

                # Get total count
                count_sql = f"SELECT COUNT(*) FROM flow_log WHERE {where_sql}"
                async with db.execute(count_sql, params) as cursor:
                    row = await cursor.fetchone()
                    total = row[0] if row else 0

                # Get data with pagination
                data_sql = f"""
                    SELECT id, flow_id, timestamp, domain, query_type, client_id,
                           device_id, status, verdict, confidence, response_ips,
                           response_code, latency_ms, cached, upstream_used,
                           evidence_summary, matcher_id, categories
                    FROM flow_log
                    WHERE {where_sql}
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """
                params.extend([limit, offset])

                verdicts = []
                async with db.execute(data_sql, params) as cursor:
                    async for row in cursor:
                        client_id = row[5]
                        client_info = client_map.get(client_id, {})
                        evidence_summary = row[15] or ""

                        # NetProtection API contract expects evidence as a structured list.
                        evidence_items = self._evidence_summary_to_evidence(
                            evidence_summary
                        )
                        source_key, source_label = self._classify_block_source(
                            evidence_summary, row[8], row[17] or ""
                        )

                        verdicts.append(
                            {
                                "id": row[0],
                                "flow_id": row[1],
                                "time": row[2],
                                # Back-compat alias used by some legacy network-activity endpoints
                                "timestamp": row[2],
                                "domain": row[3],
                                "query_type": row[4],
                                # Back-compat for older internal consumers
                                "client": client_id,
                                "client_id": client_id,
                                # Best-effort attribution (derived from current clients.json)
                                "client_ip": client_info.get("client_ip"),
                                "client_name": client_info.get("client_name"),
                                "device_id": row[6],
                                "status": row[7],
                                "verdict": row[8],
                                "confidence": row[9],
                                # Raw response IPs are stored as a comma-separated string in flow_log.db.
                                # Keep the old "response" field, but also expose "response_ips" as a list.
                                "response": row[10],
                                "response_ips": [
                                    ip.strip()
                                    for ip in (row[10] or "").split(",")
                                    if ip and ip.strip()
                                ],
                                "response_code": row[11],
                                "latency_ms": row[12],
                                "response_time_ms": row[12],
                                "cached": bool(row[13])
                                if row[13] is not None
                                else False,
                                "upstream": row[14],
                                "upstream_used": row[14],
                                "evidence": evidence_items,
                                "evidence_summary": evidence_summary,
                                "block_source": source_label,
                                "block_source_key": source_key,
                                "matcher_id": row[16],
                            }
                        )

                return {
                    "data": verdicts,
                    "oldest": verdicts[-1]["time"] if verdicts else None,
                    "total": total,
                }
        except Exception as e:
            logger.error(f"Failed to read flow_log.db: {e}")
            return {"data": [], "oldest": None, "total": 0}

    async def get_prism_device_activity(
        self, client_ip: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return recent TLS/QUIC host names already observed by PRISM.

        This complements the DNS Query Log when a browser uses encrypted DNS,
        cached answers, or another resolver. Reading is bounded and performed
        off the event loop; no packet capture or protection policy is changed.
        """
        try:
            normalized_ip = str(ipaddress.ip_address(str(client_ip).strip()))
        except ValueError:
            return []

        safe_limit = max(1, min(int(limit), 200))
        path = getattr(
            self,
            "prism_flowgraph_path",
            Path("/var/lib/easypi/prism/flowgraph.jsonl"),
        )
        try:
            return await asyncio.to_thread(
                self._read_prism_device_activity,
                Path(path),
                normalized_ip,
                safe_limit,
            )
        except Exception as exc:
            logger.warning(
                "Failed to read PRISM device activity: %s", type(exc).__name__
            )
            return []

    async def get_prism_activity(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent PRISM TLS/QUIC observations across LAN devices."""
        safe_limit = max(1, min(int(limit), 200))
        path = getattr(
            self,
            "prism_flowgraph_path",
            Path("/var/lib/easypi/prism/flowgraph.jsonl"),
        )
        try:
            return await asyncio.to_thread(
                self._read_prism_device_activity,
                Path(path),
                None,
                safe_limit,
            )
        except Exception as exc:
            logger.warning("Failed to read PRISM activity: %s", type(exc).__name__)
            return []

    async def get_browsing_activity(
        self,
        client_ip: str,
        limit: int = 100,
        force_refresh: bool = False,
        device_identity: str | None = None,
        since_epoch: float | None = None,
    ) -> List[Dict[str, Any]]:
        """Return a device's bounded DNS/TLS domain-connection journal."""
        try:
            normalized_ip = str(ipaddress.ip_address(str(client_ip).strip()))
        except ValueError:
            return []
        safe_limit = max(1, min(int(limit), 200))
        try:
            safe_since = max(0.0, float(since_epoch or 0.0))
        except (TypeError, ValueError, OverflowError):
            return []
        identity = str(device_identity or normalized_ip).strip().lower()[:128]
        cache_key = f"{normalized_ip}|{identity}|{safe_since:.3f}"

        cache = self._browsing_activity_cache
        now = time.monotonic()
        cached = cache.get(cache_key)
        if (
            not force_refresh
            and cached is not None
            and now - cached[0] < self._BROWSING_CACHE_SECONDS
        ):
            return self._copy_browsing_rows(cached[1], safe_limit)

        async with self._browsing_activity_cache_lock:
            now = time.monotonic()
            cached = cache.get(cache_key)
            last_forced = self._browsing_activity_forced_refresh.get(cache_key, 0.0)
            if (
                force_refresh
                and cached is not None
                and now - last_forced
                < self._BROWSING_FORCE_REFRESH_COOLDOWN_SECONDS
            ):
                return self._copy_browsing_rows(cached[1], safe_limit)
            if (
                not force_refresh
                and cached is not None
                and now - cached[0] < self._BROWSING_CACHE_SECONDS
            ):
                return self._copy_browsing_rows(cached[1], safe_limit)

            activity = await self._build_browsing_activity(
                normalized_ip, safe_since
            )
            completed_at = time.monotonic()
            cache[cache_key] = (completed_at, activity)
            if force_refresh:
                self._browsing_activity_forced_refresh[cache_key] = completed_at
            if len(cache) > self._BROWSING_CACHE_MAX_DEVICES:
                oldest = min(cache, key=lambda address: cache[address][0])
                cache.pop(oldest, None)
                self._browsing_activity_forced_refresh.pop(oldest, None)
            return self._copy_browsing_rows(activity, safe_limit)

    async def _build_browsing_activity(
        self, normalized_ip: str, since_epoch: float
    ) -> List[Dict[str, Any]]:
        """Build a fresh domain-connection journal for one normalized address."""

        dns_activity = await self._read_dns_browsing_activity(
            normalized_ip, since_epoch
        )
        path = getattr(
            self,
            "prism_flowgraph_path",
            Path("/var/lib/easypi/prism/flowgraph.jsonl"),
        )
        try:
            prism_rows = await asyncio.to_thread(
                self._read_prism_device_activity,
                Path(path),
                normalized_ip,
                0,
                False,
                since_epoch,
            )
        except Exception as exc:
            logger.warning("Failed to read PRISM browsing context: %s", type(exc).__name__)
            prism_rows = []

        prism_activity = []
        for row in prism_rows:
            candidate = self._prism_domain_connection(row)
            if candidate is not None:
                prism_activity.append(candidate)

        return self._merge_domain_connections(dns_activity + prism_activity, 200)

    @staticmethod
    def _copy_browsing_rows(
        rows: List[Dict[str, Any]], limit: int
    ) -> List[Dict[str, Any]]:
        copied: List[Dict[str, Any]] = []
        counts = {"site": 0, "service": 0}
        for row in rows:
            traffic_class = str(row.get("traffic_class") or "")
            if traffic_class not in counts or counts[traffic_class] >= limit:
                continue
            copied.append(dict(row))
            counts[traffic_class] += 1
        return copied

    async def _read_dns_browsing_activity(
        self, client_ip: str, since_epoch: float = 0.0
    ) -> List[Dict[str, Any]]:
        if not self.flow_log_path.exists():
            return []
        client_id = self._hash_client_ip(client_ip)
        since_local = datetime.fromtimestamp(since_epoch).isoformat()
        try:
            async with aiosqlite.connect(str(self.flow_log_path)) as db:
                async with db.execute(
                    """
                    SELECT timestamp, domain, status
                    FROM (
                        SELECT timestamp, domain, status
                        FROM flow_log
                        WHERE client_id = ?
                          AND datetime(timestamp) >= datetime('now', '-24 hours')
                          AND datetime(timestamp) >= datetime(?)
                        ORDER BY timestamp DESC
                        LIMIT ?
                    )
                    ORDER BY timestamp ASC
                    """,
                    (client_id, since_local, self._BROWSING_DNS_MAX_ROWS),
                ) as cursor:
                    rows = [row async for row in cursor]
        except (OSError, aiosqlite.Error) as exc:
            logger.warning("Failed to read DNS browsing context: %s", type(exc).__name__)
            return []

        normalized_rows: List[tuple[float, str, str]] = []
        for timestamp, domain, status in rows:
            try:
                epoch = datetime.fromisoformat(str(timestamp)).timestamp()
            except (TypeError, ValueError, OverflowError):
                continue
            host = str(domain or "").strip().lower().rstrip(".")
            if not host or len(host) > 253:
                continue
            normalized_status = str(status or "").strip().lower()
            # A/AAAA pairs often create identical adjacent rows. Keep a
            # successful result if it immediately follows a failed attempt.
            if (
                normalized_rows
                and host == normalized_rows[-1][1]
                and epoch - normalized_rows[-1][0] <= 0.75
            ):
                if (
                    normalized_rows[-1][2]
                    not in {"allowed", "cached", "upstream"}
                    and normalized_status in {"allowed", "cached", "upstream"}
                ):
                    normalized_rows[-1] = (epoch, host, normalized_status)
                continue
            normalized_rows.append((epoch, host, normalized_status))

        return self._dns_domain_connections(normalized_rows)

    def _dns_domain_connections(
        self, rows: List[tuple[float, str, str]]
    ) -> List[Dict[str, Any]]:
        connections: List[Dict[str, Any]] = []
        for timestamp, host, status in rows:
            # Only a successful upstream/cached result establishes that DNS
            # resolution completed. Failed, blocked and redirected requests
            # remain visible in the technical Query Log.
            if status not in {"allowed", "cached", "upstream"}:
                continue
            normalized = self._normalize_connection_host(host)
            if normalized is None:
                continue
            domain = self._registrable_domain(normalized)
            connections.append(
                {
                    "id": "domain-dns-"
                    + hashlib.sha256(
                        f"{timestamp}|{normalized}".encode()
                    ).hexdigest()[:20],
                    "timestamp_epoch": timestamp,
                    "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                    "domain": domain,
                    "host": normalized,
                    "source": "dns",
                    "traffic_class": self._domain_connection_class(
                        normalized, domain
                    ),
                }
            )
        return connections

    def _prism_domain_connection(
        self, row: Dict[str, Any]
    ) -> Dict[str, Any] | None:
        host = self._normalize_connection_host(row.get("domain"))
        if host is None:
            return None
        try:
            timestamp = datetime.fromisoformat(str(row.get("timestamp"))).timestamp()
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(timestamp) or timestamp <= 0:
            return None
        domain = self._registrable_domain(host)
        return {
            "id": "domain-tls-"
            + hashlib.sha256(f"{timestamp}|{host}".encode()).hexdigest()[:20],
            "timestamp_epoch": timestamp,
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "domain": domain,
            "host": host,
            "source": "tls",
            "traffic_class": self._domain_connection_class(host, domain),
        }

    @staticmethod
    def _normalize_connection_host(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        host = value.strip().lower().rstrip(".")
        if not host or len(host) > 253 or "." not in host:
            return None
        if host.endswith((".arpa", ".local", ".lan", ".home")):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char in "-_" for char in label)
            for label in labels
        ):
            return None
        return host

    def _domain_connection_class(self, host: str, domain: str) -> str:
        if (
            host in self._BROWSING_EXACT_SERVICE_HOSTS
            or domain in self._BROWSING_SERVICE_SITES
        ):
            return "service"
        return "site" if self._classify_visited_domain(host) == "site" else "service"

    def _merge_domain_connections(
        self, activity: List[Dict[str, Any]], limit: int
    ) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        for event in sorted(
            activity, key=lambda item: float(item.get("timestamp_epoch") or 0.0)
        ):
            timestamp = float(event.get("timestamp_epoch") or 0.0)
            previous = next(
                (
                    item
                    for item in reversed(merged)
                    if item.get("host") == event.get("host")
                    and timestamp - float(item.get("merge_anchor_epoch") or 0.0)
                    <= self._BROWSING_DEDUPE_SECONDS
                ),
                None,
            )
            if previous is None:
                merged.append({**event, "merge_anchor_epoch": timestamp})
                continue
            sources = set(str(previous.get("source") or "").split("+"))
            sources.add(str(event.get("source") or ""))
            previous["source"] = "+".join(
                source for source in ("dns", "tls") if source in sources
            )
            previous["timestamp_epoch"] = timestamp
            previous["timestamp"] = event.get("timestamp")

        ordered = sorted(
            merged,
            key=lambda item: float(item.get("timestamp_epoch") or 0.0),
            reverse=True,
        )
        output: List[Dict[str, Any]] = []
        counts = {"site": 0, "service": 0}
        for item in ordered:
            traffic_class = str(item.get("traffic_class") or "")
            if traffic_class not in counts or counts[traffic_class] >= limit:
                continue
            output.append(item)
            counts[traffic_class] += 1
        for item in output:
            item.pop("timestamp_epoch", None)
            item.pop("merge_anchor_epoch", None)
        return output

    @classmethod
    def _read_prism_device_activity(
        cls,
        path: Path,
        client_ip: str | None,
        limit: int,
        include_browsing_meta: bool = False,
        since_epoch: float = 0.0,
    ) -> List[Dict[str, Any]]:
        remaining_bytes = cls._PRISM_ACTIVITY_READ_BYTES
        rows_by_flow: Dict[str, Dict[str, Any]] = {}

        # The active file is newest. If it has just rotated, spend the remaining
        # bounded read budget on .1 so a visit does not disappear at rotation.
        for candidate in (path, path.with_suffix(path.suffix + ".1")):
            if remaining_bytes <= 0:
                break
            descriptor = -1
            try:
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(candidate, flags)
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                read_bytes = min(metadata.st_size, remaining_bytes)
                start = max(0, metadata.st_size - read_bytes)
                with os.fdopen(descriptor, "rb") as source:
                    descriptor = -1
                    source.seek(start)
                    if start:
                        source.readline()
                    for raw in source:
                        if len(raw) > cls._PRISM_ACTIVITY_MAX_LINE_BYTES:
                            continue
                        try:
                            value = json.loads(raw)
                            if not isinstance(value, dict):
                                continue
                            if value.get("event") != "flow_assessment":
                                continue
                            try:
                                observed_client_ip = str(
                                    ipaddress.ip_address(
                                        str(value.get("client_ip") or "").strip()
                                    )
                                )
                            except ValueError:
                                continue
                            observed_address = ipaddress.ip_address(observed_client_ip)
                            if (
                                observed_address.is_loopback
                                or observed_address.is_unspecified
                            ):
                                continue
                            if client_ip is not None and observed_client_ip != client_ip:
                                continue
                            raw_server_name = value.get("server_name")
                            if not isinstance(raw_server_name, str):
                                continue
                            server_name = raw_server_name.strip()
                            if not server_name or len(server_name) > 253:
                                continue
                            raw_timestamp = value.get("timestamp", 0.0)
                            if isinstance(raw_timestamp, bool):
                                continue
                            timestamp = float(value.get("timestamp", 0.0))
                            if not math.isfinite(timestamp) or timestamp <= 0:
                                continue
                            if timestamp < since_epoch:
                                continue
                            flow = value.get("flow")
                            if not isinstance(flow, str) or not flow or len(flow) > 512:
                                continue
                            raw_session = value.get("session_id")
                            if not isinstance(raw_session, int) or isinstance(
                                raw_session, bool
                            ):
                                continue
                            raw_revision = value.get("revision", 0)
                            if not isinstance(raw_revision, int) or isinstance(
                                raw_revision, bool
                            ):
                                continue
                            revision = int(raw_revision)
                            if revision < 0 or revision > 1_000_000:
                                continue
                            key = f"{flow}|{raw_session}"
                            previous = rows_by_flow.get(key)
                            if previous:
                                previous_revision = int(previous.get("revision", 0))
                                previous_timestamp = float(
                                    previous.get("timestamp_epoch", 0.0)
                                )
                                if revision < previous_revision or (
                                    revision == previous_revision
                                    and timestamp <= previous_timestamp
                                ):
                                    continue
                            observed_at = datetime.fromtimestamp(timestamp).isoformat()
                            rows_by_flow[key] = {
                                "timestamp_epoch": timestamp,
                                "timestamp": observed_at,
                                "domain": server_name,
                                "source": "prism",
                                "queryType": "QUIC"
                                if flow.startswith("udp:")
                                else "TLS",
                                "status": "observed",
                                "reason": "Hostname observed in encrypted traffic by Prisma DPI",
                                "client_ip": observed_client_ip,
                                "revision": revision,
                                "id": "prism-"
                                + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20],
                            }
                            if include_browsing_meta:
                                features = value.get("features")
                                if not isinstance(features, dict):
                                    features = {}
                                rows_by_flow[key]["_timestamp_epoch"] = timestamp
                                rows_by_flow[key]["_browsing"] = {
                                    "root_server_name": features.get("root_server_name")
                                    is True,
                                    "compact_client_hello": features.get(
                                        "compact_client_hello"
                                    )
                                    is True,
                                    "client_payload_bytes": features.get(
                                        "client_payload_bytes", 0
                                    ),
                                    "server_payload_bytes": features.get(
                                        "server_payload_bytes", 0
                                    ),
                                    "first_client_application_record": features.get(
                                        "first_client_application_record", 0
                                    ),
                                    "first_server_application_record": features.get(
                                        "first_server_application_record", 0
                                    ),
                                    "session_flow_count": features.get(
                                        "session_flow_count", 0
                                    ),
                                    "session_distinct_sni": features.get(
                                        "session_distinct_sni", 0
                                    ),
                                    "burst_flow_count": features.get(
                                        "burst_flow_count", 0
                                    ),
                                    "prism_confidence": value.get("confidence", 0.0),
                                }
                        except (OSError, OverflowError, TypeError, ValueError):
                            # JSON may be syntactically valid but have a corrupt
                            # shape or field. One record must not hide the rest.
                            continue
                remaining_bytes -= read_bytes
            except (FileNotFoundError, PermissionError, OSError):
                continue
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        rows = sorted(
            rows_by_flow.values(),
            key=lambda item: float(item["timestamp_epoch"]),
            reverse=True,
        )
        # A zero limit is used by the domain journal: the file read is already
        # capped by bytes, and classification must happen before per-tab limits
        # so noisy service traffic cannot displace real sites.
        if limit > 0:
            rows = rows[:limit]
        for row in rows:
            row.pop("timestamp_epoch", None)
            row.pop("revision", None)
        return rows

    def _collect_lan_client_ips(self) -> set:
        """Best-effort set of current LAN IPv4 client addresses.

        Sources: this host (loopback + primary LAN IP) and the kernel ARP cache
        (/proc/net/arp). Used to recover client_id (sha256(ip)[:16]) -> IP
        attribution for the Query Log on read, WITHOUT storing raw client IPs in
        the flow log. Pure file/socket reads only (no subprocess) and cached
        briefly; callers must still run it off the event loop.
        """
        import time as _t

        cached = getattr(self, "_lan_ips_cache", None)
        if cached and (_t.time() - cached[0]) < 30:
            return cached[1]

        import ipaddress

        ips: set = {"127.0.0.1"}

        # This host's primary LAN IP (the box resolves DNS too).
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("192.0.2.1", 9))  # TEST-NET-1; no packets are actually sent
                ips.add(s.getsockname()[0])
            finally:
                s.close()
        except Exception:
            pass

        # ARP table: "IP  HWtype  Flags  HWaddr  Mask  Device"
        try:
            arp_path = Path("/proc/net/arp")
            if arp_path.exists():
                for line in arp_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        try:
                            ipaddress.ip_address(parts[0])
                            ips.add(parts[0])
                        except ValueError:
                            pass
        except Exception:
            pass

        self._lan_ips_cache = (_t.time(), ips)
        return ips

    async def _build_flowlog_client_map(self) -> Dict[str, Dict[str, str]]:
        """
        Build best-effort mapping from flow_log client_id -> client_ip/client_name.

        flow_log.db stores a hashed client identifier (sha256(ip)[:16] in current NetProtection builds).
        We recover the human-readable client IP by hashing the currently configured device IPs from
        data/netprotection/clients.json. This keeps flow_log privacy properties while making the
        Query Log usable.
        """
        import ipaddress

        try:
            clients_data = await self.get_clients()
            clients = (
                clients_data.get("clients", [])
                if isinstance(clients_data, dict)
                else []
            )
        except Exception:
            clients = []

        mapping: Dict[str, Dict[str, str]] = {}

        for client in clients:
            if not isinstance(client, dict):
                continue

            name = str(client.get("name") or "").strip()
            ids = client.get("ids") or []
            if isinstance(ids, str):
                ids = [ids]
            ip_candidates = []

            ip_field = client.get("ip")
            if ip_field:
                ip_candidates.append(ip_field)

            for v in ids:
                if v:
                    ip_candidates.append(v)

            for candidate in ip_candidates:
                try:
                    ip = str(candidate).strip()
                    if not ip:
                        continue
                    ipaddress.ip_address(ip)
                except Exception:
                    continue

                cid = self._hash_client_ip(ip)
                if cid not in mapping:
                    mapping[cid] = {"client_ip": ip, "client_name": name or ip}

        # Named devices from the Devices inventory (devices.json), if any.
        try:
            for device in await self.get_devices():
                if not isinstance(device, dict):
                    continue
                ip = str(device.get("ip") or "").strip()
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    continue
                cid = self._hash_client_ip(ip)
                if cid not in mapping:
                    dev_name = str(device.get("name") or "").strip()
                    mapping[cid] = {"client_ip": ip, "client_name": dev_name or ip}
        except Exception:
            pass

        # Live LAN inventory (ARP/neighbor table + this host). Resolves devices
        # that were never manually named, so the Query Log shows the real client
        # IP instead of the privacy hash. Named entries above keep priority.
        for ip in await asyncio.to_thread(self._collect_lan_client_ips):
            cid = self._hash_client_ip(ip)
            if cid not in mapping:
                mapping[cid] = {"client_ip": ip, "client_name": ip}

        return mapping

    def _evidence_summary_to_evidence(
        self, evidence_summary: str
    ) -> List[Dict[str, Any]]:
        """
        Convert stored evidence_summary string into NetProtection API Evidence objects.

        NetProtection flow log stores a compact summary for privacy. The UI expects a list of
        evidence entries. We expose the summary as evidence items so the badge/reason field works.
        """
        summary = (evidence_summary or "").strip()
        if not summary:
            return []

        parts = [p.strip() for p in summary.split(";") if p.strip()]
        items: List[Dict[str, Any]] = []
        for p in parts[:10]:
            # Use the signal itself as the "source" so UI can show something meaningful.
            items.append({"source": p, "signal": p})
        return items

    def _classify_block_source(
        self, evidence_summary: str, verdict: str, categories: str = ""
    ) -> tuple[str, str]:
        """Return (source_key, source_label) explaining why a query got its verdict.

        ``categories`` is the flow log column; when it carries the engine's
        recorded reason, that reason decides. Older rows fall back to the
        evidence summary.
        """
        for item in (categories or "").split(","):
            item = item.strip()
            if item.startswith(FLOW_REASON_PREFIX):
                known = self._BLOCK_REASON_SOURCES.get(item[len(FLOW_REASON_PREFIX):])
                if known:
                    return known
        s = (evidence_summary or "").lower()
        for needle, (key, label) in self._BLOCK_SOURCE_RULES:
            if needle in s:
                return key, label
        v = (verdict or "").lower()
        if v in ("deny", "block"):
            return "blocklist", "Blocked"
        if v == "redirect":
            return "rewrite", "Redirected"
        if v == "observe":
            return "behavioral", "Watched"
        return "", ""

    def _hash_client_ip(self, client_ip: str) -> str:
        """Match NetProtection flow log hashing (first 16 chars of SHA-256)."""
        if not client_ip:
            return "unknown"
        return hashlib.sha256(client_ip.encode()).hexdigest()[:16]

    async def get_client_activity(
        self, client_ips: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Get aggregated activity for a list of client IPs from flow_log.db."""
        if not client_ips:
            return {}

        if not self.flow_log_path.exists():
            return {}

        # Build client_id mapping
        id_to_ip: Dict[str, str] = {}
        for ip in client_ips:
            if ip:
                id_to_ip[self._hash_client_ip(ip)] = ip

        if not id_to_ip:
            return {}

        placeholders = ",".join(["?"] * len(id_to_ip))
        ids = list(id_to_ip.keys())

        results: Dict[str, Dict[str, Any]] = {
            ip: {
                "requestsCount": 0,
                "blockedCount": 0,
                "allowedCount": 0,
                "lastSeen": None,
            }
            for ip in id_to_ip.values()
        }

        try:
            async with aiosqlite.connect(str(self.flow_log_path)) as db:
                # Counts by status
                count_sql = f"""
                    SELECT client_id, status, COUNT(*)
                    FROM flow_log
                    WHERE client_id IN ({placeholders})
                    GROUP BY client_id, status
                """
                async with db.execute(count_sql, ids) as cursor:
                    async for row in cursor:
                        client_id, status, count = row[0], row[1], row[2]
                        ip = id_to_ip.get(client_id)
                        if not ip:
                            continue
                        results[ip]["requestsCount"] += count
                        if status == "blocked":
                            results[ip]["blockedCount"] += count
                        else:
                            results[ip]["allowedCount"] += count

                # Last seen timestamp
                last_sql = f"""
                    SELECT client_id, MAX(timestamp)
                    FROM flow_log
                    WHERE client_id IN ({placeholders})
                    GROUP BY client_id
                """
                async with db.execute(last_sql, ids) as cursor:
                    async for row in cursor:
                        client_id, last_seen = row[0], row[1]
                        ip = id_to_ip.get(client_id)
                        if ip:
                            results[ip]["lastSeen"] = last_seen
        except Exception as e:
            logger.error(f"Failed to aggregate client activity: {e}")
            return {}

        return results

    def _flow_entry_to_dict(self, entry: Any) -> Dict[str, Any]:
        """Convert FlowEntry to verdict dict format."""
        evidence_summary = getattr(entry, "evidence_summary", "") or ""
        return {
            "flow_id": entry.flow_id,
            "time": entry.timestamp.isoformat(),
            "timestamp": entry.timestamp.isoformat(),
            "domain": entry.domain,
            "query_type": entry.query_type.value
            if hasattr(entry.query_type, "value")
            else str(entry.query_type),
            "client": entry.client_id,
            "client_id": entry.client_id,
            "device_id": entry.device_id,
            "status": entry.status.value
            if hasattr(entry.status, "value")
            else str(entry.status),
            "verdict": entry.verdict,
            "confidence": entry.confidence,
            "response": entry.response_ips,
            "response_ips": entry.response_ips,
            "response_code": entry.response_code,
            "latency_ms": entry.latency_ms,
            "response_time_ms": entry.latency_ms,
            "cached": entry.cached,
            "upstream": entry.upstream_used,
            "upstream_used": entry.upstream_used,
            "evidence": self._evidence_summary_to_evidence(evidence_summary),
            "evidence_summary": evidence_summary,
            "matcher_id": entry.matcher_id,
            "categories": entry.categories,
        }

    async def get_verdict_by_flow_id(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Get single verdict by flow ID."""
        # Use FlowLogger if available
        if self._flow_logger:
            try:
                entry = await self._flow_logger.get_flow(flow_id)
                if entry:
                    return self._flow_entry_to_dict(entry)
            except Exception as e:
                logger.error(f"FlowLogger get_flow failed: {e}")

        # Fallback to in-memory
        for v in self._recent_verdicts:
            if v.get("flow_id") == flow_id:
                return v
        return None

    def record_verdict(self, verdict: Dict[str, Any]) -> None:
        """
        Record a new verdict (called by DNS engine).

        Stores in both FlowLogger (persistent) and in-memory buffer.
        """
        # Store in FlowLogger if available
        if self._flow_logger and FLOW_LOGGER_AVAILABLE:
            try:
                # Map verdict dict to FlowEntry
                status_map = {
                    "deny": FlowStatus.BLOCKED,
                    "allow": FlowStatus.ALLOWED,
                    "redirect": FlowStatus.REDIRECTED,
                    "observe": FlowStatus.ALLOWED,
                }

                qtype_map = {
                    "A": QueryType.A,
                    "AAAA": QueryType.AAAA,
                    "CNAME": QueryType.CNAME,
                    "MX": QueryType.MX,
                    "TXT": QueryType.TXT,
                    "NS": QueryType.NS,
                    "PTR": QueryType.PTR,
                    "SOA": QueryType.SOA,
                    "SRV": QueryType.SRV,
                }

                self._flow_logger.log_flow(
                    flow_id=verdict.get(
                        "flow_id", f"flow-{datetime.now().timestamp()}"
                    ),
                    domain=verdict.get("domain", "unknown"),
                    client_ip=verdict.get("client", "0.0.0.0"),
                    query_type=qtype_map.get(
                        verdict.get("query_type", "A"), QueryType.A
                    ),
                    device_id=verdict.get("device_id"),
                    status=status_map.get(
                        verdict.get("verdict", "allow"), FlowStatus.ALLOWED
                    ),
                    verdict=verdict.get("verdict", "allow"),
                    confidence=verdict.get("confidence", 100),
                    response_ips=verdict.get("response", []),
                    response_code=verdict.get("response_code", "NOERROR"),
                    latency_ms=verdict.get("latency_ms", 0.0),
                    cached=verdict.get("cached", False),
                    upstream_used=verdict.get("upstream"),
                    evidence_summary=verdict.get("evidence", ""),
                    matcher_id=verdict.get("matcher_id"),
                    categories=verdict.get("categories", []),
                )
            except Exception as e:
                logger.error(f"FlowLogger record failed: {e}")

        # Also store in in-memory buffer (for immediate access)
        self._recent_verdicts.insert(0, verdict)
        if len(self._recent_verdicts) > self._max_verdicts:
            self._recent_verdicts = self._recent_verdicts[: self._max_verdicts]

        # Update stats
        self._stats["total_queries"] += 1
        if verdict.get("verdict") == "deny":
            self._stats["blocked_queries"] += 1
        else:
            self._stats["allowed_queries"] += 1

    async def get_query_log_stats(self) -> Dict[str, Any]:
        """Get query log statistics directly from flow_log.db."""
        import aiosqlite

        db_path = self.flow_log_path

        if not db_path.exists():
            return {
                "total_logged": 0,
                "storage_total": 0,
                "blocked_total": 0,
                "allowed_total": 0,
            }

        try:
            async with aiosqlite.connect(str(db_path)) as db:
                # Total entries
                async with db.execute("SELECT COUNT(*) FROM flow_log") as cursor:
                    row = await cursor.fetchone()
                    total = row[0] if row else 0

                # Blocked entries
                async with db.execute(
                    "SELECT COUNT(*) FROM flow_log WHERE status = 'blocked'"
                ) as cursor:
                    row = await cursor.fetchone()
                    blocked = row[0] if row else 0

                # Allowed entries
                async with db.execute(
                    "SELECT COUNT(*) FROM flow_log WHERE status = 'allowed'"
                ) as cursor:
                    row = await cursor.fetchone()
                    allowed = row[0] if row else 0

                return {
                    "total_logged": total,
                    "storage_total": total,
                    "blocked_total": blocked,
                    "allowed_total": allowed,
                }
        except Exception as e:
            logger.error(f"Failed to get query log stats: {e}")
            return {
                "total_logged": 0,
                "storage_total": 0,
                "blocked_total": 0,
                "allowed_total": 0,
            }

    async def clear_query_log(self, older_than_days: int = 0) -> int:
        """
        Clear query log entries.

        Args:
            older_than_days: Clear entries older than this (0 = clear all, max 90)

        Returns:
            Number of entries cleared
        """
        # Cap to prevent retention bypass
        if older_than_days > 90:
            older_than_days = 90

        cleared = 0

        if self._flow_logger:
            try:
                if older_than_days > 0:
                    cleared = await self._flow_logger._storage.cleanup_old_entries(
                        older_than_days
                    )
                else:
                    # Clear all - reinitialize storage
                    await self._flow_logger._storage.close()
                    if self.flow_log_path.exists():
                        self.flow_log_path.unlink()
                    await self._flow_logger._storage.initialize()
                    cleared = len(self._recent_verdicts)
            except Exception as e:
                logger.error(f"FlowLogger clear failed: {e}")

        # Clear in-memory buffer
        if older_than_days == 0:
            self._recent_verdicts.clear()

        return cleared

    async def update_query_log_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update query log configuration.

        Args:
            config: Dict with enabled, store_evidence, store_response_ips, retention_days

        Returns:
            Updated configuration
        """
        # Update in-memory config
        if "enabled" in config:
            self._query_log_config["enabled"] = config["enabled"]
            if self._flow_logger:
                self._flow_logger.enabled = config["enabled"]

        if "store_evidence" in config:
            self._query_log_config["store_evidence"] = config["store_evidence"]
            if self._flow_logger:
                self._flow_logger._store_evidence = config["store_evidence"]

        if "store_response_ips" in config:
            self._query_log_config["store_response_ips"] = config["store_response_ips"]
            if self._flow_logger:
                self._flow_logger._store_response_ips = config["store_response_ips"]

        if "retention_days" in config:
            retention = min(config["retention_days"], 90)  # Cap at 90
            self._query_log_config["retention_days"] = retention
            if self._flow_logger:
                self._flow_logger._retention_days = retention

        # Persist to file
        config_file = self.data_dir / "query_log_config.json"
        try:
            config_file.write_text(json.dumps(self._query_log_config, indent=2))
        except Exception as e:
            logger.error(f"Failed to save query log config: {e}")

        return self._query_log_config
