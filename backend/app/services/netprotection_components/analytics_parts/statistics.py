"""Analytics operations for NetProtection."""

import asyncio
import aiosqlite
import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List

from app.services.netprotection_components.runtime_context import (
    logger,
)


class AnalyticsStatisticsMixin:
    async def get_mobile_client_stats(self, client_ip: str) -> Dict[str, Any]:
        """Return today's local-time DNS statistics for one authenticated phone."""
        return await self.get_mobile_client_stats_by_id(self._hash_client_ip(client_ip))

    async def get_mobile_client_stats_by_id(self, client_id: str) -> Dict[str, Any]:
        """Return today's DNS statistics for one anonymized PRISM client."""
        empty = {
            "num_dns_queries": 0,
            "num_blocked_filtering": 0,
            "dns_queries": [0] * 24,
            "blocked_filtering": [0] * 24,
            "top_blocked_domains": {},
        }
        if not self.flow_log_path.exists():
            return empty

        if not re.fullmatch(r"[0-9a-f]{16}", client_id):
            return empty
        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                db.row_factory = aiosqlite.Row
                today = (
                    "datetime(timestamp) >= date('now', 'localtime') "
                    "AND datetime(timestamp) < date('now', 'localtime', '+1 day')"
                )
                async with db.execute(
                    "SELECT COUNT(*) AS total, "
                    "SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) AS blocked "
                    f"FROM flow_log WHERE client_id = ? AND {today}",
                    (client_id,),
                ) as cursor:
                    row = await cursor.fetchone()
                    total = int(row["total"] or 0) if row else 0
                    blocked = int(row["blocked"] or 0) if row else 0

                hourly = {hour: {"total": 0, "blocked": 0} for hour in range(24)}
                async with db.execute(
                    "SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hour, "
                    "COUNT(*) AS total, "
                    "SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) AS blocked "
                    f"FROM flow_log WHERE client_id = ? AND {today} "
                    "GROUP BY hour ORDER BY hour",
                    (client_id,),
                ) as cursor:
                    async for row in cursor:
                        hour = int(row["hour"])
                        if hour in hourly:
                            hourly[hour] = {
                                "total": int(row["total"] or 0),
                                "blocked": int(row["blocked"] or 0),
                            }

                top_blocked: dict[str, int] = {}
                async with db.execute(
                    "SELECT domain, COUNT(*) AS hits FROM flow_log "
                    f"WHERE client_id = ? AND status = 'blocked' AND {today} "
                    "GROUP BY domain ORDER BY hits DESC, domain ASC LIMIT 4",
                    (client_id,),
                ) as cursor:
                    async for row in cursor:
                        domain = str(row["domain"] or "").strip().lower()
                        if domain:
                            top_blocked[domain] = int(row["hits"] or 0)

                return {
                    "num_dns_queries": total,
                    "num_blocked_filtering": blocked,
                    "dns_queries": [hourly[hour]["total"] for hour in range(24)],
                    "blocked_filtering": [hourly[hour]["blocked"] for hour in range(24)],
                    "top_blocked_domains": top_blocked,
                }
        except Exception as exc:
            logger.warning("Failed to read mobile client statistics: %s", exc)
            return empty

    async def _read_stats_from_db(self) -> Dict[str, Any]:
        """
        Read statistics directly from flow_log.db (fallback when FlowLogger unavailable).

        Security measures:
        - Read-only access (no writes)
        - Parameterized queries (no SQL injection risk)
        - Connection timeout to prevent hanging
        - Error details not exposed to caller
        """
        if not self.flow_log_path.exists():
            return None

        try:
            async with aiosqlite.connect(
                str(self.flow_log_path),
                timeout=5.0,  # 5 second timeout
            ) as db:
                db.row_factory = aiosqlite.Row

                # Total queries and blocked count (today only)
                async with db.execute(
                    "SELECT COUNT(*) as total, "
                    "SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked "
                    "FROM flow_log "
                    "WHERE datetime(timestamp) >= datetime('now', 'start of day')"
                ) as cursor:
                    row = await cursor.fetchone()
                    total = row["total"] if row else 0
                    blocked = row["blocked"] if row else 0

                # Hourly statistics (for Query Trend) - TODAY ONLY
                dns_queries = []
                blocked_filtering = []

                # Get hourly stats for TODAY (from midnight to now in localtime)
                hourly_query = (
                    "SELECT strftime('%H', timestamp, 'localtime') as hour, "
                    "COUNT(*) as cnt, "
                    "SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_cnt "
                    "FROM flow_log "
                    "WHERE datetime(timestamp, 'localtime') >= date('now', 'localtime') "
                    "GROUP BY hour ORDER BY hour"
                )

                async with db.execute(hourly_query) as cursor:
                    hourly_data = {i: {"queries": 0, "blocked": 0} for i in range(24)}
                    async for row in cursor:
                        hour = int(row["hour"])
                        hourly_data[hour] = {
                            "queries": row["cnt"],
                            "blocked": row["blocked_cnt"],
                        }

                    for i in range(24):
                        dns_queries.append(hourly_data[i]["queries"])
                        blocked_filtering.append(hourly_data[i]["blocked"])

                # Top blocked domains (limit 10)
                top_blocked = {}
                async with db.execute(
                    "SELECT domain, COUNT(*) as cnt FROM flow_log "
                    "WHERE status = 'blocked' "
                    "GROUP BY domain ORDER BY cnt DESC LIMIT 10"
                ) as cursor:
                    async for row in cursor:
                        top_blocked[row["domain"]] = row["cnt"]

                # Top queried domains (limit 10)
                top_queried = {}
                async with db.execute(
                    "SELECT domain, COUNT(*) as cnt FROM flow_log "
                    "GROUP BY domain ORDER BY cnt DESC LIMIT 10"
                ) as cursor:
                    async for row in cursor:
                        top_queried[row["domain"]] = row["cnt"]

                # Top clients (limit 10)
                top_clients = {}
                async with db.execute(
                    "SELECT client_id, COUNT(*) as cnt FROM flow_log "
                    "GROUP BY client_id ORDER BY cnt DESC LIMIT 10"
                ) as cursor:
                    async for row in cursor:
                        top_clients[row["client_id"]] = row["cnt"]

                # Average latency
                avg_latency = None
                async with db.execute(
                    "SELECT AVG(latency_ms) as avg_lat FROM flow_log "
                    "WHERE latency_ms IS NOT NULL"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row and row["avg_lat"]:
                        avg_latency = round(row["avg_lat"], 2)

                return {
                    "num_dns_queries": total,
                    "num_blocked_filtering": blocked,
                    "num_replaced_safebrowsing": 0,
                    "num_replaced_safesearch": 0,
                    "num_replaced_parental": 0,
                    "avg_processing_time": avg_latency,
                    "dns_queries": dns_queries,
                    "blocked_filtering": blocked_filtering,
                    "top_clients": top_clients,
                    "top_blocked_domains": top_blocked,
                    "top_queried_domains": top_queried,
                }
        except Exception as e:
            logger.warning(f"Failed to read stats from flow_log.db: {e}")
            return None

    async def get_stats(self) -> Dict[str, Any]:
        """Get DNS query statistics from FlowLogger, database, or in-memory."""
        # ALWAYS read from database for hourly breakdown and accurate stats
        db_stats = await self._read_stats_from_db()
        if db_stats:
            return db_stats

        # Fallback: Try FlowLogger if database unavailable
        if self._flow_logger:
            try:
                flow_stats = await self._flow_logger.get_stats()
                total = flow_stats.get("total_logged", 0) or flow_stats.get(
                    "storage_total", 0
                )
                blocked = flow_stats.get("blocked_total", 0)

                return {
                    "num_dns_queries": total,
                    "num_blocked_filtering": blocked,
                    "num_replaced_safebrowsing": 0,
                    "num_replaced_safesearch": 0,
                    "num_replaced_parental": 0,
                    "avg_processing_time": flow_stats.get(
                        "avg_latency_ms"
                    ),  # Real data or None
                    "dns_queries": [],
                    "blocked_filtering": [],
                    "top_clients": {},
                    "top_blocked_domains": {},
                    "top_queried_domains": {},
                }
            except Exception as e:
                logger.error(f"Failed to get FlowLogger stats: {e}")

        # Final fallback to in-memory stats (will be zeros if service just started)
        total = self._stats["total_queries"]
        blocked = self._stats["blocked_queries"]

        return {
            "num_dns_queries": total,
            "num_blocked_filtering": blocked,
            "num_replaced_safebrowsing": 0,
            "num_replaced_safesearch": 0,
            "num_replaced_parental": 0,
            "avg_processing_time": None,  # No data available in fallback mode
            "dns_queries": [],
            "blocked_filtering": [],
            "top_clients": {},
            "top_blocked_domains": {},
            "top_queried_domains": {},
        }

    async def get_period_stats(self, period: str = "24h") -> Dict[str, Any]:
        """Period-aware statistics (24h / 7d) from flow_log.db.

        Totals, trend, and top lists are ALL computed over the same selected
        window, and hashed client_ids are resolved to real IPs/names. Returns the
        exact shape the Statistics UI expects.
        """
        empty = {
            "totalQueries": 0,
            "blocked": 0,
            "blockRate": 0,
            "queryTrend": [],
            "blockTrend": [],
            "topBlocked": [],
            "topClients": [],
            "topQueried": [],
            "avgResponseTime": None,
        }
        if not self.flow_log_path.exists():
            return empty

        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                db.row_factory = aiosqlite.Row

                # flow_log timestamps are written in LOCAL time (no tz suffix), so the
                # bucket expressions below must NOT re-apply 'localtime' (that would
                # double-shift recent rows into "future" buckets). We only need a local
                # "now" to build the key list, which strftime(..,'localtime') gives us.
                async with db.execute(
                    "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime') AS n"
                ) as cur:
                    _r = await cur.fetchone()
                now = (
                    datetime.strptime(_r["n"], "%Y-%m-%d %H:%M:%S")
                    if _r and _r["n"]
                    else datetime.now()
                )

                # Build the window so its start aligns exactly with the first trend
                # bucket, which guarantees totalQueries == sum(trend bars). 7d
                # buckets by calendar day, 24h by calendar hour. The timestamp column
                # is already local, so no 'localtime' conversion on it.
                if period == "7d":
                    keys = [
                        (now - timedelta(days=d)).strftime("%Y-%m-%d")
                        for d in range(6, -1, -1)
                    ]
                    labels = {k: k[5:] for k in keys}
                    bucket_expr = "date(timestamp)"
                    where = f"date(timestamp) >= '{keys[0]}'"
                else:
                    period = "24h"
                    keys = [
                        (now - timedelta(hours=h)).strftime("%Y-%m-%dT%H")
                        for h in range(23, -1, -1)
                    ]
                    labels = {k: k[-2:] + ":00" for k in keys}
                    bucket_expr = "strftime('%Y-%m-%dT%H', timestamp)"
                    _earliest = (now - timedelta(hours=23)).strftime(
                        "%Y-%m-%d %H:00:00"
                    )
                    where = f"datetime(timestamp) >= '{_earliest}'"

                async with db.execute(
                    f"SELECT COUNT(*) AS total, "
                    f"SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) AS blocked "
                    f"FROM flow_log WHERE {where}"
                ) as cur:
                    row = await cur.fetchone()
                    total = (row["total"] if row else 0) or 0
                    blocked = (row["blocked"] if row else 0) or 0

                counts: Dict[str, tuple] = {}
                async with db.execute(
                    f"SELECT {bucket_expr} AS b, COUNT(*) AS cnt, "
                    f"SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) AS bc "
                    f"FROM flow_log WHERE {where} GROUP BY b"
                ) as cur:
                    async for row in cur:
                        counts[row["b"]] = (row["cnt"] or 0, row["bc"] or 0)

                query_trend = []
                for k in keys:
                    q, bl = counts.get(k, (0, 0))
                    query_trend.append(
                        {
                            "time": labels[k],
                            "queries": q,
                            "blocked": bl,
                            "allowed": max(q - bl, 0),
                        }
                    )

                top_blocked = []
                async with db.execute(
                    f"SELECT domain, COUNT(*) AS cnt FROM flow_log "
                    f"WHERE status='blocked' AND {where} GROUP BY domain ORDER BY cnt DESC LIMIT 5"
                ) as cur:
                    async for row in cur:
                        top_blocked.append(
                            {"domain": row["domain"], "hits": row["cnt"]}
                        )

                top_queried = []
                async with db.execute(
                    f"SELECT domain, COUNT(*) AS cnt FROM flow_log "
                    f"WHERE {where} GROUP BY domain ORDER BY cnt DESC LIMIT 5"
                ) as cur:
                    async for row in cur:
                        top_queried.append(
                            {"domain": row["domain"], "queries": row["cnt"]}
                        )

                raw_clients = []
                async with db.execute(
                    f"SELECT client_id, COUNT(*) AS cnt FROM flow_log "
                    f"WHERE {where} GROUP BY client_id ORDER BY cnt DESC LIMIT 5"
                ) as cur:
                    async for row in cur:
                        raw_clients.append((row["client_id"], row["cnt"]))

                try:
                    client_map = await self._build_flowlog_client_map()
                except Exception:
                    client_map = {}
                top_clients = []
                for cid, cnt in raw_clients:
                    info = client_map.get(cid) or {}
                    label = (
                        info.get("client_name")
                        or info.get("client_ip")
                        or (f"client {str(cid)[:8]}" if cid else "unknown")
                    )
                    top_clients.append({"client": label, "queries": cnt})

                avg_latency = None
                async with db.execute(
                    f"SELECT AVG(latency_ms) AS a FROM flow_log WHERE latency_ms IS NOT NULL AND {where}"
                ) as cur:
                    row = await cur.fetchone()
                    if row and row["a"] is not None:
                        avg_latency = round(row["a"], 2)

                return {
                    "totalQueries": total,
                    "blocked": blocked,
                    "blockRate": round((blocked / total * 100) if total else 0, 1),
                    "queryTrend": query_trend,
                    "blockTrend": [
                        {
                            "time": p["time"],
                            "blocked": p["blocked"],
                            "allowed": p["allowed"],
                        }
                        for p in query_trend
                    ],
                    "topBlocked": top_blocked,
                    "topClients": top_clients,
                    "topQueried": top_queried,
                    "avgResponseTime": avg_latency,
                }
        except Exception as e:
            logger.warning(f"Failed to read period stats from flow_log.db: {e}")
            return empty

    async def get_active_devices(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Devices that actually generated DNS activity (from flow_log), resolved to
        IP/name, with per-device request/blocked/allowed counts.

        Reflects who is really using the DNS, instead of only the manually
        configured parental clients.
        """
        devices: List[Dict[str, Any]] = []
        if not self.flow_log_path.exists():
            return devices
        try:
            client_map = await self._build_flowlog_client_map()
        except Exception:
            client_map = {}
        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                db.row_factory = aiosqlite.Row
                # flow_log timestamps are local, naive ISO values. Use a local
                # Python cutoff so the Devices window matches the 24h detail
                # view regardless of the host's UTC offset.
                cutoff = (
                    datetime.now() - timedelta(hours=max(1, int(hours)))
                ).isoformat()
                async with db.execute(
                    "SELECT client_id, COUNT(*) AS total, "
                    "SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) AS blocked, "
                    "MAX(timestamp) AS last_seen "
                    "FROM flow_log WHERE datetime(timestamp) >= datetime(?) "
                    "GROUP BY client_id ORDER BY total DESC",
                    (cutoff,),
                ) as cur:
                    async for row in cur:
                        cid = row["client_id"]
                        # The resolver watchdog is internal EasyPi traffic, not
                        # a LAN device. Match by hash as well as recovered IP so
                        # an attribution failure cannot expose it as unresolved.
                        if cid in {
                            self._hash_client_ip("127.0.0.1"),
                            self._hash_client_ip("::1"),
                        }:
                            continue
                        info = client_map.get(cid) or {}
                        ip = info.get("client_ip") or ""
                        if ip in {"127.0.0.1", "::1"}:
                            continue
                        identity_resolved = bool(ip)
                        name = (
                            info.get("client_name")
                            or ip
                            or (
                                f"Unresolved device {str(cid)[:8]}"
                                if cid
                                else "Unresolved device"
                            )
                        )
                        total = row["total"] or 0
                        blocked = row["blocked"] or 0
                        devices.append(
                            {
                                "id": (ip or str(cid))
                                .replace(".", "_")
                                .replace(":", "_"),
                                "name": name,
                                "ip": ip,
                                "hostname": name,
                                "client_id": cid,
                                "identityResolved": identity_resolved,
                                "lastSeen": row["last_seen"],
                                "status": "online",
                                "requestsCount": total,
                                "blockedCount": blocked,
                                "allowedCount": max(total - blocked, 0),
                            }
                        )
        except Exception as e:
            logger.warning(f"get_active_devices failed: {e}")
        return devices

    @staticmethod
    def _pct_change(cur: int, prev: int) -> "float | None":
        if not prev:
            return None
        return round((cur - prev) / prev * 100, 1)

    def _build_analytics_insights(
        self, period, total, blocked, p_total, p_blocked, categories, devices, peak
    ) -> List[str]:
        """Deterministic plain-language narrative of the numbers ('agent explains')."""
        out: List[str] = []
        span = {
            "24h": "the last 24 hours",
            "7d": "the last 7 days",
        }.get(period, "this period")
        rate = round(blocked / total * 100, 1) if total else 0
        if not total:
            return ["No DNS activity recorded in this window yet."]
        out.append(f"{total:,} DNS queries in {span}, {rate}% blocked ({blocked:,}).")

        def phrase(cur: int, prev: int, noun: str, floor: int):
            ch = self._pct_change(cur, prev)
            if ch is None or abs(ch) < floor:
                return None
            direction = "up" if ch > 0 else "down"
            # A tiny/erratic baseline makes a raw % misleading (e.g. +5000%).
            if abs(ch) > 200 or prev < 100:
                return f"{noun} are well {direction} vs the previous {period}."
            return f"{noun} are {direction} {abs(ch)}% vs the previous {period}."

        for line in (
            phrase(total, p_total, "Queries", 5),
            phrase(blocked, p_blocked, "Blocks", 10),
        ):
            if line:
                out.append(line)
        if categories and blocked:
            top = categories[0]
            share = round(top["count"] / blocked * 100)
            out.append(
                f"Most blocks were {top['label']} — {top['count']:,} ({share}% of all blocks)."
            )
        if devices and blocked:
            by_blocks = sorted(devices, key=lambda d: d["blocked"], reverse=True)
            d0 = by_blocks[0]
            if d0["blocked"] > 0:
                share = round(d0["blocked"] / blocked * 100)
                out.append(
                    f"{d0['name']} drove the most blocks — {d0['blocked']:,} ({share}% of blocks)."
                )
            eligible = [d for d in devices if d["requests"] >= 50]
            if eligible:
                risky = max(eligible, key=lambda d: d["blockRate"])
                if risky["blockRate"] >= 30 and risky is not d0:
                    out.append(
                        f"{risky['name']} has an unusually high block rate ({risky['blockRate']}%) — worth a look."
                    )
        if peak:
            out.append(f"Busiest time was around {peak}.")
        if total and not blocked:
            out.append("Nothing was blocked in this window.")
        return out

    async def get_analytics(self, period: str = "24h") -> Dict[str, Any]:
        """Deeper analytics for the Statistics view: threat-category breakdown (why
        things were blocked), per-device summary, busiest hour, period-over-period
        change, and a deterministic narrative that explains the numbers."""
        empty = {
            "period": period,
            "threatCategories": [],
            "devices": [],
            "insights": [],
            "comparison": {},
            "peakHour": None,
        }
        if not self.flow_log_path.exists():
            return empty
        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT strftime('%Y-%m-%d %H:%M:%S','now','localtime') AS n"
                ) as cur:
                    _r = await cur.fetchone()
                now = (
                    datetime.strptime(_r["n"], "%Y-%m-%d %H:%M:%S")
                    if _r and _r["n"]
                    else datetime.now()
                )

                if period == "7d":
                    start = (now - timedelta(days=6)).strftime("%Y-%m-%d")
                    where = f"date(timestamp) >= '{start}'"
                    p0 = (now - timedelta(days=13)).strftime("%Y-%m-%d")
                    prior_where = (
                        f"date(timestamp) >= '{p0}' AND date(timestamp) < '{start}'"
                    )
                else:
                    period = "24h"
                    earliest = (now - timedelta(hours=23)).strftime("%Y-%m-%d %H:00:00")
                    where = f"datetime(timestamp) >= '{earliest}'"
                    pe = (now - timedelta(hours=47)).strftime("%Y-%m-%d %H:00:00")
                    prior_where = f"datetime(timestamp) >= '{pe}' AND datetime(timestamp) < '{earliest}'"

                async def totals(w: str):
                    async with db.execute(
                        f"SELECT COUNT(*) t, SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) b "
                        f"FROM flow_log WHERE {w}"
                    ) as c:
                        r = await c.fetchone()
                        return (r["t"] or 0), (r["b"] or 0)

                total, blocked = await totals(where)
                p_total, p_blocked = await totals(prior_where)

                # Threat categories = why blocked (classify evidence_summary).
                cat_counts: Dict[str, list] = {}
                async with db.execute(
                    f"SELECT evidence_summary, verdict, categories, COUNT(*) AS cnt FROM flow_log "
                    f"WHERE status='blocked' AND {where} "
                    f"GROUP BY evidence_summary, verdict, categories"
                ) as cur:
                    async for row in cur:
                        key, label = self._classify_block_source(
                            row["evidence_summary"] or "",
                            row["verdict"] or "",
                            row["categories"] or "",
                        )
                        if not key:
                            key, label = "other", "Other"
                        elif key == "blocklist":
                            label = (
                                "Blocklist"  # canonical label (avoid generic "Blocked")
                            )
                        entry = cat_counts.setdefault(key, [label, 0])
                        entry[1] += row["cnt"] or 0
                threat_categories = sorted(
                    [
                        {"key": k, "label": v[0], "count": v[1]}
                        for k, v in cat_counts.items()
                    ],
                    key=lambda x: x["count"],
                    reverse=True,
                )

                # Per-device summary.
                try:
                    client_map = await self._build_flowlog_client_map()
                except Exception:
                    client_map = {}
                devices = []
                async with db.execute(
                    f"SELECT client_id, COUNT(*) t, SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) b "
                    f"FROM flow_log WHERE {where} GROUP BY client_id ORDER BY t DESC LIMIT 12"
                ) as cur:
                    async for row in cur:
                        cid = row["client_id"]
                        info = client_map.get(cid) or {}
                        ip = info.get("client_ip") or ""
                        name = (
                            info.get("client_name")
                            or ip
                            or (f"device {str(cid)[:8]}" if cid else "unknown")
                        )
                        t = row["t"] or 0
                        b = row["b"] or 0
                        devices.append(
                            {
                                "client_id": cid,
                                "name": name,
                                "ip": ip,
                                "requests": t,
                                "blocked": b,
                                "blockRate": round(b / t * 100, 1) if t else 0,
                            }
                        )

                peak = None
                async with db.execute(
                    f"SELECT strftime('%H', timestamp) AS h, COUNT(*) AS c FROM flow_log "
                    f"WHERE {where} GROUP BY h ORDER BY c DESC LIMIT 1"
                ) as cur:
                    r = await cur.fetchone()
                    if r and r["h"] is not None:
                        peak = f"{r['h']}:00"

                insights = self._build_analytics_insights(
                    period,
                    total,
                    blocked,
                    p_total,
                    p_blocked,
                    threat_categories,
                    devices,
                    peak,
                )

                return {
                    "period": period,
                    "threatCategories": threat_categories,
                    "devices": devices,
                    "insights": insights,
                    "comparison": {
                        "queriesChangePct": self._pct_change(total, p_total),
                        "blockedChangePct": self._pct_change(blocked, p_blocked),
                    },
                    "peakHour": peak,
                }
        except Exception as e:
            logger.warning(f"get_analytics failed: {e}")
            return empty

    async def get_device_detail(
        self, client_id: str, period: str = "24h", search: str | None = None
    ) -> Dict[str, Any]:
        """Drill-down for one device: its top queried/blocked domains + category mix."""
        out = {
            "recent": [],
            "topQueried": [],
            "topBlocked": [],
            "categories": [],
            "visited": {"sites": [], "trackers": [], "background": []},
            "totals": {"total": 0, "blocked": 0, "allowed": 0},
        }
        if not self.flow_log_path.exists() or not client_id:
            return out
        # flow_log keys on the hashed id (sha256(ip)[:16]). The Statistics tab already
        # passes that hash, but Parental Controls only has the raw device IP — hash it
        # here so a plain IP works too (a real hash is not a valid IP, so it passes through).
        try:
            import ipaddress

            ipaddress.ip_address(client_id.strip())
            client_id = self._hash_client_ip(client_id.strip())
        except ValueError:
            pass
        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                db.row_factory = aiosqlite.Row
                if period == "7d":
                    w = "date(timestamp) >= date('now','localtime','-6 days')"
                else:
                    w = "datetime(timestamp) >= datetime('now','localtime','-24 hours')"
                base = f"client_id = ? AND {w}"
                async with db.execute(
                    f"SELECT COUNT(*) total, "
                    f"SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked "
                    f"FROM flow_log WHERE {base}",
                    (client_id,),
                ) as cur:
                    totals_row = await cur.fetchone()
                    total = int(totals_row["total"] or 0) if totals_row else 0
                    blocked = int(totals_row["blocked"] or 0) if totals_row else 0
                    out["totals"] = {
                        "total": total,
                        "blocked": blocked,
                        "allowed": max(total - blocked, 0),
                    }
                async with db.execute(
                    f"SELECT domain, COUNT(*) c, "
                    f"SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) b "
                    f"FROM flow_log WHERE {base} "
                    f"GROUP BY domain ORDER BY c DESC LIMIT 8",
                    (client_id,),
                ) as cur:
                    out["topQueried"] = [
                        {
                            "domain": r["domain"],
                            "count": r["c"],
                            "blocked": r["b"] or 0,
                        }
                        async for r in cur
                    ]
                # Recently visited: each domain once, newest-first — so a site the user
                # just opened shows near the top. On a busy device a single visit can be
                # buried under constant background/telemetry churn, so a `search` filters
                # to matching domains server-side (finds it however deep the history is).
                if search and search.strip():
                    recent_sql = (
                        f"SELECT domain, MAX(timestamp) mt, COUNT(*) c FROM flow_log "
                        f"WHERE {base} AND domain LIKE ? GROUP BY domain ORDER BY mt DESC LIMIT 200"
                    )
                    recent_args = (client_id, f"%{search.strip()}%")
                else:
                    recent_sql = (
                        f"SELECT domain, MAX(timestamp) mt, COUNT(*) c FROM flow_log "
                        f"WHERE {base} GROUP BY domain ORDER BY mt DESC LIMIT 100"
                    )
                    recent_args = (client_id,)
                async with db.execute(recent_sql, recent_args) as cur:
                    recent_rows = [(r["domain"], r["mt"], r["c"]) async for r in cur]
                out["recent"] = [
                    {"domain": d, "count": c} for (d, _mt, c) in recent_rows
                ]
                # Split visited hosts into real sites (collapsed to the registrable
                # domain, e.g. www./inbox.google.com -> google.com) vs trackers / fetched
                # background (telemetry, CDN, APIs, push). rows are already newest-first.
                sites_agg: Dict[str, list] = {}
                trackers: list = []
                background: list = []
                for dom, mt, c in recent_rows:
                    kind = self._classify_visited_domain(dom)
                    if kind == "site":
                        reg = self._registrable_domain(dom)
                        e = sites_agg.get(reg)
                        if e is None:
                            sites_agg[reg] = [c or 0, mt or "", 1]
                        else:
                            e[0] += c or 0
                            if (mt or "") > e[1]:
                                e[1] = mt or ""
                            e[2] += 1
                    elif kind == "tracker":
                        trackers.append({"domain": dom, "count": c})
                    else:
                        background.append({"domain": dom, "count": c})
                sites = sorted(
                    [
                        {"domain": r, "count": v[0], "hosts": v[2], "_mt": v[1]}
                        for r, v in sites_agg.items()
                    ],
                    key=lambda x: x["_mt"],
                    reverse=True,
                )
                for s in sites:
                    s.pop("_mt", None)
                out["visited"] = {
                    "sites": sites,
                    "trackers": trackers,
                    "background": background,
                }
                async with db.execute(
                    f"SELECT domain, COUNT(*) c FROM flow_log WHERE {base} AND status='blocked' "
                    f"GROUP BY domain ORDER BY c DESC LIMIT 8",
                    (client_id,),
                ) as cur:
                    out["topBlocked"] = [
                        {"domain": r["domain"], "count": r["c"]} async for r in cur
                    ]
                cats: Dict[str, list] = {}
                async with db.execute(
                    f"SELECT evidence_summary, verdict, categories, COUNT(*) c FROM flow_log "
                    f"WHERE {base} AND status='blocked' "
                    f"GROUP BY evidence_summary, verdict, categories",
                    (client_id,),
                ) as cur:
                    async for r in cur:
                        key, label = self._classify_block_source(
                            r["evidence_summary"] or "",
                            r["verdict"] or "",
                            r["categories"] or "",
                        )
                        if not key:
                            key, label = "other", "Other"
                        entry = cats.setdefault(key, [label, 0])
                        entry[1] += r["c"] or 0
                out["categories"] = sorted(
                    [{"key": k, "label": v[0], "count": v[1]} for k, v in cats.items()],
                    key=lambda x: x["count"],
                    reverse=True,
                )
            return out
        except Exception as e:
            logger.warning(f"get_device_detail failed: {e}")
            return out

    async def get_onboarding_status(self) -> Dict[str, Any]:
        """First-run guide state: detects each setup step (protection on, devices
        actually using EasyPi for DNS, gateway/unbypassable, device profiles) and
        returns a checklist + a plain-language next-step the agent walks the user
        through. Read-only detection."""
        import socket

        pi_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            pi_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        protection_on = False
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl",
                "is-active",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            protection_on = out.decode().strip() == "active"
        except Exception:
            pass

        active_devices = 0
        try:
            devs = await self.get_active_devices(hours=24)
            # get_active_devices already excludes the resolver watchdog by its
            # privacy hash. Count unresolved clients too: immediately after a
            # fresh install DNS traffic can arrive before the IP hash has been
            # matched to the LAN inventory.
            active_devices = len(devs)
        except Exception:
            pass
        dns_ok = active_devices > 0

        gateway = False
        try:
            st = await self.get_schedule_enforcement_status()
            gateway = bool(st.get("gateway_enforcement"))
        except Exception:
            pass

        configured = 0
        try:
            pj = self.flow_log_path.parent / "profiles.json"
            if pj.exists():
                d = json.loads(pj.read_text())
                profs = (
                    d.get("profiles")
                    if (isinstance(d, dict) and "profiles" in d)
                    else d
                )
                items = (
                    list(profs.values()) if isinstance(profs, dict) else (profs or [])
                )
                configured = len(
                    [
                        p
                        for p in items
                        if isinstance(p, dict)
                        and (p.get("name") or "").lower() != "default"
                    ]
                )
        except Exception:
            pass
        profiles_ok = configured > 0

        steps = [
            {
                "key": "protection",
                "title": "Protection is on",
                "done": protection_on,
                "required": True,
                "detail": "The DNS filter is running."
                if protection_on
                else "The DNS filter isn't running.",
                "hint": "Start NetProtection so it can filter your DNS.",
                "link": "/guard?tab=dashboard",
            },
            {
                "key": "dns",
                "title": "Devices use EasyPi for DNS",
                "done": dns_ok,
                "required": True,
                "detail": (
                    f"{active_devices} device(s) are querying EasyPi."
                    if dns_ok
                    else "No devices are using EasyPi for DNS yet."
                ),
                "hint": (
                    f"Point your router's DNS to {pi_ip} (or set it per-device), so their traffic flows through EasyPi."
                    if pi_ip
                    else "Point your router's or devices' DNS at this box."
                ),
                "link": "/dashboard",
            },
            {
                "key": "gateway",
                "title": "Unbypassable enforcement",
                "done": gateway,
                "required": False,
                "detail": (
                    "EasyPi is your gateway — blocks can't be bypassed."
                    if gateway
                    else "DNS-only — a device could bypass by changing its DNS or using a VPN."
                ),
                "hint": "Optional: set EasyPi as your network's gateway so schedules/blocks can't be bypassed.",
                "link": "/dashboard",
            },
            {
                "key": "profiles",
                "title": "Device profiles & parental controls",
                "done": profiles_ok,
                "required": False,
                "detail": (
                    f"{configured} device profile(s) configured."
                    if profiles_ok
                    else "Only the default profile — no per-device rules yet."
                ),
                "hint": "Create a profile for a device (e.g. a kid's tablet) to enable parental controls, schedules and Safe Search.",
                "link": "/guard?tab=parental",
            },
        ]

        required_done = all(s["done"] for s in steps if s["required"])
        all_done = all(s["done"] for s in steps)
        next_step = next((s for s in steps if not s["done"]), None)
        if next_step is None:
            narrative = "You're all set — EasyPi is protecting your network. Explore Statistics and Parental Controls."
        else:
            narrative = f"Next: {next_step['title'].lower()}. {next_step['hint']}"

        return {
            "steps": steps,
            "completedCount": sum(1 for s in steps if s["done"]),
            "totalCount": len(steps),
            "requiredDone": required_done,
            "allDone": all_done,
            "nextStep": next_step["key"] if next_step else None,
            "piIp": pi_ip,
            "narrative": narrative,
        }

    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics (always uses today's data from database)."""
        # ALWAYS read from database with today filter (not FlowLogger totals)
        db_stats = await self._read_stats_from_db()

        if db_stats:
            total = db_stats["num_dns_queries"]
            blocked = db_stats["num_blocked_filtering"]
        else:
            # Fallback to zeros if DB unavailable
            total = 0
            blocked = 0

        return {
            "total_queries": total,
            "blocked_today": blocked,
            "block_percentage": round((blocked / total * 100) if total > 0 else 0, 1),
            "active_blocklists": await self._count_active_blocklists(),
            "blocked_domains": await self._count_blocked_domains(),
            "active_threats": await self._count_active_threats_today(),
            "cache_hit_rate": None,  # Real cache stats not yet implemented
            "avg_response_time_ms": None,  # Real latency stats not yet implemented
        }

    async def _count_active_threats_today(self) -> int:
        """Domains actively flagged as threats by heuristic/behavioral analysis today.

        These are blocks the engine produced beyond a plain ad-blocklist hit
        (DGA, homoglyph, suspicious structure, behavioral ad/tracker, threat
        intel) — i.e. live detections, not entries from the unused threat-feed
        database. Read-only from flow_log.db.
        """
        if not self.flow_log_path.exists():
            return 0
        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                async with db.execute(
                    "SELECT COUNT(DISTINCT domain) FROM flow_log "
                    "WHERE status = 'blocked' "
                    "AND (evidence_summary IS NULL OR evidence_summary NOT LIKE 'domain in blocklist%') "
                    "AND datetime(timestamp) >= datetime('now', 'start of day')"
                ) as cursor:
                    row = await cursor.fetchone()
                    return int(row[0]) if row and row[0] else 0
        except Exception as e:
            logger.debug(f"active-threats count unavailable: {e}")
            return 0

    async def reset_stats(self) -> Dict[str, Any]:
        """Reset statistics (clears flow_log.db data)."""
        try:
            if self.flow_log_path.exists():
                async with aiosqlite.connect(
                    str(self.flow_log_path), timeout=5.0
                ) as db:
                    await db.execute("DELETE FROM flow_log")
                    await db.commit()
                logger.info("Statistics reset - flow_log cleared")
            return {"success": True, "message": "Statistics reset"}
        except Exception as e:
            logger.error(f"Failed to reset stats: {e}")
            # Don't expose internal error details
            return {"success": False, "error": "Failed to reset statistics"}

    async def _count_active_blocklists(self) -> int:
        """Count active blocklists - 1 for verified or custom."""
        # Check if using real blocklist
        blocklist_path = self.data_dir / "verified_blocklist.txt"
        custom_path = self.data_dir / "custom_blocklist.txt"
        config_path = self.data_dir / "blocklist_config.json"

        # Check which is active
        use_custom = False
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text())
                use_custom = config.get("use_custom", False)
            except Exception:
                pass

        active_path = custom_path if use_custom else blocklist_path
        if active_path.exists():
            return 1  # One active blocklist
        return 0

    async def _count_blocked_domains(self) -> int:
        """Count total blocked domains from actual blocklist file."""
        blocklist_path = self.data_dir / "verified_blocklist.txt"
        custom_path = self.data_dir / "custom_blocklist.txt"
        config_path = self.data_dir / "blocklist_config.json"

        # Check which is active
        use_custom = False
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text())
                use_custom = config.get("use_custom", False)
            except Exception:
                pass

        active_path = custom_path if use_custom else blocklist_path

        if active_path.exists():
            try:
                # Count non-empty, non-comment lines
                count = 0
                with open(active_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            count += 1
                return count
            except Exception as e:
                logger.error(f"Error counting blocklist domains: {e}")

        return 0
