"""Blocked & Allowed overview: what the network-wide protection blocked, split
into sites a person can open and trackers/background requests they cannot,
with who blocked each one, plus the domains the user explicitly allowed.

Only network-wide default blocking is listed. Restrictions an administrator
enabled for a specific device (parental controls, schedules, device rules, app
blocking, SafeSearch) are deliberately left out: they are managed on their
own pages and the allowlist never overrides them.

DNS shows names and timing, not pages, so the site/tracker split is a best
effort and every entry says what it was based on:
  reason    the engine's own decisive reason (Ad/Tracker AI, CNAME cloaking)
  name      the domain name is an unmistakable tracker or background service
  behavior  when it was requested: alone (someone tried to open it) or within
            a second or two after another site (loaded by that page)
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

import aiosqlite

from app.services.netprotection_components.policy_data import (
    ALLOWLIST_SOURCE_ASSISTANT,
    ALLOWLIST_SOURCE_BLOCKED_TAB,
    ALLOWLIST_SOURCE_LISTS,
    ALLOWLIST_SOURCE_SHADOW_MODE,
    is_shared_zone,
    normalize_list_domain,
)
from app.services.netprotection_components.runtime_context import logger

PERIOD_FILTERS = {
    "24h": "datetime(timestamp) >= datetime('now','localtime','-24 hours')",
    "7d": "date(timestamp) >= date('now','localtime','-6 days')",
}

# A page's own sub-requests follow its navigation within about a second.
EMBEDDED_WINDOW_SECONDS = 3.0
# A blocked domain loaded under this many different sites is cross-site content.
CROSS_SITE_CONTEXTS = 3
# Bound the work on a small device: only the newest rows of the period are read.
MAX_SCAN_ROWS = 300_000
MAX_ENTRIES_PER_SECTION = 300
CACHE_SECONDS = 20.0

# Reasons that already say the domain is embedded, not navigated.
TRACKER_SOURCE_KEYS = frozenset({"ad_ai", "cname"})

ALLOWLIST_SOURCE_LABELS = {
    ALLOWLIST_SOURCE_LISTS: "Lists",
    ALLOWLIST_SOURCE_SHADOW_MODE: "Shadow Mode",
    ALLOWLIST_SOURCE_BLOCKED_TAB: "Blocked & Allowed",
    ALLOWLIST_SOURCE_ASSISTANT: "AI Assistant",
}


def _covered(domain: str, names: set[str]) -> bool:
    """True when the domain or one of its parent domains is in ``names``."""
    labels = domain.split(".")
    return any(".".join(labels[i:]) in names for i in range(len(labels) - 1))


def _epoch(value: str) -> Optional[float]:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return None


class AnalyticsBlockedOverviewMixin:
    _blocked_overview_cache: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]]

    async def get_blocked_overview(
        self, period: str = "24h", client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Blocked sites, blocked trackers and user-allowed domains for a period."""
        if period not in PERIOD_FILTERS:
            period = "24h"
        client_id = (client_id or "").strip() or None
        if client_id:
            import ipaddress

            try:
                ipaddress.ip_address(client_id)
                client_id = self._hash_client_ip(client_id)
            except ValueError:
                pass

        cache = getattr(self, "_blocked_overview_cache", None)
        if cache is None:
            cache = self._blocked_overview_cache = {}
        key = (period, client_id or "")
        cached = cache.get(key)
        if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]

        allowlist = await self.get_whitelist()
        allowed_names = {entry["domain"].lower() for entry in allowlist}
        blocked = await self._scan_blocked(period, client_id, allowed_names)

        result = {
            "period": period,
            "client_id": client_id,
            **blocked,
            "allowed": [
                {
                    "domain": entry["domain"],
                    "added_at": entry.get("addedAt", ""),
                    "hits": entry.get("hits", 0),
                    "comment": entry.get("comment", ""),
                    "source": entry.get("source", ALLOWLIST_SOURCE_LISTS),
                    "source_label": ALLOWLIST_SOURCE_LABELS.get(
                        entry.get("source", ALLOWLIST_SOURCE_LISTS), "Lists"
                    ),
                }
                for entry in sorted(
                    allowlist, key=lambda item: item.get("addedAt", ""), reverse=True
                )
            ],
        }
        cache[key] = (time.monotonic(), result)
        return result

    def invalidate_blocked_overview(self) -> None:
        """Drop cached overviews after the user changes a decision."""
        if getattr(self, "_blocked_overview_cache", None):
            self._blocked_overview_cache.clear()

    async def _scan_blocked(
        self, period: str, client_id: Optional[str], allowed_names: set[str]
    ) -> Dict[str, Any]:
        empty = {"sites": [], "trackers": [], "scanned_rows": 0, "truncated": False}
        if not self.flow_log_path.exists():
            return empty

        where = PERIOD_FILTERS[period]
        params: List[Any] = []
        if client_id:
            where += " AND client_id = ?"
            params.append(client_id)

        name_kind: Dict[str, str] = {}
        registrable: Dict[str, str] = {}

        def kind_of(domain: str) -> str:
            kind = name_kind.get(domain)
            if kind is None:
                kind = name_kind[domain] = self._classify_visited_domain(domain)
            return kind

        def reg_of(domain: str) -> str:
            reg = registrable.get(domain)
            if reg is None:
                reg = registrable[domain] = self._registrable_domain(domain)
            return reg

        recent_pages: Dict[str, Deque[Tuple[float, str]]] = {}
        stats: Dict[str, Dict[str, Any]] = {}
        scanned = 0
        truncated = False

        try:
            async with aiosqlite.connect(str(self.flow_log_path), timeout=5.0) as db:
                async with db.execute(
                    f"SELECT COUNT(*) FROM flow_log WHERE {where}", params
                ) as cursor:
                    row = await cursor.fetchone()
                    in_period = int(row[0] or 0) if row else 0
                truncated = in_period > MAX_SCAN_ROWS
                # Newest rows of the period, replayed oldest-first.
                sql = (
                    "SELECT timestamp, domain, client_id, status, evidence_summary,"
                    " verdict, categories FROM ("
                    f"  SELECT id, timestamp, domain, client_id, status, evidence_summary,"
                    f"   verdict, categories FROM flow_log WHERE {where}"
                    "   ORDER BY id DESC LIMIT ?"
                    ") ORDER BY id"
                )
                async with db.execute(sql, [*params, MAX_SCAN_ROWS]) as cursor:
                    async for ts_raw, domain, cid, status, summary, verdict, cats in cursor:
                        scanned += 1
                        epoch = _epoch(ts_raw)
                        domain = (domain or "").lower().rstrip(".")
                        if epoch is None or not domain:
                            continue
                        pages = recent_pages.setdefault(cid, deque())
                        while pages and epoch - pages[0][0] > EMBEDDED_WINDOW_SECONDS:
                            pages.popleft()
                        reg = reg_of(domain)

                        if status != "blocked":
                            if kind_of(domain) == "site":
                                pages.append((epoch, reg))
                            continue

                        source_key, source_label = self._classify_block_source(
                            summary or "", verdict or "", cats or ""
                        )
                        if (
                            not source_key
                            or source_key in self.DEVICE_RESTRICTION_SOURCES
                            or _covered(domain, allowed_names)
                        ):
                            continue
                        entry = stats.get(domain)
                        if entry is None:
                            entry = stats[domain] = {
                                "count": 0,
                                "embedded": 0,
                                "contexts": set(),
                                "clients": set(),
                                "last_seen": ts_raw,
                                "source_key": source_key,
                                "source_label": source_label,
                            }
                        entry["count"] += 1
                        entry["clients"].add(cid)
                        # Rows arrive oldest-first: the latest reason wins.
                        entry["last_seen"] = ts_raw
                        entry["source_key"] = source_key
                        entry["source_label"] = source_label
                        hosts = {page_reg for _, page_reg in pages if page_reg != reg}
                        if hosts:
                            entry["embedded"] += 1
                            entry["contexts"].update(hosts)
        except Exception as exc:
            logger.warning("Blocked overview scan failed: %s", exc)
            return empty

        try:
            client_map = await self._build_flowlog_client_map()
        except Exception:
            client_map = {}

        sites: List[Dict[str, Any]] = []
        trackers: List[Dict[str, Any]] = []
        for domain, entry in stats.items():
            kind, basis = self._blocked_domain_kind(domain, entry, kind_of(domain))
            devices = sorted(
                {
                    (client_map.get(cid) or {}).get("client_name")
                    or (client_map.get(cid) or {}).get("client_ip")
                    or "Unknown device"
                    for cid in entry["clients"]
                }
            )
            item = {
                "domain": domain,
                "count": entry["count"],
                "last_seen": entry["last_seen"],
                "devices": devices,
                "source_key": entry["source_key"],
                "source_label": entry["source_label"],
                "basis": basis,
            }
            (sites if kind == "site" else trackers).append(item)

        def newest(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            items.sort(key=lambda item: item["last_seen"], reverse=True)
            return items[:MAX_ENTRIES_PER_SECTION]

        return {
            "sites": newest(sites),
            "trackers": newest(trackers),
            "scanned_rows": scanned,
            "truncated": truncated,
        }

    @staticmethod
    def _blocked_domain_kind(
        domain: str, entry: Dict[str, Any], name_kind: str
    ) -> Tuple[str, str]:
        """Return ("site" | "tracker", basis) for one blocked domain."""
        if entry["source_key"] in TRACKER_SOURCE_KEYS:
            return "tracker", "reason"
        if name_kind in ("tracker", "background"):
            return "tracker", "name"
        embedded_share = entry["embedded"] / entry["count"] if entry["count"] else 0.0
        if embedded_share >= 0.5 or len(entry["contexts"]) >= CROSS_SITE_CONTEXTS:
            return "tracker", "behavior"
        return "site", "behavior"

    async def set_domain_decision(self, domain: str, decision: str) -> Dict[str, Any]:
        """Apply the user's latest decision for one domain.

        allow: remove it from the user's blacklist and add it to the allowlist,
               which overrides every network-wide block.
        block: remove it from the allowlist and add it to the user's blacklist,
               so it is blocked whatever the other protections decide.
        """
        # Refuse before touching either list, so a refused allow never drops
        # the domain from the user's blacklist.
        domain = normalize_list_domain(domain)
        if decision == "allow" and is_shared_zone(domain):
            raise ValueError(
                f"{domain} is a shared domain zone; allow a specific site instead"
            )
        if decision == "allow":
            await self.remove_from_blacklist(domain)
            result = await self.add_to_whitelist(
                domain,
                comment="Unblocked in Blocked & Allowed",
                source=ALLOWLIST_SOURCE_BLOCKED_TAB,
            )
        elif decision == "block":
            await self.remove_from_whitelist(domain)
            result = await self.add_to_blacklist(
                domain, comment="Blocked again in Blocked & Allowed"
            )
        else:
            raise ValueError(f"Unknown decision: {decision}")
        self.invalidate_blocked_overview()
        return {"success": bool(result.get("success", True)), "domain": domain, "decision": decision}
