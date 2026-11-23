"""
Ad-Genesis — block the *birth of an ad event*, not known ad signatures.

Network-only (no capture, no decryption, no browser): purely from the DNS
history the resolver already logs (Chronicle `flow_log`), classify each domain
by its ROLE around user navigation and block the confident "parasitic ad branch"
— catching unlisted / brand-new ad domains that signature lists miss.

Two composed signals, both from DNS-burst structure:

  Navigation-Anchor Inference (NAI)
    A user action (open/click/type) => an idle gap, then a LEAD domain (the page
    the user chose), then a CASCADE of sub-resource lookups. A domain that is the
    lead is a navigation ANCHOR (user content) and is NEVER blocked here.

  Co-occurrence
    Among sub-resources, a domain that rides under >=2 DIFFERENT anchors
    (cross-site), co-occurs with >=2 distinct already-blocked ad domains, is never
    itself an anchor, and is not a CDN => confident parasitic ad branch => BLOCK.

The batch (run from maintenance) learns from real traffic and writes the block
set; the engine does a cheap O(1) lookup and blocks + logs each hit in the query
log (reason=advertising). It is a no-op until it has learned from real DNS data,
so it never blocks on a fresh install, and navigation content is structurally
excluded from the set.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

logger = logging.getLogger(__name__)

BLOCK_FILENAME = "ad_genesis_block.json"
MODEL_VERSION = 3

# Burst / role detection
IDLE_GAP_SECONDS = 20.0       # silence before a query => possible new navigation
CASCADE_WINDOW_SECONDS = 8.0  # sub-resources fired within this of the lead
CASCADE_MIN_DISTINCT = 3      # a navigation anchor is followed by >=3 other domains

# Confident-block thresholds (conservative; tunable)
MAX_ANCHOR_RATIO = 0.05       # candidate must be essentially NEVER a navigation anchor
MIN_DISTINCT_AD = 2           # co-occurs with >= this many distinct blocked ad domains
MIN_CROSS_SITE_ANCHORS = 2    # rides under >= this many DIFFERENT navigation anchors

_CDN_SUFFIXES = (
    ".cloudflare.com", ".cloudflare.net", ".cloudfront.net", ".akamai.net",
    ".akamaiedge.net", ".fastly.net", ".gstatic.com", ".googleapis.com",
    ".googleusercontent.com", ".azureedge.net", ".jsdelivr.net", ".unpkg.com",
)


def _reg(domain: str) -> str:
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _is_cdn(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == s.lstrip(".") or d.endswith(s) for s in _CDN_SUFFIXES)


# ───────────────────────── pure algorithm (unit-testable) ─────────────────────────

def analyze(
    rows: Iterable[tuple[str, float, str]],
    is_known_ad: Callable[[str], bool],
    *,
    idle_gap: float = IDLE_GAP_SECONDS,
    cascade_window: float = CASCADE_WINDOW_SECONDS,
    cascade_min: int = CASCADE_MIN_DISTINCT,
) -> dict:
    """
    rows: (client_id, timestamp_seconds, domain).
    Returns per-domain stats: seen, anchor, anchors_of (set), co_ad (set).
    """
    by_client: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for client_id, ts, domain in rows:
        domain = (domain or "").lower().strip().rstrip(".")
        if domain:
            by_client[client_id].append((float(ts), domain))

    seen: dict[str, int] = defaultdict(int)
    anchor: dict[str, int] = defaultdict(int)
    anchors_of: dict[str, set] = defaultdict(set)
    co_ad: dict[str, set] = defaultdict(set)

    for evs in by_client.values():
        evs.sort()
        n = len(evs)
        i = 0
        while i < n:
            ts, d = evs[i]
            prev = evs[i - 1][0] if i > 0 else None
            if prev is None or (ts - prev) > idle_gap:
                j = i + 1
                cascade = []
                while j < n and evs[j][0] - ts <= cascade_window:
                    cascade.append(evs[j][1])
                    j += 1
                distinct = set(cascade)
                if len(distinct) >= cascade_min:
                    all_domains = {d} | distinct
                    ad_regs = {_reg(x) for x in all_domains if is_known_ad(x)}
                    has_ad = bool(ad_regs)
                    anchor[d] += 1
                    for x in all_domains:
                        seen[x] += 1
                    d_reg = _reg(d)
                    for sub in all_domains:
                        if is_known_ad(sub) or sub == d:
                            continue
                        # First-party subresource of the navigated site (api.amazon.de
                        # under amazon.de) is NOT a parasitic cross-site ad — skip it,
                        # else functional infra gets blocked. Count anchors by distinct
                        # ORGANISATION so "cross-site" means truly different sites.
                        if _reg(sub) == d_reg:
                            continue
                        anchors_of[sub].add(d_reg)
                        if has_ad:
                            co_ad[sub] |= (ad_regs - {_reg(sub)})
                    i = j
                    continue
            i += 1

    return {"seen": dict(seen), "anchor": dict(anchor),
            "anchors_of": {k: set(v) for k, v in anchors_of.items()},
            "co_ad": {k: set(v) for k, v in co_ad.items()}}


def decide_blocks(
    stats: dict,
    *,
    is_excluded: Callable[[str], bool] | None = None,
    is_ad_shaped: Callable[[str], bool] | None = None,
    max_anchor_ratio: float = MAX_ANCHOR_RATIO,
    min_distinct_ad: int = MIN_DISTINCT_AD,
    min_cross_site: int = MIN_CROSS_SITE_ANCHORS,
) -> dict:
    """Return {domain: {'score','ad_assoc','anchors'}} for confident parasitic ads.

    A domain is blocked only when ALL hold: it rides under >= min_cross_site DISTINCT
    organisations (truly cross-site), co-occurs with >= min_distinct_ad known ad
    domains, neither it nor its registrable family has a navigation-anchor role,
    is not a CDN, is not excluded (allowlist/CDN), AND — when is_ad_shaped is
    supplied — itself looks like an ad/tracker. The last guards stop functional
    cross-site infra and first-party service hosts being blocked on co-occurrence.
    """
    seen = stats["seen"]
    anchor = stats["anchor"]
    anchors_of = stats["anchors_of"]
    co_ad = stats["co_ad"]
    anchor_regs = {_reg(d) for d, count in anchor.items() if count > 0}
    out: dict[str, dict] = {}
    for d, sup in seen.items():
        ad_assoc = len(co_ad.get(d, ()))
        cross = len(anchors_of.get(d, ()))
        if ad_assoc < min_distinct_ad or cross < min_cross_site:
            continue
        anchor_ratio = (anchor.get(d, 0) / sup) if sup else 0.0
        if anchor_ratio > max_anchor_ratio:          # it IS user-navigated content -> never block
            continue
        # Navigation is an organisation-level role, not an exact-host role. A
        # mobile app can lead with portal.vendor.test and later fetch user data
        # from storage.vendor.test without another idle gap. Treating only the
        # exact lead hostname as first-party lets that functional sibling become
        # a false cross-site candidate when unrelated background DNS overlaps.
        if _reg(d) in anchor_regs:
            continue
        if _is_cdn(d):
            continue
        if is_excluded and is_excluded(d):
            continue
        if is_ad_shaped is not None and not is_ad_shaped(d):  # must itself look like an ad/tracker
            continue
        out[d] = {"score": round(min(1.0, ad_assoc / 3.0 + 0.4), 3),
                  "ad_assoc": ad_assoc, "anchors": cross}
    return out


# ───────────────────────── batch build from Chronicle DB ─────────────────────────

def _find_flow_log_db(data_dir: Path) -> Path | None:
    if not data_dir.exists():
        return None
    for db in sorted(data_dir.rglob("*.db")):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2.0)
            try:
                row = con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='flow_log'"
                ).fetchone()
            finally:
                con.close()
            if row:
                return db
        except Exception:
            continue
    return None


def _to_epoch(ts) -> float | None:
    """Normalise a flow_log timestamp to epoch seconds.

    In this schema `timestamp` is ISO-8601 text ('2026-06-17T16:52:41.851253'),
    but other deployments may store epoch numbers — accept both. The old code did
    float(ts) directly, so every ISO row raised and got dropped, leaving Ad-Genesis
    permanently starved of data (it learned from 0 rows and blocked nothing)."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    if not s:
        return None
    try:
        return float(s)  # epoch stored as a number-like string
    except ValueError:
        pass
    s = s.replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def _read_recent_rows(db_path: Path, lookback_hours: int, limit: int) -> list[tuple[str, float, str]]:
    cutoff = time.time() - lookback_hours * 3600
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    try:
        # Order by rowid (schema-agnostic) and filter on a parsed epoch in Python:
        # timestamp is TEXT, so a SQL "timestamp >= <epoch>" compare is unreliable
        # across type affinities. Burst/gap math downstream uses relative diffs.
        cur = con.execute(
            "SELECT client_id, timestamp, domain FROM flow_log ORDER BY rowid DESC LIMIT ?",
            (limit,),
        )
        out: list[tuple[str, float, str]] = []
        for client_id, ts, domain in cur:
            ep = _to_epoch(ts)
            if ep is None or ep < cutoff:
                continue
            out.append((str(client_id), ep, str(domain)))
        return out
    finally:
        con.close()


def build_from_db(
    data_dir: str | Path,
    *,
    lookback_hours: int = 24,
    max_rows: int = 500_000,
    db_path: str | Path | None = None,
    extra_ad_shaped: Callable[[str], bool] | None = None,
    extra_ad_score: Callable[[str], float | None] | None = None,
) -> dict:
    data_dir = Path(data_dir)
    db = Path(db_path) if db_path else _find_flow_log_db(data_dir)
    if not db or not db.exists():
        return {"success": False, "error": "flow_log database not found", "blocked": 0}

    rows = _read_recent_rows(db, lookback_hours, max_rows)
    if not rows:
        return {"success": False, "error": "no recent dns rows", "blocked": 0}

    try:
        from ..verdict.blocklist_filter import get_blocklist_filter
        bl = get_blocklist_filter(str(data_dir))
    except Exception as e:
        return {"success": False, "error": f"blocklist unavailable: {e}", "blocked": 0}

    # Seed "known ad" from more than the user's blocklist — reuse the curated
    # tracker/ad-network set and the name-shape detector (no new lists) — so a
    # brand-new ad domain is still recognised as parasitic when the ad infra beside
    # it isn't on the list. The FP guards in decide_blocks (cross-site + never-anchor
    # + CDN/allowlist) are unchanged: a richer seed adds recall, not risk.
    known_trackers: set[str] = set()
    cdn_regs: set[str] = set()
    try:
        from ..intel.cname_chain import KNOWN_TRACKER_DOMAINS, CDN_ALLOWLIST
        known_trackers = set(KNOWN_TRACKER_DOMAINS)
        cdn_regs = set(CDN_ALLOWLIST)
    except Exception:
        pass
    try:
        from .ad_tracker_detector import get_ad_tracker_detector
        _det = get_ad_tracker_detector()

        def _is_named_ad(domain: str) -> bool:
            return bool(getattr(_det.analyze(domain), "is_definite_ad", False))

        def _det_ad_shaped(domain: str) -> bool:
            return bool(getattr(_det.analyze(domain), "is_suspicious", False))
    except Exception:
        def _is_named_ad(domain: str) -> bool:
            return False

        def _det_ad_shaped(domain: str) -> bool:
            return False  # no detector -> rely on extra signal only

    def _is_ad_shaped(d: str) -> bool:
        # name/heuristic shape OR an external behavioural signal (e.g. conntrack
        # beacon shape from causal_flow). The never-anchor + cross-site + CDN/allowlist
        # guards in decide_blocks still apply, so a navigated site is never blocked here.
        return _det_ad_shaped(d) or bool(extra_ad_shaped and extra_ad_shaped(d))

    def is_known_ad(d: str) -> bool:
        if bl.is_blocked(d, check_allowlist=False):
            return True
        if _reg(d) in known_trackers:
            return True
        return _is_named_ad(d)

    def is_excluded(d: str) -> bool:
        # never let Ad-Genesis touch first-party allowlist or known CDN/infra
        return bool(bl.is_allowed(d)) or _reg(d) in cdn_regs

    stats = analyze(rows, is_known_ad)
    blocks = decide_blocks(stats, is_excluded=is_excluded, is_ad_shaped=_is_ad_shaped)
    # Keep learned-flow evidence alongside the decision for auditability.  It is
    # explanatory metadata only: decide_blocks has already applied every safety
    # gate before a domain reaches this dictionary.
    if extra_ad_score:
        for domain, metadata in blocks.items():
            try:
                probability = extra_ad_score(domain)
            except Exception:
                probability = None
            if probability is not None:
                metadata["flow_ml_probability"] = round(float(probability), 4)
    protected_navigation_families = sorted(
        {_reg(domain) for domain, count in stats["anchor"].items() if count > 0}
    )
    out_path = data_dir / BLOCK_FILENAME
    payload = {
        "model_version": MODEL_VERSION,
        "generated_at": time.time(),
        "source_rows": len(rows),
        "protected_navigation_families": protected_navigation_families,
        "domains": blocks,
    }
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = out_path.with_name(f".{out_path.name}.{os.getpid()}.tmp")
        try:
            with temp_path.open("w", encoding="utf-8") as output:
                json.dump(payload, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, out_path)
        finally:
            temp_path.unlink(missing_ok=True)
    except Exception as e:
        return {"success": False, "error": f"write failed: {e}", "blocked": len(blocks)}
    logger.info(
        "ad-genesis: %d parasitic ad domains from %d rows; "
        "%d navigation families protected",
        len(blocks),
        len(rows),
        len(protected_navigation_families),
    )
    return {
        "success": True,
        "blocked": len(blocks),
        "rows": len(rows),
        "protected_navigation_families": len(protected_navigation_families),
        "db": str(db),
    }


# ───────────────────────── runtime blocklist (cheap lookup) ─────────────────────────

class AdGenesisBlocklist:
    """Loads the batch-built block set; O(1) lookup with automatic reloads."""

    def __init__(self, data_dir: str | Path):
        self._path = Path(data_dir) / BLOCK_FILENAME
        self._domains: dict[str, dict] = {}
        self._protected_regs: frozenset[str] = frozenset()
        self._generated_at: float | None = None
        self._model_version: int | None = None
        self._file_signature: tuple[int, int, int, int] | None = None
        self._reload()

    def _reload(self) -> None:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            self._domains = {}
            self._protected_regs = frozenset()
            self._generated_at = None
            self._model_version = None
            self._file_signature = None
            return
        file_signature = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
        if self._file_signature == file_signature:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if data.get("model_version") != MODEL_VERSION:
                self._domains = {}
                self._protected_regs = frozenset()
                self._generated_at = None
                self._model_version = None
                self._file_signature = file_signature
                return
            raw = data.get("domains", {})
            protected = data.get("protected_navigation_families", [])
            if not isinstance(raw, dict) or not isinstance(protected, list):
                return
            next_domains = {
                str(k).lower(): (v if isinstance(v, dict) else {})
                for k, v in raw.items()
            }
            next_protected = frozenset(
                _reg(value)
                for value in protected
                if isinstance(value, str) and value.strip()
            )
            generated_at = data.get("generated_at")
            self._domains = next_domains
            self._protected_regs = next_protected
            self._generated_at = (
                float(generated_at) if isinstance(generated_at, (int, float)) else None
            )
            self._model_version = MODEL_VERSION
            self._file_signature = file_signature
        except Exception:
            pass

    def lookup(self, domain: str) -> dict | None:
        self._reload()
        if not self._domains:
            return None
        normalized = (domain or "").lower().strip().rstrip(".")
        if not normalized or _reg(normalized) in self._protected_regs:
            return None
        return self._domains.get(normalized)

    def snapshot(self) -> dict[str, int | float | None]:
        self._reload()
        return {
            "model_version": self._model_version,
            "generated_at": self._generated_at,
            "domains": len(self._domains),
            "protected_navigation_families": len(self._protected_regs),
        }


_blocklist: AdGenesisBlocklist | None = None
_lock = threading.Lock()


def get_ad_genesis_blocklist(data_dir: str | Path) -> AdGenesisBlocklist:
    global _blocklist
    if _blocklist is None:
        with _lock:
            if _blocklist is None:
                _blocklist = AdGenesisBlocklist(data_dir)
    return _blocklist


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ad_genesis",
                                 description="Build the Ad-Genesis behavioral block set from Chronicle DNS logs.")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--lookback-hours", type=int, default=24)
    args = ap.parse_args(argv)
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        try:
            from ..config import get_settings
            data_dir = Path(get_settings().NETPROTECTION_DATA_DIR)
        except Exception:
            data_dir = Path("data/netprotection")
    res = build_from_db(data_dir, lookback_hours=args.lookback_hours, db_path=args.db)
    print(res)
    return 0 if res.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
