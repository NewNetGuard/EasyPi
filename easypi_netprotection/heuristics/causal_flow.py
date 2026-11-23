"""Causal flow analysis for reports and active guarded ad blocking.

Joins cheap **conntrack** flow metadata (no DPI, no decryption, no packet capture)
with the resolver's DNS log to label each outbound connection with the domain that
produced it, then summarises per-domain network behaviour: how many flows, total
bytes, tiny "beacon"-shaped flows, large "media/creative" flows, and cross-site
fan-in (how many different clients/sites pulled the same third party).

``build_report`` only reports candidate parasitic-ad nodes. ``runtime_build``
adds connection-shape and learned PRISM/conntrack evidence to Ad-Genesis, whose
navigation/CDN/cross-site guards decide what is safe to block. This is the
connection-level companion to the DNS-timing layer: judge a domain by its causal
role and encrypted-flow behaviour, not only its name.

Data sources, both already on the box:
  * conntrack  — `conntrack -E -e DESTROY -o timestamp,extended` (needs
                 nf_conntrack_acct + nf_conntrack_timestamp = 1 for bytes/time)
  * flow_log   — Chronicle DNS log, now carrying `response_ips` (IP -> domain)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import subprocess
import time
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

# Reuse Ad-Genesis helpers — do NOT duplicate registrable / CDN / time logic.
from .ad_genesis import _find_flow_log_db, _is_cdn, _reg, _to_epoch

logger = logging.getLogger(__name__)

CONNTRACK_BIN = "/usr/sbin/conntrack"
REPORT_FILENAME = "causal_flow_report.json"
FLOWGRAPH_STATE_PATH = Path("/var/lib/easypi/prism/flowgraph.jsonl")
MAX_FLOWGRAPH_READ_BYTES = 8 * 1024 * 1024

TINY_FLOW_BYTES = 2_000        # <= this is beacon / pixel / reporting shaped
MEDIA_FLOW_BYTES = 200_000     # >= this is creative / media shaped
WEB_PORTS = {80, 443, 8080, 8443}

_RE_SRC = re.compile(r"\bsrc=(\d{1,3}(?:\.\d{1,3}){3})")
_RE_DST = re.compile(r"\bdst=(\d{1,3}(?:\.\d{1,3}){3})")
_RE_DPORT = re.compile(r"\bdport=(\d+)")
_RE_BYTES = re.compile(r"\bbytes=(\d+)")
_RE_TS = re.compile(r"^\[(\d+)\.\d+\]")


def _is_private(ip: str) -> bool:
    if ip.startswith(("192.168.", "10.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def _hash_client(ip: str) -> str:
    """Reproduce the resolver's client_id (sha256(ip)[:16]) so conntrack flows can
    be joined to flow_log rows, which store the hashed client id, not the raw IP."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# ───────────────────────── pure, unit-testable core ─────────────────────────

def parse_conntrack_events(lines) -> list[dict]:
    """Parse `conntrack -E -e DESTROY -o timestamp,extended` output into flows.

    Each line carries two tuples (orig + reply); the original-direction src is the
    LAN client and dst is the server. Bytes from both directions are summed.
    """
    out: list[dict] = []
    for ln in lines:
        if " tcp " not in ln and " udp " not in ln:
            continue
        srcs = _RE_SRC.findall(ln)
        dsts = _RE_DST.findall(ln)
        if not srcs or not dsts:
            continue
        dports = _RE_DPORT.findall(ln)
        byte_counts = [int(b) for b in _RE_BYTES.findall(ln)]
        m_ts = _RE_TS.search(ln)
        out.append({
            "client_ip": srcs[0],
            "dst_ip": dsts[0],
            "dport": int(dports[0]) if dports else 0,
            "proto": "tcp" if " tcp " in ln else "udp",
            "bytes": sum(byte_counts),
            # conntrack prints original then reply tuple.  Keeping both directions
            # lets the learned layer distinguish upload beacons from media delivery.
            "up_bytes": byte_counts[0] if byte_counts else 0,
            "down_bytes": byte_counts[1] if len(byte_counts) > 1 else 0,
            "ts": float(m_ts.group(1)) if m_ts else time.time(),
        })
    return out


def build_ip_domain_map(dns_rows):
    """dns_rows: iterable of (client_id, timestamp, domain, response_ips_csv).
    Returns (by_key, by_ip): {(client_id, ip): [(epoch, domain)]} and {ip: [...]}."""
    by_key: dict = defaultdict(list)
    by_ip: dict = defaultdict(list)
    for client_id, ts, domain, ips_csv in dns_rows:
        ep = _to_epoch(ts)
        if ep is None or not ips_csv:
            continue
        dom = (domain or "").lower().strip().rstrip(".")
        for ip in str(ips_csv).split(","):
            ip = ip.strip()
            if ip and not _is_private(ip):
                by_key[(client_id, ip)].append((ep, dom))
                by_ip[ip].append((ep, dom))
    return by_key, by_ip


def _pick_domain(pairs, ts):
    """Most recent lookup at/just-before the connection time (small future skew ok)."""
    best = None
    for ep, dom in pairs:
        if ep <= ts + 5 and (best is None or ep > best[0]):
            best = (ep, dom)
    if best:
        return best[1]
    return pairs[-1][1] if pairs else None


def attribute_flows(flows, by_key, by_ip) -> list[dict]:
    """Label each external web flow with the domain that resolved to its dst IP."""
    labeled = []
    for f in flows:
        if f["dport"] not in WEB_PORTS:
            continue
        if not _is_private(f["client_ip"]) or _is_private(f["dst_ip"]):
            continue
        cid = _hash_client(f["client_ip"])
        dom = _pick_domain(by_key.get((cid, f["dst_ip"]), []), f["ts"])
        if not dom:
            dom = _pick_domain(by_ip.get(f["dst_ip"], []), f["ts"])
        if dom:
            g = dict(f)
            g["domain"] = dom
            g["client_id"] = cid
            labeled.append(g)
    return labeled


def domain_flow_stats(labeled) -> dict:
    """Aggregate per registrable domain: flow count, bytes, beacon/media shape,
    distinct clients (cross-site fan-in proxy), and the FQDNs seen."""
    agg: dict = {}
    for f in labeled:
        reg = _reg(f["domain"])
        a = agg.get(reg)
        if a is None:
            a = agg[reg] = {"n_flows": 0, "total_bytes": 0, "max_bytes": 0,
                            "n_tiny": 0, "n_media": 0, "n_udp": 0,
                            "up_bytes": 0, "down_bytes": 0,
                            "clients": set(), "fqdns": set()}
        a["n_flows"] += 1
        a["total_bytes"] += f["bytes"]
        a["max_bytes"] = max(a["max_bytes"], f["bytes"])
        a["up_bytes"] += int(f.get("up_bytes", 0) or 0)
        a["down_bytes"] += int(f.get("down_bytes", 0) or 0)
        if f.get("proto") == "udp":
            a["n_udp"] += 1
        if 0 < f["bytes"] <= TINY_FLOW_BYTES:
            a["n_tiny"] += 1
        if f["bytes"] >= MEDIA_FLOW_BYTES:
            a["n_media"] += 1
        a["clients"].add(f["client_id"])
        a["fqdns"].add(f["domain"])
    return agg


def read_flowgraph_assessments(
    path: str | Path = FLOWGRAPH_STATE_PATH,
    *,
    after_timestamp: float = 0.0,
    max_bytes: int = MAX_FLOWGRAPH_READ_BYTES,
    max_rows: int = 20_000,
) -> tuple[list[dict], float]:
    """Read only new PRISM FlowGraph assessments from a bounded file tail.

    The returned rows stay in memory.  A timestamp watermark is persisted in the
    aggregate model so the same DPI events are not learned repeatedly.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
        start = max(0, size - max(1, int(max_bytes)))
        rows_by_flow: dict[str, dict] = {}
        watermark = max(0.0, float(after_timestamp))
        with path.open("rb") as source:
            source.seek(start)
            if start:
                source.readline()  # discard the partial first JSONL record
            for raw in source:
                try:
                    value = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if value.get("event") != "flow_assessment" or not value.get("server_name"):
                    continue
                try:
                    timestamp = float(value.get("timestamp", 0.0))
                except (TypeError, ValueError):
                    continue
                if timestamp <= after_timestamp:
                    continue
                watermark = max(watermark, timestamp)
                flow_key = "%s|%s" % (
                    value.get("flow") or f"row:{timestamp}:{len(rows_by_flow)}",
                    value.get("session_id", ""),
                )
                previous = rows_by_flow.get(flow_key)
                if previous is None or int(value.get("revision", 0) or 0) >= int(previous.get("revision", 0) or 0):
                    rows_by_flow[flow_key] = value
                if len(rows_by_flow) >= max_rows:
                    break
        return list(rows_by_flow.values()), watermark
    except (FileNotFoundError, PermissionError, OSError):
        return [], max(0.0, float(after_timestamp))


def merge_flowgraph_assessments(stats: dict, assessments) -> dict:
    """Attach bounded DPI sequence/timing aggregates to per-domain flow stats."""
    prism: dict[str, dict] = {}

    def number(value) -> float:
        try:
            return max(0.0, float(value or 0.0))
        except (TypeError, ValueError):
            return 0.0

    for row in assessments:
        domain = _reg(str(row.get("server_name") or ""))
        if not domain:
            continue
        features = row.get("features") if isinstance(row.get("features"), dict) else {}
        client_bytes = int(number(features.get("client_payload_bytes")))
        server_bytes = int(number(features.get("server_payload_bytes")))
        total_bytes = client_bytes + server_bytes
        aggregate = prism.get(domain)
        if aggregate is None:
            aggregate = prism[domain] = {
                "n": 0,
                "total_bytes": 0,
                "max_bytes": 0,
                "n_tiny": 0,
                "n_media": 0,
                "n_udp": 0,
                "client_bytes": 0,
                "server_bytes": 0,
                "causal_sum": 0.0,
                "burst_sum": 0.0,
                "session_flow_sum": 0.0,
                "blocked_dns_hits": 0,
                "response_delay_sum": 0.0,
                "resumption_hits": 0,
                "clients": set(),
            }
        aggregate["n"] += 1
        aggregate["total_bytes"] += total_bytes
        aggregate["max_bytes"] = max(aggregate["max_bytes"], total_bytes)
        aggregate["n_tiny"] += int(0 < total_bytes <= TINY_FLOW_BYTES)
        aggregate["n_media"] += int(total_bytes >= MEDIA_FLOW_BYTES)
        aggregate["n_udp"] += int(str(row.get("flow") or "").startswith("udp:"))
        aggregate["client_bytes"] += client_bytes
        aggregate["server_bytes"] += server_bytes
        aggregate["causal_sum"] += number(features.get("causal_edge_score"))
        aggregate["burst_sum"] += number(features.get("burst_flow_count"))
        aggregate["session_flow_sum"] += number(features.get("session_flow_count"))
        aggregate["blocked_dns_hits"] += int(number(features.get("blocked_dns_count")) > 0)
        aggregate["response_delay_sum"] += number(features.get("first_response_delay_ms"))
        aggregate["resumption_hits"] += int(
            number(features.get("tls_psk_identity_count")) > 0
            or "tls_session_resumption" in (row.get("evidence") or ())
        )
        client_ip = str(row.get("client_ip") or "")
        if client_ip:
            aggregate["clients"].add(_hash_client(client_ip))

    for domain, learned in prism.items():
        aggregate = stats.get(domain)
        if aggregate is None:
            aggregate = stats[domain] = {
                "n_flows": learned["n"],
                "total_bytes": learned["total_bytes"],
                "max_bytes": learned["max_bytes"],
                "n_tiny": learned["n_tiny"],
                "n_media": learned["n_media"],
                "n_udp": learned["n_udp"],
                "up_bytes": learned["client_bytes"],
                "down_bytes": learned["server_bytes"],
                "clients": set(learned["clients"]),
                "fqdns": set(),
            }
        aggregate["prism_n"] = learned["n"]
        aggregate["prism_client_bytes"] = learned["client_bytes"]
        aggregate["prism_server_bytes"] = learned["server_bytes"]
        aggregate["prism_causal_sum"] = learned["causal_sum"]
        aggregate["prism_burst_sum"] = learned["burst_sum"]
        aggregate["prism_session_flow_sum"] = learned["session_flow_sum"]
        aggregate["prism_blocked_dns_hits"] = learned["blocked_dns_hits"]
        aggregate["prism_response_delay_sum"] = learned["response_delay_sum"]
        aggregate["prism_resumption_hits"] = learned["resumption_hits"]
    return stats


def classify_nodes(stats, *, is_known_ad=None, is_excluded=None) -> list[dict]:
    """Observe-only verdicts. Flags a node 'ad-ish by flow' when it is NOT a CDN /
    allowlisted, and either is a known ad/tracker OR shows a beacon-heavy /
    cross-client tracker shape. Pure reporting — nothing is blocked here."""
    rows = []
    for reg, a in stats.items():
        if _is_cdn(reg) or (is_excluded and is_excluded(reg)):
            verdict = "exempt"
        else:
            known = bool(is_known_ad and is_known_ad(reg))
            beacon_heavy = a["n_flows"] >= 3 and a["n_tiny"] >= max(2, a["n_flows"] // 2) and a["n_media"] == 0
            if known:
                verdict = "ad/tracker (known)"
            elif beacon_heavy:
                verdict = "ad/tracker (beacon-shape)"
            else:
                verdict = "neutral"
        rows.append({
            "domain": reg,
            "verdict": verdict,
            "flows": a["n_flows"],
            "kb": round(a["total_bytes"] / 1024, 1),
            "tiny": a["n_tiny"],
            "media": a["n_media"],
            "clients": len(a["clients"]),
        })
    rows.sort(key=lambda r: (r["verdict"].startswith("ad"), r["flows"]), reverse=True)
    return rows


def _classification_context(data_dir: Path):
    """Return cached high-confidence label/exclusion callbacks.

    The callbacks reuse the same blocklist, tracker intelligence, allowlist and
    name detector as Ad-Genesis.  Failure is fail-closed for learning: no labels
    are invented when those sources are unavailable.
    """
    try:
        from ..verdict.blocklist_filter import get_blocklist_filter
        from ..intel.cname_chain import KNOWN_TRACKER_DOMAINS, CDN_ALLOWLIST
        from .ad_tracker_detector import get_ad_tracker_detector

        bl = get_blocklist_filter(str(data_dir))
        trackers = {_reg(value) for value in KNOWN_TRACKER_DOMAINS}
        cdn_regs = {_reg(value) for value in CDN_ALLOWLIST}
        detector = get_ad_tracker_detector()

        @lru_cache(maxsize=8192)
        def _named_result(domain: str):
            return detector.analyze(domain)

        def is_known_ad(domain: str) -> bool:
            normalized = _reg(domain)
            result = _named_result(normalized)
            return bool(bl.is_blocked(normalized, check_allowlist=False)) \
                or normalized in trackers \
                or bool(getattr(result, "is_definite_ad", False)) \
                or bool(getattr(result, "is_definite_tracker", False))

        def is_excluded(domain: str) -> bool:
            normalized = _reg(domain)
            return bool(bl.is_allowed(normalized)) \
                or normalized in cdn_regs \
                or _is_cdn(normalized)

        return is_known_ad, is_excluded
    except Exception as exc:
        logger.debug("causal flow labels unavailable: %s", exc)
        return None, None


def _navigation_anchor_regs(dns_rows, is_known_ad) -> set[str]:
    """Infer protected navigation families from the same DNS window."""
    if not dns_rows or not is_known_ad:
        return set()
    from . import ad_genesis

    rows = []
    for client_id, ts, domain, _ips in dns_rows:
        epoch = _to_epoch(ts)
        if epoch is not None:
            rows.append((str(client_id), epoch, str(domain)))
    if not rows:
        return set()
    learned = ad_genesis.analyze(rows, is_known_ad)
    return {_reg(domain) for domain, count in learned["anchor"].items() if count > 0}


def _training_examples(stats, *, is_known_ad, is_excluded, anchor_regs) -> list[tuple[str, dict]]:
    """Build conservative labels; ambiguous domains stay completely unlabeled."""
    if not is_known_ad or not is_excluded:
        return []
    examples = []
    for domain, aggregate in stats.items():
        if is_known_ad(domain):
            examples.append(("ad", aggregate))
        elif is_excluded(domain) or _reg(domain) in anchor_regs:
            examples.append(("clean", aggregate))
    return examples


# ───────────────────────── capture + report (side-effecting) ─────────────────────────

def capture_conntrack(seconds: int, binary: str = CONNTRACK_BIN) -> list[dict]:
    """Run conntrack in event mode for `seconds`, return parsed closed flows.

    Catches flows WITH final byte counts as they close — best for a long unattended
    window (e.g. a scheduled batch), but misses still-open keepalive connections.
    """
    try:
        proc = subprocess.run(
            [binary, "-E", "-e", "DESTROY", "-o", "timestamp,extended"],
            capture_output=True, text=True, timeout=seconds,
        )
        stdout = proc.stdout
    except subprocess.TimeoutExpired as exc:  # expected: we stop it by timeout
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return []
    return parse_conntrack_events(stdout.splitlines())


def capture_conntrack_snapshot(binary: str = CONNTRACK_BIN) -> list[dict]:
    """Snapshot the CURRENT conntrack table (open + recently-closed flows).

    Better for an on-demand reading right after a page load: browser keepalive
    connections are still open and would not yet have emitted a DESTROY event.
    Byte counters are whatever has accumulated so far (needs nf_conntrack_acct=1).
    """
    try:
        proc = subprocess.run([binary, "-L", "-o", "extended"],
                              capture_output=True, text=True, timeout=20)
        return parse_conntrack_events(proc.stdout.splitlines())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _read_dns_rows(db_path, lookback_seconds, limit=200_000):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    try:
        cur = con.execute(
            "SELECT client_id, timestamp, domain, response_ips FROM flow_log "
            "WHERE response_ips IS NOT NULL AND response_ips != '' "
            "ORDER BY rowid DESC LIMIT ?",
            (limit,),
        )
        cutoff = time.time() - lookback_seconds
        rows = []
        for cid, ts, dom, ips in cur:
            ep = _to_epoch(ts)
            if ep is None or ep < cutoff:
                continue
            rows.append((str(cid), ts, str(dom), ips))
        return rows
    finally:
        con.close()


def build_report(data_dir, *, mode="snapshot", capture_seconds=90, lookback_seconds=1800, db_path=None) -> dict:
    data_dir = Path(data_dir)
    flows = capture_conntrack_snapshot() if mode == "snapshot" else capture_conntrack(capture_seconds)
    db = Path(db_path) if db_path else _find_flow_log_db(data_dir)
    dns_rows = _read_dns_rows(db, lookback_seconds) if db and db.exists() else []

    by_key, by_ip = build_ip_domain_map(dns_rows)
    labeled = attribute_flows(flows, by_key, by_ip)
    stats = domain_flow_stats(labeled)

    # Reuse the Ad-Genesis seed/exclusion (blocklist + known trackers + name-shape).
    is_known_ad, is_excluded = _classification_context(data_dir)

    rows = classify_nodes(stats, is_known_ad=is_known_ad, is_excluded=is_excluded)
    payload = {
        "generated_at": time.time(),
        "mode": mode,
        "capture_seconds": capture_seconds if mode == "events" else 0,
        "flows_captured": len(flows),
        "flows_labeled": len(labeled),
        "domains": rows,
    }
    try:
        (data_dir / REPORT_FILENAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass
    return payload


def beacon_shaped_regs(stats) -> set:
    """Registrables whose conntrack flows look like a beacon / reporting tail:
    several flows, mostly tiny, no media download. Reliable only with EVENT-mode
    final byte counts (a snapshot shows partial bytes and would misjudge)."""
    out = set()
    for reg, a in stats.items():
        if a["n_flows"] >= 3 and a["n_media"] == 0 and a["n_tiny"] >= max(2, a["n_flows"] // 2):
            out.add(reg)
    return out


def runtime_build(data_dir, *, capture_seconds=60, lookback_seconds=1800) -> dict:
    """ACTIVE runtime pass (no observe/shadow): capture closing conntrack flows,
    derive a per-domain beacon-shape signal, and feed it into the Ad-Genesis builder
    as an extra 'ad-shaped' input. Ad-Genesis's own guards (never-anchor + cross-site
    + CDN/allowlist + first-party same-org) decide the final block set, so a navigated
    site can never be blocked. Writes ad_genesis_block.json -> enforced live (stage 2.7).
    """
    data_dir = Path(data_dir)
    flows = capture_conntrack(capture_seconds)
    db = _find_flow_log_db(data_dir)
    dns_rows = _read_dns_rows(db, lookback_seconds) if db and db.exists() else []
    by_key, by_ip = build_ip_domain_map(dns_rows)
    labeled = attribute_flows(flows, by_key, by_ip)
    flow_stats = domain_flow_stats(labeled)
    # Preserve the legacy beacon branch exactly: only final conntrack byte
    # counters may activate it. PRISM aggregates below are training/inference
    # features and must not bypass the ML maturity and probability gates.
    beacon = beacon_shaped_regs(flow_stats)

    # Learned second level.  Only known ads and protected clean traffic train the
    # model; unknown domains are inference-only.  The persisted model contains
    # aggregate means/variances, never domains, IPs, payloads, or device identity.
    from .flow_behavior_model import (
        AD_PROBABILITY_THRESHOLD,
        FlowBehaviorModel,
        update_on_device,
    )
    current_model = FlowBehaviorModel.load(data_dir)
    prism_rows, flowgraph_timestamp = read_flowgraph_assessments(
        after_timestamp=current_model.flowgraph_timestamp,
    )
    merge_flowgraph_assessments(flow_stats, prism_rows)
    is_known_ad, is_excluded = _classification_context(data_dir)
    anchor_regs = _navigation_anchor_regs(dns_rows, is_known_ad)
    examples = _training_examples(
        flow_stats,
        is_known_ad=is_known_ad,
        is_excluded=is_excluded,
        anchor_regs=anchor_regs,
    )
    watermark_advanced = flowgraph_timestamp > current_model.flowgraph_timestamp
    model = update_on_device(
        data_dir,
        examples,
        flowgraph_timestamp=flowgraph_timestamp if watermark_advanced else None,
    ) if examples or watermark_advanced else current_model
    probabilities = {
        reg: probability
        for reg, aggregate in flow_stats.items()
        if (probability := model.probability(aggregate)) is not None
    }
    learned_ad = {
        reg for reg, probability in probabilities.items()
        if probability >= AD_PROBABILITY_THRESHOLD
    }

    def _flow_probability(domain: str) -> float | None:
        return probabilities.get(_reg(domain))

    def _ad_shaped(domain: str) -> bool:
        reg = _reg(domain)
        return reg in beacon or reg in learned_ad

    from . import ad_genesis
    res = dict(ad_genesis.build_from_db(
        data_dir,
        extra_ad_shaped=_ad_shaped,
        extra_ad_score=_flow_probability,
    ) or {})
    res["flows_labeled"] = len(labeled)
    res["flow_beacon_regs"] = len(beacon)
    res["flow_ml_regs"] = len(learned_ad)
    res["flowgraph_assessments"] = len(prism_rows)
    res["flow_ml_trained_ad"] = sum(1 for label, _stats in examples if label == "ad")
    res["flow_ml_trained_clean"] = sum(1 for label, _stats in examples if label == "clean")
    res["flow_model"] = model.snapshot()
    logger.info(
        "causal_flow runtime: conntrack_flows=%d labeled=%d beacon_shaped=%d "
        "ml_shaped=%d model=%s -> blocked=%s",
        len(flows), len(labeled), len(beacon), len(learned_ad),
        "ready" if model.available else "learning", res.get("blocked"),
    )
    return res


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="causal_flow",
        description="OBSERVE-ONLY causal-flow report: label conntrack flows with domains and "
                    "summarise per-domain network behaviour. Does not block.")
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--mode", choices=["snapshot", "events"], default="snapshot",
                    help="snapshot = read current conntrack table (on-demand); "
                         "events = watch closing flows for --capture-seconds (batch)")
    ap.add_argument("--capture-seconds", type=int, default=90)
    ap.add_argument("--lookback-seconds", type=int, default=1800)
    args = ap.parse_args(argv)
    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:
        try:
            from ..config import get_settings
            data_dir = Path(get_settings().NETPROTECTION_DATA_DIR)
        except Exception:
            data_dir = Path("data/netprotection")

    res = build_report(data_dir, mode=args.mode, capture_seconds=args.capture_seconds,
                        lookback_seconds=args.lookback_seconds, db_path=args.db)
    print("mode: %s | captured flows: %d | labeled with a domain: %d" % (
        res["mode"], res["flows_captured"], res["flows_labeled"]))
    print("%-34s %-26s %6s %9s %5s %5s %7s" % ("domain", "verdict", "flows", "KB", "tiny", "media", "clients"))
    for r in res["domains"][:40]:
        print("%-34s %-26s %6d %9.1f %5d %5d %7d" % (
            r["domain"][:34], r["verdict"], r["flows"], r["kb"], r["tiny"], r["media"], r["clients"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
