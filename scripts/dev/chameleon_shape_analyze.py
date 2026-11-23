#!/usr/bin/env python3
"""Passive-observer metrics for the Chameleon carrier.

Reads a server-side capture with tshark and reports the flow properties a
DPI classifier uses: TLS fingerprint, connection topology, TLS record sizes
and idle behaviour. Phases come from the bench log ("<epoch> <phase>" lines).

Usage: chameleon_shape_analyze.py CAPTURE.pcap CLIENT_PUBLIC_IP [PHASES.log]
"""
from __future__ import annotations

import collections
import json
import subprocess
import sys

SERVER_PORT = "443"
# Records this small from the server are control frames (WINDOW_UPDATE is 30
# bytes, PING ack 34 with TLS 1.3 AES-GCM); larger ones carry data.
SMALL_CONTROL_RECORD = 34
# A second in which a connection received this much is a download second.
DOWNLOAD_SECOND_BYTES = 50_000
ECHO_WINDOW = 0.3


def percentile(histogram: collections.Counter, share: float) -> int:
    total = sum(histogram.values())
    if not total:
        return 0
    running = 0
    for value in sorted(histogram):
        running += histogram[value]
        if running >= share * total:
            return value
    return max(histogram)


def tshark(capture: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    command = ["tshark", "-r", capture, "-Y", display_filter, "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in output.splitlines() if line]


def load_phases(path: str | None) -> list[tuple[float, float, str]]:
    if not path:
        return []
    marks = []
    for line in open(path, encoding="utf-8"):
        parts = line.split()
        if len(parts) == 2:
            marks.append((float(parts[0]), parts[1]))
    return [(start, marks[index + 1][0], name) for index, (start, name) in enumerate(marks[:-1])]


def main() -> None:
    # A long capture may be split into time-ordered parts (comma-separated) so
    # tshark's per-file memory stays bounded; connections are matched across
    # parts by the client's TCP port.
    captures, client = sys.argv[1].split(","), sys.argv[2]
    phases = load_phases(sys.argv[3] if len(sys.argv) > 3 else None)
    base = f"ip.addr=={client} && tcp.port=={SERVER_PORT}"

    streams: dict[str, dict] = collections.defaultdict(lambda: {"up": 0, "down": 0, "first": None, "last": None, "syn": None})
    records = {"up": collections.Counter(), "down": collections.Counter()}
    totals: dict[str, dict] = {}
    for _start, _end, name in phases:
        totals.setdefault(name, {"seconds": 0.0, "runs": 0, "packets": 0, "up": 0, "down": 0})
    hellos: list[list[str]] = []
    origin = None
    # Upload rhythm: how often the client writes while the connection is
    # downloading, and whether the server answers each write with a tiny
    # control record ("echo") before the client writes again.
    rhythm: dict[str, dict] = collections.defaultdict(lambda: {"last_up": None, "awaiting": None})
    per_second: dict[tuple, list] = collections.defaultdict(lambda: [0, 0])
    up_writes = echoes = small_down = 0
    up_gap_ms: collections.Counter = collections.Counter()
    echo_lag_ms: collections.Counter = collections.Counter()
    for capture in captures:
        hellos += tshark(capture, f"{base} && tls.handshake.type==1", ["tls.handshake.ja4"])
        rows = tshark(
            capture,
            base,
            ["frame.time_epoch", "tcp.srcport", "tcp.dstport", "ip.src", "tcp.len",
             "tls.record.length", "tcp.flags.syn", "tcp.flags.ack"],
        )
        for epoch, source_port, destination_port, source, length, record_lengths, syn, ack in rows:
            moment = float(epoch)
            origin = moment if origin is None else min(origin, moment)
            direction = "up" if source == client else "down"
            size = int(length or 0)
            entry = streams[source_port if direction == "up" else destination_port]
            entry["first"] = entry["first"] or moment
            entry["last"] = moment
            entry[direction] += size
            # tshark 4 prints flags as True/False, older releases as 1/0.
            if syn in ("1", "True") and ack in ("0", "False"):
                entry["syn"] = moment
            sizes = [int(value) for value in (record_lengths or "").split(",") if value.isdigit()]
            for value in sizes:
                records[direction][value] += 1
            port = source_port if direction == "up" else destination_port
            state = rhythm[port]
            bucket = per_second[(port, int(moment))]
            if direction == "up" and sizes:
                up_writes += 1
                bucket[0] += 1
                if state["last_up"] is not None and moment - state["last_up"] < 1.0:
                    up_gap_ms[int((moment - state["last_up"]) * 1000)] += 1
                state["last_up"] = state["awaiting"] = moment
            elif direction == "down":
                bucket[1] += size
                tiny = sum(1 for value in sizes if value <= SMALL_CONTROL_RECORD)
                small_down += tiny
                if tiny and state["awaiting"] is not None and moment - state["awaiting"] <= ECHO_WINDOW:
                    echoes += 1
                    echo_lag_ms[int((moment - state["awaiting"]) * 1000)] += 1
                    state["awaiting"] = None
            for start, end, name in phases:
                if start <= moment < end:
                    total = totals[name]
                    total["packets"] += 1
                    total[direction] += size
                    break
        del rows

    opened = sorted(entry["syn"] for entry in streams.values() if entry["syn"])
    simultaneous = max(
        (sum(1 for other in opened if 0 <= other - moment <= 1.0) for moment in opened),
        default=0,
    )
    carrying = [entry for entry in streams.values() if entry["up"] + entry["down"] > 1_000_000]
    upload_only = sum(1 for entry in carrying if entry["up"] / (entry["up"] + entry["down"]) > 0.9)

    def record_summary(counter: collections.Counter) -> dict:
        total = sum(counter.values())
        top8 = sum(count for _, count in counter.most_common(8))
        small = sum(count for length, count in counter.items() if length <= 64)
        return {
            "records": total,
            "top8_share": round(top8 / total, 3) if total else 0,
            "small_share": round(small / total, 3) if total else 0,
            "max": max(counter) if counter else 0,
            "most_common": counter.most_common(5),
        }

    # A phase that repeats across cycles is reported once, over all its runs.
    for start, end, name in phases:
        totals[name]["seconds"] += end - start
        totals[name]["runs"] += 1
    phase_report = {}
    for name, total in totals.items():
        minutes = max(total["seconds"] / 60, 1e-9)
        phase_report[name] = {
            "seconds": round(total["seconds"]),
            "runs": total["runs"],
            "packets_per_min": round(total["packets"] / minutes),
            "kb_up_per_min": round(total["up"] / 1024 / minutes),
            "kb_down_per_min": round(total["down"] / 1024 / minutes),
        }

    # Lifetimes show how long one carrier connection lives and when a new
    # transport epoch replaced it; a browser keeps an origin connection open.
    origin = origin or 0.0
    lifetimes = [
        {
            "opened_at_min": round(((entry["syn"] or entry["first"]) - origin) / 60, 1),
            "minutes": round((entry["last"] - (entry["syn"] or entry["first"])) / 60, 1),
            "mb": round((entry["up"] + entry["down"]) / 1_000_000, 1),
            "seen_from_start": entry["syn"] is not None,
        }
        for entry in sorted(streams.values(), key=lambda value: value["syn"] or value["first"])
        if entry["first"] is not None
    ]

    download_seconds = [ups for ups, down in per_second.values() if down >= DOWNLOAD_SECOND_BYTES]
    upload_rhythm = {
        "client_writes": up_writes,
        "echo_share": round(echoes / up_writes, 3) if up_writes else 0,
        "echo_lag_ms_median": percentile(echo_lag_ms, 0.5),
        "small_down_records_per_write": round(small_down / up_writes, 3) if up_writes else 0,
        "download_seconds": len(download_seconds),
        "writes_per_download_second": round(sum(download_seconds) / len(download_seconds), 1) if download_seconds else 0,
        "write_gap_ms_p10_p50_p90": [percentile(up_gap_ms, share) for share in (0.1, 0.5, 0.9)],
    }

    report = {
        "ja4": sorted(set(hello[0] for hello in hellos if hello and hello[0])),
        "upload_rhythm": upload_rhythm,
        "connections": len(streams),
        "max_opened_within_1s": simultaneous,
        "connections_over_1mb": len(carrying),
        "upload_only_connections": upload_only,
        "records_up": record_summary(records["up"]),
        "records_down": record_summary(records["down"]),
        "phases": phase_report,
        "connection_lifetimes": lifetimes,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
