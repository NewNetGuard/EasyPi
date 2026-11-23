#!/usr/bin/env python3
"""Summarise chameleon_transport_baseline.sh measurements.

Usage: chameleon_transport_baseline_report.py RAW_FILE CARRIER_JSON
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict

CLK_TCK = 100  # Linux USER_HZ on the Pi


def spread(values: list[float], digits: int = 3) -> dict:
    if not values:
        return {}
    return {
        "median": round(statistics.median(values), digits),
        "min": round(min(values), digits),
        "max": round(max(values), digits),
        "n": len(values),
    }


def busy_pct(total: int, idle: int) -> float:
    return 100.0 * (total - idle) / total if total else 0.0


def main() -> None:
    raw, carrier_path = sys.argv[1], sys.argv[2]
    transfers: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    failures: dict = defaultdict(int)
    for line in open(raw, encoding="utf-8"):
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "R" and len(parts) >= 13:
            iface, test = parts[1], parts[2]
            code = parts[3]
            t_conn, t_tls, t_first, t_total = map(float, parts[4:8])
            size_dl, size_ul = float(parts[8]), float(parts[9])
            total_j, idle_j, client_j = map(int, parts[10:13])
            if code not in ("200", "206") or t_total <= 0:
                failures[f"{iface}/{test}"] += 1
                continue
            kind = "site" if test.startswith("site_") else test
            bucket = transfers[iface][kind]
            if kind == "site":
                bucket["connect_ms"].append(t_conn * 1000)
                bucket["tls_ms"].append(t_tls * 1000)
                bucket["first_byte_ms"].append(t_first * 1000)
                bucket["total_ms"].append(t_total * 1000)
            else:
                size = size_ul if test == "upload" else size_dl
                bucket["mb_per_s"].append(size / t_total / 1e6)
                bucket["pi_cpu_pct"].append(busy_pct(total_j, idle_j))
                bucket["client_cpu_pct_of_core"].append(100.0 * client_j / CLK_TCK / t_total)
        elif parts[0] == "P" and len(parts) >= 8:
            iface = parts[1]
            duration, size = float(parts[3]), float(parts[4])
            total_j, idle_j, client_j = map(int, parts[5:8])
            bucket = transfers[iface]["parallel4"]
            bucket["mb_per_s"].append(size / duration / 1e6 if duration else 0.0)
            bucket["pi_cpu_pct"].append(busy_pct(total_j, idle_j))
            bucket["client_cpu_pct_of_core"].append(100.0 * client_j / CLK_TCK / duration if duration else 0.0)

    summary = {
        iface: {kind: {metric: spread(values) for metric, values in metrics.items()} for kind, metrics in kinds.items()}
        for iface, kinds in transfers.items()
    }
    try:
        text = open(carrier_path, encoding="utf-8").read()
        carrier = json.loads(text[text.index("{"):])
    except (OSError, ValueError):
        carrier = {"error": "carrier analysis unavailable"}
    print(json.dumps({"paths": summary, "failed_transfers": dict(failures), "tunnel_carrier": carrier}, indent=2))


if __name__ == "__main__":
    main()
