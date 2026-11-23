# Combines one step's load result, resource samples and marks into one row,
# and decides whether the stand was overloaded.
# usage: evaluate.py <run-dir> <ram_mb> <label>   (prints one JSON row)
import json
import os
import sys

RUN, RAM, LABEL = sys.argv[1], int(sys.argv[2]), sys.argv[3]
load = json.load(open(RUN + "/load.json")) if os.path.exists(RUN + "/load.json") else {}
samples = [json.loads(l) for l in open(RUN + "/samples.jsonl") if l.strip()]
mark = lambda name: os.path.getmtime(RUN + "/mark." + name) if os.path.exists(RUN + "/mark." + name) else None
t0, t1 = mark("measure"), mark("done")
window = [s for s in samples if t0 and t1 and t0 <= s["t"] <= t1]


def cpu(key, rows):
    if len(rows) < 2:
        return None, None
    total = (rows[-1][key] - rows[0][key]) / 1e6 / (rows[-1]["t"] - rows[0]["t"]) * 100
    peaks = []
    for i in range(5, len(rows)):
        a, b = rows[i - 5], rows[i]
        peaks.append((b[key] - a[key]) / 1e6 / (b["t"] - a["t"]) * 100)
    return round(total, 1), round(max(peaks), 1) if peaks else None


row = {"label": LABEL, "ram_mb": RAM, "devices": load.get("devices"), "mode": load.get("mode"),
       "connected": load.get("connected"), "connect_failed": load.get("connect_failed")}
for key in ("all", "server", "nginx"):
    row[key + "_cpu_avg"], row[key + "_cpu_max5s"] = cpu(key + "_cpu_usec", window)
last = samples[-1] if samples else {}
mb = lambda b: round(b / 1048576, 1)
row["mem_all_max_mb"] = mb(max((s["all_mem"] for s in samples), default=0))
row["mem_all_peak_mb"] = mb(last.get("all_mem_peak", 0))
row["mem_server_peak_mb"] = mb(last.get("server_mem_peak", 0))
row["mem_nginx_peak_mb"] = mb(last.get("nginx_mem_peak", 0))
row["rss_server_max_mb"] = round(max((s["server_rss_kb"] for s in samples), default=0) / 1024, 1)
row["rss_server_hwm_mb"] = round(max((s["server_hwm_kb"] for s in samples), default=0) / 1024, 1)
row["rss_nginx_max_mb"] = round(max((s["nginx_rss_kb"] for s in samples), default=0) / 1024, 1)
row["rss_nginx_hwm_mb"] = round(max((s["nginx_hwm_kb"] for s in samples), default=0) / 1024, 1)
row["oom_kill"] = last.get("all_oom_kill", 0) + last.get("server_oom_kill", 0) + last.get("nginx_oom_kill", 0)
row["server_mem_high_events"] = last.get("server_mem_high_events", 0)
row["server_alive_at_end"] = last.get("server_procs", 0) > 0
counts = load.get("counts", {})
errors = {k[7:]: v for k, v in counts.items() if k.startswith("error: ")}
counts = {k: v for k, v in counts.items() if not k.startswith("error: ")}
seconds = load.get("measure_s") or 1
row["traffic_mbit_s_down"] = round(counts.pop("bytes_down", 0) * 8 / seconds / 1e6, 1)
row["traffic_mbit_s_up"] = round(counts.pop("bytes_up", 0) * 8 / seconds / 1e6, 1)
# one operation = one stream fetch or one echo round trip
ok = sum(v for k, v in counts.items() if k.endswith("_stream_ok") or k == "echo_ok")
# page_failed duplicates its streams' page_fail_* / page_open_fail_* counts
failing = {k: v for k, v in counts.items() if ("fail" in k or k.endswith("dropped")) and k != "page_failed"}
fail = sum(failing.values())
row["ops_ok"], row["ops_failed"] = ok, fail
row["fail_pct"] = round(100 * fail / max(1, ok + fail), 2)
row["failures"] = failing
row["pages_failed"] = counts.get("page_failed", 0)
row["error_texts"] = errors
try:
    row["nginx_worker_connections_errors"] = int(open(RUN + "/nginx_wc_errors").read().strip() or 0)
except (OSError, ValueError):
    row["nginx_worker_connections_errors"] = None
for k in ("echo_ms", "page_ms", "bg_ms", "download_mb_s", "upload_mb_s", "connect_ms"):
    if load.get(k):
        row[k] = {q: load[k][q] for q in ("n", "p50", "p95", "p99", "min") if q in load[k]}
reasons = []
if row["connected"] is None:
    reasons.append("load generator produced no result")
elif row["connected"] < row["devices"]:
    reasons.append("%d devices failed to connect" % (row["devices"] - row["connected"]))
if row["oom_kill"]:
    reasons.append("OOM kill")
if not row["server_alive_at_end"]:
    reasons.append("server process gone")
if row["fail_pct"] > 2:
    reasons.append("failures %.1f%%" % row["fail_pct"])
if row.get("echo_ms") and row["echo_ms"]["p95"] > 2000:
    reasons.append("echo p95 > 2 s")
if row.get("page_ms") and row["page_ms"]["p95"] > 10000:
    reasons.append("page p95 > 10 s")
row["overload"] = reasons
print(json.dumps(row))
