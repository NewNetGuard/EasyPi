# Prints the results table from results.jsonl.
import json
import sys

rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
head = ("RAM", "mode", "dev", "conn", "CPU avg%", "CPU 5s max%", "mem peak MB", "srv RSS MB", "ngx RSS MB",
        "Mbit/s down/up", "echo p50/p95/p99 ms", "page p50/p95 ms", "dl MB/s p50/min", "ul MB/s p50/min",
        "ops ok/fail", "wc err", "overload")
print(" | ".join(head))


def q(r, k, a, b, c=None):
    v = r.get(k)
    if not v:
        return "-"
    parts = [v.get(a), v.get(b)] + ([v.get(c)] if c else [])
    return "/".join(str(round(x)) if isinstance(x, (int, float)) and x >= 10 else str(x) for x in parts)


for r in rows:
    print(" | ".join(str(x) for x in (
        r["ram_mb"], r["mode"], r["devices"], r["connected"], r["all_cpu_avg"], r["all_cpu_max5s"],
        r["mem_all_peak_mb"], r["rss_server_hwm_mb"], r["rss_nginx_hwm_mb"],
        "%s/%s" % (r.get("traffic_mbit_s_down"), r.get("traffic_mbit_s_up")),
        q(r, "echo_ms", "p50", "p95", "p99"), q(r, "page_ms", "p50", "p95"),
        q(r, "download_mb_s", "p50", "min"), q(r, "upload_mb_s", "p50", "min"),
        "%s/%s" % (r["ops_ok"], r["ops_failed"]), r.get("nginx_worker_connections_errors"),
        "; ".join(r["overload"]) or "no")))
    if r["ops_failed"]:
        print("    failures:", r["failures"], "errors:", r.get("error_texts"))
