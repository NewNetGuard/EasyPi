import json
import statistics
import sys

data = json.load(open(sys.argv[1]))


def avg(items, key):
    vals = [i[key] for i in items if key in i]
    return round(statistics.mean(vals), 2) if vals else "FAIL"


def lat(s):
    return "%s/%s/%s" % (s["p50"], s["p99"], s["max"]) if s else "-"


for name, r in data.items():
    print("==", name)
    for kind in ("bulk_capped", "bulk_free"):
        runs = r[kind]
        fails = [x.get("FAIL") for x in runs if not x.get("ok")]
        print("  %-11s MB/s %s (%s)  streamWU %s  connWU %s  avgWU %s KB  blocked %s s  maxblock %s ms  rec ms p50/p99/max %s  %s" % (
            kind, avg(runs, "mb_s"), [x.get("mb_s") for x in runs], avg(runs, "stream_wu"),
            avg(runs, "conn_wu"), avg(runs, "wu_avg_kb"), avg(runs, "client_blocked_s"),
            avg(runs, "client_max_block_ms"),
            " | ".join(lat(x["sink"]["big_ms"]) for x in runs if "sink" in x), fails or "ok"))
    s = r["slow_3mb"]
    print("  slow 3MB/s  MB/s %s  streamWU %s  maxblock %s ms  %s" % (
        s.get("mb_s"), s.get("stream_wu"), s.get("client_max_block_ms"), s.get("FAIL") or ("ok" if s.get("ok") else "BAD")))
    i = r["interactive"]
    print("  interactive bulk MB/s %s  bulkWU %s  probe ms p50/p99/max %s  %s" % (
        i.get("bulk_mb_s"), i.get("bulk_wu"), lat(i.get("probe_ms")), i.get("FAIL") or ("ok" if i.get("ok") else "BAD")))
    t = r["trickle"]
    print("  trickle     ms %s  WU %s  %s" % (lat(t.get("small_ms")), t.get("stream_wu"), t.get("FAIL") or ("ok" if t.get("ok") else "BAD")))
    p = r["pauses"]
    print("  pauses      ms %s  WU %s  blocked %s  %s" % (lat(p.get("small_ms")), p.get("stream_wu"), p.get("client_blocked_s"), p.get("FAIL") or ("ok" if p.get("ok") else "BAD")))
    e = r["exhaust"]
    print("  exhaust     wait ms %s  %s" % (e.get("wait_ms"), e.get("FAIL") or ("ok" if e.get("ok") else "BAD")))
    print("  last        %s" % r["last_portion"])
    print("  log         %s" % r["log_problems"])
