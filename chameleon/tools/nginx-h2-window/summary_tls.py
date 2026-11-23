import json
import statistics
import sys


def lat(s):
    return "%s/%s/%s" % (s["p50"], s["p99"], s["max"]) if s else "-"


for path in sys.argv[1:]:
    r = json.load(open(path))
    print("==", path.rsplit("/", 1)[-1])
    for kind, n in (("bulk_capped", 3), ("bulk_free", 2)):
        runs = [r["%s_%d" % (kind, i)] for i in range(1, n + 1)]
        good = [x for x in runs if x.get("ok")]
        print("  %-11s MB/s %s  WU-records(30B) %s  down-records %s  rec ms %s  top %s  %s" % (
            kind, [round(x["mb_s"], 2) for x in good],
            [x["wu_records_30"] for x in good], [x["down_records"] for x in good],
            " | ".join(lat(x["big_ms"]) for x in good), good[0]["top"] if good else "",
            "ok" if len(good) == n else [x.get("FAIL") for x in runs]))
    s = r["slow_3mb"]
    print("  slow 3MB/s  MB/s %s  WU %s  %s" % (round(s.get("mb_s", 0), 2), s.get("wu_records_30"), s.get("FAIL") or ("ok" if s.get("ok") else "BAD")))
    i = r["interactive"]
    print("  interactive bulk MB/s %s  WU %s  probe ms %s  %s" % (round(i.get("bulk_mb_s", 0), 2), i.get("wu_records_30"), lat(i.get("probe_ms")), i.get("FAIL") or ("ok" if i.get("ok") else "BAD")))
    t = r["trickle"]
    print("  trickle     ms %s  WU %s  %s" % (lat(t.get("small_ms")), t.get("wu_records_30"), t.get("FAIL") or ("ok" if t.get("ok") else "BAD")))
    p = r["pauses"]
    print("  pauses      ms %s  %s" % (lat(p.get("small_ms")), p.get("FAIL") or ("ok" if p.get("ok") else "BAD")))
    print("  last        byte %s  bare_end %s" % (r["last_last_byte"].get("FAIL") or r["last_last_byte"]["ok"], r["last_bare_end"].get("FAIL") or r["last_bare_end"]["ok"]))
