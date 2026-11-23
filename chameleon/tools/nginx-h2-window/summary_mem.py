import json
import sys

rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
mb = lambda kb: kb / 1024
for mode in ("idle", "active", "stalled"):
    print("== mode", mode)
    print("%-8s %-5s %8s %8s %8s %8s | %8s %8s %8s  %s" % (
        "variant", "strm", "RSS0", "RSS1", "dRSS", "peakHWM", "VIRT0", "VIRT1", "dVIRT", "err"))
    for r in rows:
        if r["mode"] != mode:
            continue
        b, a = r["before"], r["after"]
        print("%-8s %-5d %8.1f %8.1f %8.1f %8.1f | %8.1f %8.1f %8.1f  %s" % (
            r["variant"] + " " + r["buf"], r["streams"], mb(b["VmRSS"]), mb(a["VmRSS"]),
            mb(a["VmRSS"] - b["VmRSS"]), mb(a["VmHWM"]), mb(b["VmSize"]), mb(a["VmSize"]),
            mb(a["VmSize"] - b["VmSize"]), r["open_errors"]))
