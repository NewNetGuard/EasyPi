# Samples the stand's cgroups and processes once a second until <run>/stop
# exists. Output: JSON lines with cumulative CPU (usec), memory and RSS.
import json
import os
import sys
import time

CG, RUN, OUT = sys.argv[1], sys.argv[2], sys.argv[3]


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


def kv(path):
    out = {}
    for line in read(path).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


def rss(pids):
    total = hwm = 0
    for pid in pids:
        for line in read("/proc/%s/status" % pid).splitlines():
            if line.startswith("VmRSS:"):
                total += int(line.split()[1])
            elif line.startswith("VmHWM:"):
                hwm += int(line.split()[1])
    return total, hwm


with open(OUT, "w") as out:
    while not os.path.exists(RUN + "/stop"):
        sample = {"t": time.time()}
        for name in ("", "/server", "/nginx"):
            key = name.strip("/") or "all"
            sample[key + "_cpu_usec"] = kv(CG + name + "/cpu.stat").get("usage_usec", 0)
            sample[key + "_throttled_usec"] = kv(CG + name + "/cpu.stat").get("throttled_usec", 0)
            sample[key + "_mem"] = int(read(CG + name + "/memory.current", "0") or 0)
            sample[key + "_mem_peak"] = int(read(CG + name + "/memory.peak", "0") or 0)
            events = kv(CG + name + "/memory.events")
            sample[key + "_oom_kill"] = events.get("oom_kill", 0)
            sample[key + "_mem_high_events"] = events.get("high", 0)
        for name in ("server", "nginx"):
            pids = read(CG + "/" + name + "/cgroup.procs").split()
            sample[name + "_rss_kb"], sample[name + "_hwm_kb"] = rss(pids)
            sample[name + "_procs"] = len(pids)
        out.write(json.dumps(sample) + "\n")
        out.flush()
        time.sleep(1)
