#!/bin/sh
# Isolated Chameleon load stand inside WSL (run as root in WSL only).
#
#   devices (netns clb-dev) --15 ms each way--> nginx 10.200.0.1:443 (patched,
#   1m buffer, Ubuntu-default main config) -> chameleon-server (nginx mode)
#   --5 ms each way--> origin 11.0.0.1:8080 (netns clb-net, "the internet")
#
# nginx + server share one cgroup "clb": 1 CPU (pinned to CPU 0 + 100% quota),
# memory.max = RAM - 200 MB (OS reserve), no swap; the server sits in a child
# cgroup with the production unit's MemoryHigh=60% / MemoryMax=75% of RAM.
# The load generator and the origin run on the other CPUs.
#
# usage: run_load.sh <work-dir> <series...>
#   series: "<ram_mb>:<mode>:<counts>[:limits]"  e.g. 1024:idle:10,25,50,100,200
#   limits: "prod" uses the deployed max_connections 100 / max_sessions_per_source 8,
#           default lifts them to measure the machine, not the configuration.
#   5th field: nginx worker_connections (default 768, Ubuntu's value), e.g.
#           2048:active:200::4096
# env: WARM_S, MEASURE_S
set -eu
W="$1"; shift
HERE=$(cd "$(dirname "$0")" && pwd)
CG=/sys/fs/cgroup/clb
WARM_S=${WARM_S:-20}; MEASURE_S=${MEASURE_S:-120}

# Kill everything in the stand's cgroup (server + nginx) and remove it.
stop_stand() {
    if [ -d "$CG" ]; then
        echo 1 > "$CG/cgroup.kill" 2>/dev/null || true
        i=0
        while [ $i -lt 150 ]; do
            for g in "$CG/server" "$CG/nginx" "$CG"; do [ -d "$g" ] && rmdir "$g" 2>/dev/null || true; done
            [ -d "$CG" ] || break
            sleep 0.2; i=$((i + 1))
        done
    fi
    if [ -d "$CG" ]; then
        echo "FATAL: stand cgroup still busy"
        for p in $(cat "$CG"/cgroup.procs "$CG"/*/cgroup.procs 2>/dev/null); do ps -o pid,stat,cmd -p "$p" | tail -1; done
        exit 1
    fi
}

cleanup() {
    stop_stand
    [ -n "${ORIGIN:-}" ] && kill "$ORIGIN" 2>/dev/null || true
    sleep 1
    ip netns del clb-dev 2>/dev/null || true
    ip netns del clb-net 2>/dev/null || true
    ip link del clb-vps 2>/dev/null || true
    ip link del clb-wan 2>/dev/null || true
    ip route del 11.0.0.1/32 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# ---- network ----
ip netns add clb-dev
ip netns add clb-net
ip link add clb-vps type veth peer name clb-devp
ip link set clb-devp netns clb-dev
ip addr add 10.200.0.1/30 dev clb-vps
ip link set clb-vps up
ip -n clb-dev addr add 10.200.0.2/30 dev clb-devp
ip -n clb-dev link set lo up
ip -n clb-dev link set clb-devp up
tc qdisc add dev clb-vps root netem delay 15ms limit 200000
ip netns exec clb-dev tc qdisc add dev clb-devp root netem delay 15ms limit 200000
ip link add clb-wan type veth peer name clb-netp
ip link set clb-netp netns clb-net
ip addr add 10.201.0.1/30 dev clb-wan
ip link set clb-wan up
ip -n clb-net addr add 10.201.0.2/30 dev clb-netp
ip -n clb-net addr add 11.0.0.1/32 dev lo
ip -n clb-net link set lo up
ip -n clb-net link set clb-netp up
ip route add 11.0.0.1/32 via 10.201.0.2
tc qdisc add dev clb-wan root netem delay 5ms limit 200000
ip netns exec clb-net tc qdisc add dev clb-netp root netem delay 5ms limit 200000

# ---- origin ----
ip netns exec clb-net taskset -c 2-11 runuser -u sb -- env LOAD_MODE=origin LOAD_ORIGIN_LISTEN=11.0.0.1:8080 \
    "$W/load.test" -test.run '^TestChameleonLoad$' -test.timeout 0 > "$W/origin.log" 2>&1 &
ORIGIN=$!

step() { # ram mode count limits worker_connections
    ram=$1; mode=$2; n=$3; limits=$4; wc=${5:-768}
    label="${ram}-${mode}-${n}${limits:+-$limits}"
    [ "$wc" = 768 ] || label="$label-wc$wc"
    # 768 = Ubuntu default (deployed); a larger value separates the nginx
    # setting from the machine's own limit.
    sed -i -e "s/worker_connections [0-9]*;/worker_connections $wc;/" "$W/ngx/conf/nginx.conf"
    sed -i -e '/^worker_rlimit_nofile/d' "$W/ngx/conf/nginx.conf"
    [ "$wc" = 768 ] || sed -i -e "s/^worker_processes 1;/worker_processes 1;\nworker_rlimit_nofile $((wc * 4));/" "$W/ngx/conf/nginx.conf"
    RUN="$W/runs/$label"
    rm -rf "$RUN"; mkdir -p "$RUN"; chown sb "$RUN"
    if [ "$limits" = prod ]; then maxc=100; maxsrc=8; else maxc=1000; maxsrc=1000; fi
    python3 - "$W/srv/server_config.json" "$maxc" "$maxsrc" <<'PY'
import json, sys
path, maxc, maxsrc = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
cfg = json.load(open(path))
cfg["max_connections"], cfg["max_sessions_per_source"] = maxc, maxsrc
json.dump(cfg, open(path, "w"), indent=2)
PY
    chown sb "$W/srv/server_config.json"
    if ss -ltn | grep -qE '127.0.0.1:9080 |10.200.0.1:443 |127.0.0.1:8443 '; then
        echo "FATAL: stand ports still in use"; exit 1
    fi
    # fresh cgroups, so memory.peak belongs to this step
    mkdir -p "$CG"
    echo "+cpu +memory +pids" > "$CG/cgroup.subtree_control"
    echo "100000 100000" > "$CG/cpu.max"
    echo $(( (ram - 200) * 1048576 )) > "$CG/memory.max"
    echo 0 > "$CG/memory.swap.max"
    mkdir -p "$CG/server" "$CG/nginx"
    echo $(( ram * 1048576 * 60 / 100 )) > "$CG/server/memory.high"
    echo $(( ram * 1048576 * 75 / 100 )) > "$CG/server/memory.max"
    echo 0 > "$CG/server/memory.swap.max"
    echo 512 > "$CG/server/pids.max"
    (cd "$W/srv" && sh -c 'echo $$ > '"$CG"'/server/cgroup.procs; ulimit -n 65536; exec taskset -c 0 runuser -u sb -- ./chameleon-server' > "$RUN/server.log" 2>&1 &)
    sh -c 'echo $$ > '"$CG"'/nginx/cgroup.procs; ulimit -n 1024; exec taskset -c 0 '"$W"'/nginx -p '"$W"'/ngx/ -c conf/nginx.conf' > "$RUN/nginx.log" 2>&1
    sleep 2
    if ! ss -ltn | grep -q '127.0.0.1:9080 ' || ! ss -ltn | grep -q '10.200.0.1:443 '; then
        echo "FATAL: server or nginx did not start"; tail -3 "$RUN/server.log" "$RUN/nginx.log"; exit 1
    fi
    taskset -c 1 python3 -I "$HERE/sampler.py" "$CG" "$RUN" "$RUN/samples.jsonl" &
    SAMPLER=$!
    ip netns exec clb-dev taskset -c 2-11 runuser -u sb -- env LOAD_MODE="$mode" LOAD_DEVICES="$n" \
        LOAD_SERVER=10.200.0.1:443 LOAD_ORIGIN=11.0.0.1:8080 LOAD_KEYS="$W/keys.json" \
        LOAD_WARM_S="$WARM_S" LOAD_MEASURE_S="$MEASURE_S" LOAD_MARK="$RUN/mark" LOAD_OUT="$RUN/load.json" \
        "$W/load.test" -test.run '^TestChameleonLoad$' -test.timeout 60m > "$RUN/load.log" 2>&1 || true
    touch "$RUN/stop"; wait "$SAMPLER" 2>/dev/null || true
    grep -c "worker_connections are not enough" "$W/ngx/chameleon-error.log" > "$RUN/nginx_wc_errors" 2>/dev/null || true
    cp "$W/ngx/chameleon-error.log" "$RUN/nginx-error.log" 2>/dev/null || true
    : > "$W/ngx/chameleon-error.log"
    python3 -I "$HERE/evaluate.py" "$RUN" "$ram" "$label" > "$RUN/row.json"
    stop_stand
    cat "$RUN/row.json" >> "$W/results.jsonl"
    cut -c1-300 "$RUN/row.json"
}
for series in "$@"; do
    ram=$(echo "$series" | cut -d: -f1); mode=$(echo "$series" | cut -d: -f2)
    counts=$(echo "$series" | cut -d: -f3 | tr , ' '); limits=$(echo "$series" | cut -d: -f4)
    wc=$(echo "$series" | cut -d: -f5)
    for n in $counts; do
        step "$ram" "$mode" "$n" "$limits" "${wc:-768}"
        if tail -1 "$W/results.jsonl" | grep -q '"overload": \[\]'; then :; else
            echo "overload at $series n=$n - series stopped"
            break
        fi
    done
done
echo ALL DONE
