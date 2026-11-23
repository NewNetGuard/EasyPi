#!/usr/bin/env bash
# Reproducible traffic-shape bench for the Chameleon carrier.
#
# Drives a fixed workload through the EasyPi Stealth tunnel (cham0) on the
# Pi, captures the carrier on the VPS and prints passive-observer metrics.
# Run from a development machine with SSH key access to both hosts.
#
# Usage: chameleon_shape_bench.sh PI_SSH VPS_SSH CLIENT_PUBLIC_IP [REPORT.json]
#
# BENCH_CYCLES (default 1) repeats browse + stream with BENCH_IDLE seconds
# (default 300) of silence between cycles; one bulk download ends the run.
# The default single cycle keeps results comparable with earlier reports;
# BENCH_CYCLES=5 runs for about 45 minutes and shows connection lifetimes.
# BENCH_RESTART_CLIENT=1 restarts the Stealth client once capture is running,
# so the carrier's TLS ClientHello (JA4) is recorded; the tunnel is down for a
# few seconds and the kill switch blocks covered devices meanwhile.
# Other devices using the same tunnel must stay idle for clean idle phases.
set -euo pipefail

pi="${1:?Pi SSH target, e.g. pi@pi.example}"
vps="${2:?VPS SSH target, e.g. root@203.0.113.10}"
client_ip="${3:?client public IPv4 as seen by the VPS}"
report="${4:-chameleon-shape-report.json}"
cycles="${BENCH_CYCLES:-1}"
idle_between="${BENCH_IDLE:-300}"
[[ "$cycles" =~ ^[1-9][0-9]?$ && "$idle_between" =~ ^[0-9]{1,4}$ ]] || {
  echo "BENCH_CYCLES must be 1-99 and BENCH_IDLE 0-9999 seconds" >&2
  exit 2
}
here="$(cd "$(dirname "$0")" && pwd)"
work=/var/tmp/chameleon-bench
phases="$(mktemp)"
trap 'rm -f "$phases"' EXIT
capture_limit=$(( 900 + cycles * (420 + idle_between) ))

ssh -o BatchMode=yes "$vps" "rm -rf $work && mkdir -p $work && chmod 700 $work && \
  (nohup timeout $capture_limit tcpdump -Z root -ni any -s 0 -w $work/carrier.pcap \
   'host $client_ip and tcp port 443' >/dev/null 2>&1 &)"
sleep 2

if [[ "${BENCH_RESTART_CLIENT:-0}" == 1 ]]; then
  ssh -o BatchMode=yes "$pi" 'sudo -n systemctl restart easypi-chameleon-client.service && \
    for attempt in $(seq 60); do
      curl -s --interface cham0 -m 5 -o /dev/null https://www.wikipedia.org/ && exit 0
      sleep 1
    done; echo "Stealth client did not reconnect within a minute" >&2; exit 1'
  # Let the restart settle before idle1 starts: the carrier handshake, the
  # tail of the probe request and late packets of flows from before the
  # restart otherwise land in the first idle phase and inflate it.
  sleep 20
fi

ssh -o BatchMode=yes "$pi" "CYCLES=$cycles IDLE_BETWEEN=$idle_between bash -s" > "$phases" <<'WORKLOAD'
set -u
mark() { echo "$(date +%s.%N) $1"; }
get() { curl -s --interface cham0 -m 30 -o /dev/null "$@" || true; }
mark idle1; sleep 90
for cycle in $(seq "$CYCLES"); do
  mark browse
  for site in https://www.wikipedia.org/ https://www.bbc.com/ https://github.com/ \
              https://www.reddit.com/ https://www.kernel.org/ https://www.python.org/ \
              https://www.mozilla.org/ https://www.debian.org/ https://news.ycombinator.com/; do
    get "$site"; sleep "$((RANDOM % 8 + 4))"
  done
  mark stream
  get --limit-rate 300k "https://speed.cloudflare.com/__down?bytes=40000000" -m 90
  if [ "$cycle" -lt "$CYCLES" ]; then
    mark idle_between; sleep "$IDLE_BETWEEN"
  fi
done
mark bulk
get "https://speed.cloudflare.com/__down?bytes=90000000" -m 60
mark idle2; sleep 60
mark end
WORKLOAD

ssh -o BatchMode=yes "$vps" "pkill -INT -f 'tcpdump.*$work/carrier.pcap' || true; sleep 2"
scp -q -o BatchMode=yes "$here/chameleon_shape_analyze.py" "$vps:$work/analyze.py"
scp -q -o BatchMode=yes "$phases" "$vps:$work/phases.log"
# The VPS also runs the live server: split the capture so tshark's memory stays
# bounded, and cap the analysis so it can never push the server out of memory.
# The parts are kept for inspection if the analysis fails.
ssh -o BatchMode=yes "$vps" "cd $work && editcap -c 200000 carrier.pcap part.pcap && rm -f carrier.pcap && \
  systemd-run --scope --quiet -p MemoryMax=1G nice -n 19 \
  python3 $work/analyze.py \"\$(ls part_*.pcap | sort | paste -sd,)\" $client_ip $work/phases.log && rm -rf $work" | tee "$report"
