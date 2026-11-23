#!/usr/bin/env bash
# Transport baseline: the same workload through the Stealth tunnel (cham0) and
# directly (eth0) from the Pi, plus the carrier's shape on the VPS for the
# tunnel run. Used to compare transport variants under identical conditions.
# When Stealth carries device TCP as streams (rule pref 5092 present), the
# workload also runs through that path ("streams"): for the run, TCP of an
# otherwise unused uid gets the Stealth device mark, so the Pi's own transfers
# take the same path as a covered device's.
#
# Usage: chameleon_transport_baseline.sh PI_SSH VPS_SSH CLIENT_PUBLIC_IP OUT_PREFIX
#
# Writes OUT_PREFIX.json (combined report) and OUT_PREFIX.raw (Pi measurements).
# Covered devices should stay off the tunnel during the run.
set -euo pipefail
pi=$1 vps=$2 client_ip=$3 out=$4
here="$(cd "$(dirname "$0")" && pwd)"
work=/var/tmp/chameleon-baseline

ssh -o BatchMode=yes "$vps" "rm -rf $work && mkdir -p $work && chmod 700 $work && \
  (nohup timeout 1500 tcpdump -Z root -ni any -s 0 -w $work/carrier.pcap \
   'host $client_ip and tcp port 443' >/dev/null 2>&1 &)"
sleep 2

# The workload prints "MARK <epoch> <phase>" and "R <iface> <test> ..." lines.
ssh -o BatchMode=yes "$pi" 'bash -s' > "$out.raw" <<'WORKLOAD'
set -u
cpu() { awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}' /proc/stat; }
pid=$(systemctl show -p MainPID --value easypi-chameleon-client)
pcpu() { if [ "${pid:-0}" -gt 0 ] 2>/dev/null; then awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo 0; else echo 0; fi; }
mark() { echo "MARK $(date +%s.%N) $1"; }
STREAM_UID=65533
streams=false
if ip rule show pref 5092 2>/dev/null | grep -q lookup; then
  streams=true
  sudo -n iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner $STREAM_UID -j MARK --set-mark 0x51822
  trap 'sudo -n iptables -t mangle -D OUTPUT -p tcp -m owner --uid-owner '$STREAM_UID' -j MARK --set-mark 0x51822' EXIT
fi
# xcurl PATH curl-args...: curl through cham0/eth0, or as the stream uid.
xcurl() {
  local path=$1; shift
  if [ "$path" = streams ]; then
    sudo -n setpriv --reuid=$STREAM_UID --regid=$STREAM_UID --clear-groups curl -4 "$@"
  else
    curl -4 --interface "$path" "$@"
  fi
}
fmt='%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{size_download} %{size_upload}'
# run IFACE TEST curl-args...: one transfer with system and client CPU deltas.
run() {
  local iface=$1 test=$2; shift 2
  local t0 i0 t1 i1 p0 p1 r
  read -r t0 i0 < <(cpu); p0=$(pcpu)
  r=$(xcurl "$iface" -s -o /dev/null -m 180 -w "$fmt" "$@" 2>/dev/null)
  [ -n "$r" ] || r="000 0 0 0 0 0 0"
  read -r t1 i1 < <(cpu); p1=$(pcpu)
  echo "R $iface $test $r $((t1 - t0)) $((i1 - i0)) $((p1 - p0))"
}
head -c 25000000 /dev/urandom > /tmp/baseline-up.bin
chmod 644 /tmp/baseline-up.bin
paths="cham0 eth0"
$streams && paths="streams cham0 eth0"
for iface in $paths; do
  # Carrier phases: the packet tunnel keeps its names; streams are prefixed.
  pre=""; [ "$iface" = streams ] && pre="streams_"
  tunnel=false; [ "$iface" != eth0 ] && tunnel=true
  $tunnel && mark "${pre}download"
  for i in 1 2 3; do
    run "$iface" dl_cloudflare "https://speed.cloudflare.com/__down?bytes=50000000"
    run "$iface" dl_hetzner -r 0-49999999 "https://fsn1-speed.hetzner.com/100MB.bin"
  done
  $tunnel && mark "${pre}upload"
  for i in 1 2 3; do
    run "$iface" upload --data-binary @/tmp/baseline-up.bin "https://speed.cloudflare.com/__up"
  done
  $tunnel && mark "${pre}sites"
  for i in 1 2 3; do
    for site in https://www.wikipedia.org/ https://www.bbc.com/ https://github.com/ \
                https://www.google.com/ https://www.cloudflare.com/ https://www.apple.com/; do
      run "$iface" "site_${site#https://}" "$site"
    done
  done
  $tunnel && mark "${pre}parallel"
  for i in 1 2; do
    read -r t0 i0 < <(cpu); p0=$(pcpu); s=$(date +%s.%N)
    for n in 1 2 3 4; do
      xcurl "$iface" -s -o /dev/null -m 180 -w '%{size_download}\n' \
        "https://speed.cloudflare.com/__down?bytes=25000000" > "/tmp/baseline-par.$n" &
    done
    wait
    e=$(date +%s.%N); read -r t1 i1 < <(cpu); p1=$(pcpu)
    bytes=$(cat /tmp/baseline-par.* | awk '{s+=$1} END{print s}')
    echo "P $iface parallel4 $(echo "$e - $s" | bc) $bytes $((t1 - t0)) $((i1 - i0)) $((p1 - p0))"
    rm -f /tmp/baseline-par.*
  done
  # After the stream run the next phase is the packet tunnel's own download.
  [ "$iface" = cham0 ] && mark direct_runs
done
mark end
rm -f /tmp/baseline-up.bin
WORKLOAD

grep '^MARK ' "$out.raw" | awk '{print $2, $3}' > "$out.phases"
ssh -o BatchMode=yes "$vps" "pkill -INT -f 'tcpdump.*$work/carrier.pcap' || true; sleep 2"
scp -q -o BatchMode=yes "$here/chameleon_shape_analyze.py" "$vps:$work/analyze.py"
scp -q -o BatchMode=yes "$out.phases" "$vps:$work/phases.log"
ssh -o BatchMode=yes "$vps" "cd $work && editcap -c 150000 carrier.pcap part.pcap >/dev/null && rm carrier.pcap && \
  systemd-run --scope --quiet -p MemoryMax=1G nice -n 19 \
  python3 analyze.py \"\$(ls part*.pcap* | sort | paste -sd,)\" $client_ip phases.log; rm -rf $work" > "$out.carrier.json"
python3 "$here/chameleon_transport_baseline_report.py" "$out.raw" "$out.carrier.json" > "$out.json" \
  || python "$here/chameleon_transport_baseline_report.py" "$out.raw" "$out.carrier.json" > "$out.json"
rm -f "$out.phases" "$out.carrier.json"
cat "$out.json"
