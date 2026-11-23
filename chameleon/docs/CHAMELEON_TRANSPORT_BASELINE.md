# Chameleon transport baseline (packet tunnel)

Date: 2026-11-17. Candidate build (packet transport: IPv4 packets carried
in one HTTP/2 connection through nginx). Measured from the Pi with
`scripts/dev/chameleon_transport_baseline.sh`: the same workload through the
Stealth tunnel (`cham0`) and directly (`eth0`), one after the other. The
covered computer was off the EasyPi network. Full data:
`CHAMELEON_TRANSPORT_BASELINE.json`. This is the reference for comparing a
stream-based TCP transport under the same conditions.

Limits of this run: one location, one time of day, three runs per transfer
test, two runs of the parallel test; the carrier shape covers the tunnel
run only (direct traffic does not pass the VPS).

## Throughput and Pi load (median of runs, min-max in brackets)

| Test | Tunnel MB/s | Direct MB/s | Pi CPU, tunnel / direct | Client CPU (% of one core) |
|---|---|---|---|---|
| Download 50 MB, Cloudflare | 13.65 (13.60-14.13) | 20.13 (19.88-20.13) | 25% / 15% | 49% |
| Download 50 MB, Hetzner FSN1 | 5.28 (4.75-8.16) | 19.99 (19.22-19.99) | 16% / 16% | 24% |
| Upload 25 MB, Cloudflare | 1.45 (1.44-1.78) | 10.10 (10.09-10.10) | 7% / 9% | 14% |
| 4 parallel downloads, Cloudflare | 14.11 (13.98-14.23) | 20.23 (20.17-20.29) | 33% / 18% | 56% |

Pi CPU is the share of all four cores. The Hetzner result through the
tunnel depends on the VPS-to-Hetzner path as well as on the transport; it is
not attributable to the transport alone. Upload through the tunnel is limited
by the nginx HTTP/2 receive window (64 KB per stream), measured earlier.

## Opening sites (6 sites x 3 rounds, median of 18)

| | Connect | TLS done | First byte | Total |
|---|---|---|---|---|
| Tunnel | 43 ms | 99 ms | 162 ms | 410 ms (262-1323) |
| Direct | 21 ms | 53 ms | 86 ms | 172 ms (147-302) |

## Carrier seen by an observer (tunnel run)

One carrier connection carried the whole run (767 MB, 2.3 min). During
full-speed downloads the client wrote 205 times per download second (gap
p10/p50/p90 = 0/1/9 ms), and the most common records from the server were
16,401 bytes (data), 35 bytes and 30 bytes (HTTP/2 control records). Each
client write was followed by a small server record in 78% of cases. Per
phase:

| Phase | Packets/min | KB up/min | KB down/min |
|---|---|---|---|
| download | 198,096 | 23,319 | 588,370 |
| upload | 113,898 | 114,902 | 9,177 |
| sites | 49,548 | 6,837 | 78,254 |
| parallel | 377,406 | 59,245 | 1,028,410 |
| direct runs (tunnel idle) | 23 | 4 | 1 |

What an observer can attribute these client writes to is not measured here;
the outer records are encrypted and only sizes, directions and timing are
visible.
