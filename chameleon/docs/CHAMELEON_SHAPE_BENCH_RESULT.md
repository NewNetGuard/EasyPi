# Chameleon carrier shape after the Chrome 157 and recovery changes

Date: 2026-11-17. Candidate build (Chrome 157 ClientHello, stray-packet
drop, session recovery after a server restart, downlink takeover, session
quota per client instance) plus the bench settle fix below. Chameleon code and
keepalive intervals were not changed for this measurement.

Workload: `scripts/dev/chameleon_shape_bench.sh` with `BENCH_RESTART_CLIENT=1`,
one cycle. The carrier was captured on the VPS; the covered computer was moved
off the EasyPi network so only bench traffic used the tunnel. The full report
is `CHAMELEON_SHAPE_BENCH_RESULTS.json`.

## Bench fix

`idle1` starts right after the client restart and the probe request. Without
a pause it absorbed the carrier handshake, the tail of the probe connection
and late packets of flows from before the restart, which raised it to 81
packets/min. A separate capture showed the client itself sends only 2 carrier
packets per 10 s once settled, and nothing passes inside the tunnel. The bench
now waits 20 s after the probe before `idle1`.

## Result

| Metric | Previous build | No settle | Settled 20 s |
|---|---|---|---|
| JA4 | t13d1516h2_8daaf6152771_806a8c22fdea | t13d1517h2_…_33f857a189cb | t13d1517h2_…_937be626dbce |
| Carrier connections over 1 MB | 1 | 1 | 1 |
| Opened within 1 s (max) | 1 | 1 | 1 |
| idle1 packets/min | 7 | 81 | 8 |
| browse packets/min | 1,237 | 1,111 | 1,395 |
| stream packets/min | 20,748 | 22,709 | 22,835 |
| stream KB down/min | 23,899 | 23,687 | 23,782 |
| bulk KB down/min | 1,090,408 | 995,283 | 1,090,759 |
| idle2 packets/min | 83 | 74 | 59 |
| Most common down records (bytes) | 30, 16401, 35 | 16401, 35, 30 | 16401, 35, 30 |
| Client writes per download second | — | 43.6 | 43.2 |

The JA4 prefix now matches current Chrome; the last segment varies per
connection because the signature-algorithm list starts with a random GREASE
value, as in Chrome. The `33f857a189cb` variant was also seen on real Chrome
157 connections. One long-lived carrier connection served the whole run
(the second connection in each report is the one closed by the restart).
Stream and bulk phases are within run-to-run variation. With the settle pause
the first idle phase matches the earlier baseline.

## Unchanged and open

During downloads the client still writes about 43 times per second and the
server answers each write with a small control record (30-byte HTTP/2
WINDOW_UPDATE from nginx). This rhythm was not addressed here. The idle2
figures include the tail of the bulk download.
