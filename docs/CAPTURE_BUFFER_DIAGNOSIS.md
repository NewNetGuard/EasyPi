# Chrome observer capture-buffer diagnosis

Date: 2026-11-03. Investigates the 1,212 libpcap-reported drops in the failed
YouTube repeat. No phone operation or new browsing was required.

## Reproduced cause

The Chrome observer forced libpcap immediate mode with snaplen 65,575 and a
4-MiB buffer. On Pi's libpcap 1.10.5, immediate mode selects TPACKET_V2, whereas
buffered mode selects TPACKET_V3. Both selections were checked on actual capture
socket descriptors using PACKET_VERSION, not inferred from a library banner.

The upstream [libpcap 1.10.5 Linux implementation](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap-linux.c)
explicitly excludes V3 when immediate mode is requested. Its V2 ring uses
fixed-sized frames derived from the snapshot size and link properties; V3
stores multiple variable-sized packets in blocks. Large snaplen makes V2
inefficient for bursts of small packets. A configured byte budget alone does
not establish adequate packet capacity.

The [libpcap statistics contract](https://man7.org/linux/man-pages/man3/pcap_stats.3pcap.html)
distinguishes ps_drop (capture buffer overflow) from ps_ifdrop (interface/driver).
The failed YouTube attempt had summed these, so their historical individual
values cannot now be recovered. At diagnosis time eth0 reported zero RX errors,
RX dropped/missed and TX errors/dropped; that does not replace historical
per-capture statistics.

## Controlled Pi reproduction

Only loopback UDP was used, with a dedicated local sender/receiver. No external
traffic, phone, network namespace, route, firewall change, production service
restart or saved payload capture was involved. Each datagram carried a generated
sequence number and 1,196 filler bytes. The reader started after the burst and a
10-ms sleep, reproducing a short interruption of capture draining. Source was
identical except for immediate versus buffered mode. Snaplen and buffer size
were identical in all comparisons.

| Mode | Sent | Application received | Capture read | ps_drop | ps_ifdrop |
|---|---:|---:|---:|---:|---:|
| Immediate / V2 | 128 | 128 | 32 | 192 | 0 |
| Immediate / V2 | 512 | 512 | 32 | 960 | 0 |
| Buffered / V3 | 128 | 128 | 128 | 0 | 0 |
| Buffered / V3 | 512 | 512 | 512 | 0 | 0 |

Linux loopback statistics count both directions; ps_recv was twice the sent
datagrams, whereas libpcap delivered one observed copy. Therefore ps_drop must
not be subtracted directly from application receive counts. The difference
between modes and the actual captured sequence numbers establish the loss in
the observer's capture path. Ordinary application delivery remained complete.

This proves a real mode-dependent burst-loss mechanism under the configured
capture budget, without a decoder present. It does not prove that this mechanism
accounts for every historical YouTube drop or that CPU throttling never
contributes. Real YouTube coverage and authenticated request recovery still
require another live test.

## Fix

LiveCapture now accepts an explicitly boolean immediate_mode option. Its default
remains True for existing collectors. Chrome's multi-flow agent explicitly
requests False, retaining the existing 100-ms packet buffer timeout, 4-MiB
buffer, snaplen, filtering, read batches, CPU and RAM limits. The batching delay
is below the existing seconds-scale key wait, but end-to-end latency remains
to be measured live. No guarantee is made that this libpcap timeout is a hard
real-time delivery bound on every platform.

This changes how observed copies are buffered. It cannot delay or modify actual
browser traffic. Loss invalidation and AEAD verification remain strict. No key
store size, privileges, device scope or filtering permissions were expanded.

## Regression and deployment status

- Existing Windows Chrome contract/capture/diagnostic checks: 24 passed.
- Three new Linux-only opt-in cases: single packet, burst of 128, burst of 512.
  Each verifies every generated sequence number at both the receiver and the
  buffered capture, zero capture drops and cleanup in finally.
- Pi full relevant set: 27 passed, zero failures.
- Pi burst/single-packet cases repeated in a transient cgroup with CPUQuota=25%,
  MemoryMax=256M, MemorySwapMax=0: 3 passed.
- Isolated inactive runtime source snapshot updated; ordinary observer service
  remains stopped, production backend and other services were not replaced.
- No real TLS-secret values, private URLs, PCAP or captured payload were saved.

Sanitized figures are in CAPTURE_BUFFER_RESULTS.json. Private evidence is in
EasyPi-Mobile/.build/capture-buffer-diagnosis with SHA-256 manifest. The Pi also
retains the original comparison JSON in the repeat rollback directory.

The missing independent status time series from the failed repeat is a separate
instrumentation problem. Its collector exited when the observer's socket was
temporarily unavailable during preparation. Before another browser run it must
be started after service readiness or made to reconnect, and its heartbeat/file
creation verified. Neither historical failure is erased by these corrections.

Rollback: revert this task commit and restore the prior inactive observer source
snapshot if desired. No data schema or persistent runtime configuration changed.
