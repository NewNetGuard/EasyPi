# YouTube observer recovery candidate

Date: 2026-11-03. Builds on the failed attempt documented in
YOUTUBE_TLS_OBSERVATION.md. No additional browser viewing or secret collection
was performed for these checks.

## Proven local defect

A conflict in one QUIC Initial CRYPTO assembly reset the entire ChromeObserver:
all flows, stored keys and the authorized device lease were discarded. The
failure was reproducible with a conflicting Initial alongside a valid generated
TLS 1.3 / HTTP/2 connection. This establishes an isolation defect, not the cause
of the historical 15 ambiguous capture_loss observations.

The candidate now marks the conflicting flow Unknown through its abort reason,
closes that flow and removes its endpoint mapping. It retains the device lease
and other flows' keys. It never feeds contradictory fragment contents onward.
An integration regression verifies that the unrelated HTTP/2 trace completes
authenticated header recovery after the conflict. Actual capture loss still
resets observation state conservatively. No network packet is modified.

## Capture scheduling

The old capture loop always waited 10 milliseconds after at most 64 packets.
Ignoring decoding work, this imposes an approximate 6,400-packet/second ceiling;
it is not a measured throughput result for Pi. Video bursts can exceed such a
drain rate. Whether that happened during the failed attempt is unproven because
libpcap deltas were not independently retained.

The candidate retains the 64-packet batch and releases its shared lock between
batches. A full batch requests immediate rechecking; an incomplete batch uses
the original idle wait. The stop event is checked on every iteration. Existing
systemd CPU/RAM constraints are unchanged. No packet buffer or key-store limits
were enlarged and no packet blocking was introduced.

New secret-free counters distinguish capture_packets_read, capture_full_batches,
capture_dropped_packets and quic_initial_fragment_conflict. capture_loss retains
its conservative meaning for actual capture-loss reset events. Synthetic tests
verify bounded burst draining, idle backoff selection and exact drop deltas.
Runtime CPU load, fairness and burst-loss behavior require the next live check.

## Validation and runtime state

- Windows: 24 passed across ChromeObserver contract, diagnostics and capture
  batch tests, including generated H2/H3 positive and negative controls.
- Raspberry Pi isolated environment: the same 24 passed.
- The previous inactive observer snapshot was backed up before updating its
  source. No production backend executable or active service was replaced.
- No device flags, exports, routes, firewall rules or Chameleon configuration
  were changed during this candidate preparation. No service was restarted.
- This is not a new successful YouTube decryption result. The first live attempt
  remains zero recovered headers and an undetermined original reset cause.

Next: activate a fresh short-lived observer with source-specific diagnostics,
confirm new authenticated headers before interpreting any advertising, then
compare user-labelled ad/content intervals. Do not classify a media_request as
an advertisement merely because an ad was visible during its connection.
