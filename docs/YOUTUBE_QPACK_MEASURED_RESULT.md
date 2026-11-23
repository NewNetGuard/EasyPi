# YouTube measured QPACK table-capacity result

Date: 2026-11-03.

## Outcome

The user observed two advertising blocks followed by normal video playback.
The passive observer recovered two request headers: one HTTP/3 YouTube watch-page
request and one HTTP/2 request classified as other. No advertising request was
positively identified. Advertisement blocking was not enabled or validated.

Three QUIC flows with matching session keys failed at
`limits.qpack_table_capacity`: requested **65,536 bytes**, allowed **4,096 bytes**.
Their retained measurements showed 57, 2 and 1 authenticated QUIC packets before
rejection. This is a real peer table-capacity request measured in the live test,
not the earlier generated fixture. The static-entry length correction alone
therefore does not remove the observed table-capacity barrier.

A separate QUIC flow authenticated three packets but timed out waiting for
headers (`timeouts.headers`). A TCP flow with available keys also timed out.
Later, three additional QUIC flows closed with `timeouts.missing_key`; these
must not be conflated with invalid secrets or the QPACK capacity failures.
The six-entry recent-closed window rotated, so preserved polling history is
necessary to retain the earlier table failures.

## Counters and limits

The final independent-monitor sample recorded 12,198 capture packets, nine
opened/closed flows, two headers, zero reported capture losses, zero dropped
Bridge events, zero key-store-full events and zero resource rejections.
Peak reserved Bridge memory was 4,784,128 bytes. This is a reservation counter,
not measured process RSS. No resource limits changed.

Capture was limited to 16 IPv4 destinations and explicitly incomplete.
Missing-handshake and unregistered-server packet counters were nonzero; they
are packet counts, not a count of failed connections. IPv6 and out-of-scope
addresses remain coverage limitations. Zero reported drops does not establish
complete capture or complete YouTube coverage.

## Cleanup and isolation

The independent monitor had zero failed polls at the saved checkpoint. Its
sanitized history and raw remote history SHA-256 were preserved in the ignored
Mobile `.build/youtube-qpack-measure` evidence directory, with a SHA-256 manifest.
No TLS-secret values, cookies, full viewing URLs, or bodies entered this report.

The observer and monitor were stopped, cleanup timer cancelled, runtime service
override removed and original observer configuration hash verified unchanged.
Normalized IPv4 and IPv6 firewall rules matched their pre-test snapshots.
Backend, NetProtection and the correctly named `easypi-prism-flowgraph` service
were active. Chameleon mobile-link/DNS services remained active; no Chameleon
configuration write or restart was performed. This is not a full independent
hash-based attestation of every production file.

Mobile delivery was stopped and its document grant forgotten, both verified in
the UI. The user confirmed returning the Chrome flag to Default. Chrome was
stopped, the exact expected test command-line file removed, and the exact
export file and now-empty test directory removed. This is ordinary deletion,
not a claim of forensic erasure.

## Next acceptance gate

Before another viewing, calculate and measure a bounded 65,536-byte QPACK
capacity configuration, including native decoder memory and metadata overhead
at maximum concurrent flows. Preserve header/stream/global limits; reject
larger requests. Add exact-capacity, over-capacity, rotation and concurrent-flow
regressions and run existing H2/H3 positive/negative controls. Raising the table
capacity alone must not imply a larger decoded-header allowance.

A subsequent scoped test must show continued authenticated decoding beyond the
capacity instruction, no new loss/limit regressions, and independently attributed
advertising requests before any selective-blocking experiment. A decrypted
watch page is insufficient evidence to block shared video-CDN connections.
