# YouTube TLS observation: first live attempt

Date: 2026-11-03. This attempt did not authenticate any recovered HTTP request.
The user observed two advertisements followed by normal video playback.

## Runtime result

- Existing non-root Mobile sender selected a fresh Chrome native export.
- Pi confirmed an active authenticated lease before the user opened Chrome.
- A separate snapshot of the existing Bridge ran under the observer service
  identity with its CPU/RAM limits; production backend was not replaced.
- 846 independently sampled statuses recorded up to 28 retained candidate keys.
- Recovered HTTP/2 headers: zero. Recovered HTTP/3 headers: zero.
- The Chrome export was nonempty (17,782 bytes at the inspected moment). Its
  contents were not copied to the development computer or printed.
- The old counter reached 15 capture_loss events. Their cause cannot be
  determined retrospectively because both libpcap drops and QUIC Initial
  fragment conflicts used that counter. These are not 15 proven dropped packets.
- A 30-minute independent rollback stopped the observer and restored the saved
  configuration. The timer was not automatically restarted.

No claim is made that advertisements were decrypted or distinguished from
ordinary video. Normal playback is evidence only for the user's observed
session; it is not a complete failure-isolation acceptance.

## Diagnostic implementation

The new request_category_diagnostics configuration is disabled by default.
When explicitly enabled, authenticated Bridge header events produce at most
24 in-memory observations. They retain a generated flow ID, relative time,
protocol and enumerated host/route categories. Full domains, paths, queries,
cookies, headers, bodies, video IDs and secrets are not returned. Reset clears
these observations. Status still states ad_content_classified=false.

The categories player_api, media_request and ad_telemetry are endpoint types,
not conclusions about response contents. In particular a videoplayback request
is not by itself evidence of an advertisement. The existing Bridge excludes
query parameters and inspects request headers only, not player response bodies.
Even successful category recovery alone would not establish safe selective
blocking or permission to terminate a shared connection.

After the failed attempt, diagnostics were corrected locally to distinguish
quic_initial_fragment_conflict from capture_loss. The agent also records actual
libpcap dropped-packet deltas separately as capture_dropped_packets. Both causes
still invalidate observation state; no uncertainty is promoted to Decrypted.
These corrections have not yet been deployed in a repeated live attempt.

## Checks and preservation

The first category implementation passed 20 contract/regression tests on Windows
and Pi. The subsequent diagnostic distinction passes 21 tests locally, including
a conflicting-Initial regression. No packet-count or memory limits were blindly
increased. No packet-blocking API, firewall rule or routing change was added.

Before/after raw firewall snapshots were retained root-only in
/var/lib/easypi/rollback/youtube-observer-20261103. Rules matched after excluding
generated comments (chain counters were normalized by the comparison helper).
Raw output hashes differed. Unlike the earlier historical test, this attempt
has full snapshots available for later comparison.

The service runtime override was removed by independent rollback. A private
source snapshot and isolated Python environment remain under
/opt/EasyPi/.runtime/youtube-observer-20261103; they do not auto-start. The regular
configuration was restored byte-for-byte. Server evidence SHA-256 for status.jsonl:
5f18d5cec3262c42c97225ee18068c749fbc894b3d6a75a188f33821e657f3a6.

The user confirmed stopping delivery and returning the diagnostic flag to
Default. Chrome was then stopped, the exact test export and empty directory
deleted, and the command-line file removed only after matching the expected
test arguments. The sender service was absent. Default flag state was confirmed
by the user, not independently rechecked in the UI. The document read grant
has not been independently revoked; Forget export permission remains available.
Flash/RAM forensic erasure is not guaranteed. RuntimeMaxSec left a failed unit
state; reset-failed cleared that historical marker after rollback, without
restarting it. The observer is inactive/disabled; backend, NetProtection and
FlowGraph remain active.
No PCAP or captured secrets are included in this commit.

## Next acceptance

Retain this failed result. First repeat a short new-session check with the two
failure reasons separated and actual libpcap deltas, then obtain authenticated
headers. Only after that correlate user-labelled advertisement and content
intervals. The passive observer cannot delete individual encrypted responses;
any future selective intervention needs a separately justified mechanism and
proof that ordinary playback is preserved. This attempt does not provide it.
