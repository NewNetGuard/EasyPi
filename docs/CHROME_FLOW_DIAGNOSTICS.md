# Chrome observer flow/key-stage diagnostics

Date: 2026-11-03. Follows the partial buffered YouTube result.
This task used synthetic tests only. No new browsing or secret collection ran.

## Added evidence

When the existing request_category_diagnostics opt-in is true, status now includes
flow_diagnostics and a description of the incomplete IPv4 capture scope. It
retains stage flags for at most the existing 16 admitted active flows and a ring
of six recently closed stage records. Entries deliberately omit flow IDs,
addresses, domains, ClientHello randoms and key values. Request categories remain
the separate previously bounded list; the stage list is not a new content log.

Each stage record contains:

- transport (TCP or QUIC);
- hello_seen: the observer obtained a session identifier, not proof of a full
  handshake or plaintext visibility;
- session_key_available: an unexpired candidate record matched that identifier,
  not proof that the candidate authenticated a packet;
- other_session_keys_seen: records for different identifiers existed while this
  identifier was known; this can coexist with matching keys;
- key_submissions: actual submission attempts, excluding an identical record
  already held in the flow's Secrets store;
- terminal reason, independently preserved cryptographic diagnostic, state and
  authenticated_headers flag for a closed flow.

Terminal reasons and diagnostic strings are allowlisted. Unrecognized values
become other, never raw decoder text. Reset clears stage records. No records are
persisted by the observer; existing authorized diagnostic sampling can save this
secret-free status. The maximum configured status shape is regression-tested
against the existing 8,192-byte private IPC response limit.

Additional counters identify packets_without_lease, packets_outside_scope and
unregistered_server_packets. Flow admission capacity is now counted when the
adapter's own MAX_FLOWS check rejects admission. The kernel capture filter means
packets_outside_scope alone cannot measure traffic never delivered to libpcap.
capture_scope.complete is explicitly false; the 16-address IPv4 allowlist does
not become a completeness or browser-attribution guarantee.

## Proven counter defect and fix

Bridge.add_key may retry buffered decryption and close a flow. Previously,
ChromeObserver._apply kept submitting the remaining labels to that already
closed flow, increasing key_rejected without proving that those remaining
secrets were bad. The loop now stops once the flow is no longer admitted.
A regression closes the flow during the first key retry and verifies that
exactly one submission occurred, with zero spurious key_rejected increments.
Whether this explains all nine rejections in the previous browser run remains
unknown: the old detailed flow history was not retained.

Repeated packet processing previously resubmitted identical keys already in the
flow store. The adapter now skips byte-identical records while retaining the
existing validator and conflict behavior for different values. A regression
verifies unchanged secret-store revision across ten repeated applications.
No TTL, matching rule, AEAD check or resource limit was relaxed.

## Reproducible distinctions

Generated TLS 1.3 / HTTP/2 traces verified four cases using the same packet
generation path:

| Keys | Session available | Other session keys seen | Authenticated headers | Diagnostic outcome |
|---|---|---|---|---|
| None | No | No | No | matching_keys_timeout |
| Different ClientHello random | No | Yes | No | matching_keys_timeout |
| Same random, wrong secret bytes | Yes | No | No | invalid_secret independently retained |
| Correct session and bytes | Yes | No | Yes | successful header recovery |

The wrong-secret case can retain terminal reason matching_keys_timeout while
diagnostic=invalid_secret: a decoder may hold an unverified candidate pending
until expiry. The test explicitly verifies the separate cryptographic diagnostic
rather than treating identifier equality or a timeout as AEAD success.

## Validation and preservation

- Windows: 33 passed, three explicitly opt-in Linux capture cases skipped.
- Pi inactive runtime snapshot: 36 passed, including those loopback cases.
- Existing generated QUIC/H3 positive and negative controls still pass.
- Privacy regressions reject unknown diagnostic text, bound the terminal ring,
  clear it on reset and check response size with maximum stage/category data.
- Prior inactive observer source was backed up before updating its candidate
  snapshot. No active service, phone APK/flag, firewall, route, DNS policy or
  Chameleon configuration changed. The observer was not started.

This does not retrospectively explain all 800 missing-handshake observations,
nor prove YouTube HTTP/3 or advertisement recovery. ECH, routing, missing packet
beginnings, unobserved address changes and key-delivery timing must not be
diagnosed from the absence of headers alone. The new evidence boundary enables
the next short test to separate these stages without another blind viewing loop.

Rollback: revert this commit and restore the inactive observer source backup
if necessary. No schema or Mobile/server API operation migration is required.
