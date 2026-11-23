# QUIC decoder failure classification and offline validation

Date: 2026-11-03. This work did not start a
browser test, capture live packets, read exported secrets or enable blocking.

## Implemented diagnostics

`decode_errors.py` defines a fixed vocabulary and a ValueError-compatible
DecodeError. QUIC failure events now carry error_code and error_category; their
legacy reason field also contains only that fixed code. The previous exception
class plus truncated message output was removed. Arbitrary library exceptions
are classified by type and processing stage, never by serializing their text.
QPACK guard failures use the same typed codes without relaxing the guard.

| Category | Representative codes | What it establishes |
|---|---|---|
| AEAD | aead.authentication_failed, aead.key_phase_order | Established crypto failed, or invalid key-transition ordering; not proof that secret bytes alone caused it |
| QUIC frame | frame.truncated, frame.unsupported, frame.unsupported_version | Authenticated plaintext cannot be processed as a supported frame |
| STREAM | stream.malformed, stream.conflicting_retransmission | Stream processing or overlapping-byte inconsistency |
| QPACK | qpack.invalid_field, qpack.invalid_reference, qpack.truncated, qpack.decompression, qpack.encoder, qpack.decoder, qpack.huffman | Guard/native compression parsing failed |
| Packet framing/reassembly | reassembly.malformed_header, reassembly.invalid_length | Packet framing is invalid; no packet bytes are returned |
| Limits | limits.stream_bytes, limits.stream_count, limits.packet_count, limits.pending_bytes, limits.qpack_* | An existing resource envelope stopped analysis |
| Timeouts | timeouts.missing_key, timeouts.no_authenticated_packet, timeouts.headers, timeouts.qpack, timeouts.stream_gap, timeouts.key_lease, timeouts.idle | The last observable stage when an existing deadline closed a flow |

The full vocabulary is in source. Unknown failures become a fixed stage fallback
such as frame.internal or qpack.invalid_field; no arbitrary strings or resource
identifiers are reflected. Buffer-limit failures previously set failed silently;
they now emit limits.pending_bytes. Coalesced packet lengths must make forward
progress and remain within the datagram; invalid lengths get a fixed code rather
than permitting an unbounded parse loop.

Bridge preserves decoder_code and the number of authenticated QUIC packets in
the bounded terminal Snapshot. Chrome's opt-in stage diagnostics expose these
alongside the existing closure reason. Counters/categories do not include keys,
ClientHello randoms, cookies, URLs, video IDs, header values or bodies. The maximum
stage/category status with long error codes remains below the 8,192-byte IPC
response limit in regression testing.

The established authentication-failure path still yields Unknown/invalid_secret.
An unverified candidate that never authenticates is more ambiguous: incorrect
secret, CID/packet-number interpretation, corruption or incomplete observation
can produce the same outcome. It remains a timeout with
timeouts.no_authenticated_packet, not a fabricated proof of a wrong secret.
An authenticated packet with no recovered headers can instead time out in the
QPACK, stream-gap or header stage. idle/key-lease codes describe lifecycle, not
necessarily decoder bugs; they must be interpreted with the flow state.

## Offline reproduction

All new packet tests use ephemeral generated secrets and real aioquic AEAD
protection. No historical user PCAP, exported key file or private payload was
opened. The existing generated ChromeObserver H2/H3 fixtures were reused for
positive/negative regressions. New fixtures exercise:

- Authenticated unsupported/truncated QUIC frames and ACK-range limits.
- Conflicting authenticated STREAM retransmissions, stream byte/count limits.
- Authenticated malformed/truncated QPACK field sections.
- Pending-byte and packet-count limits, unchanged in value.
- Malformed coalesced packet lengths and truncated packet headers.
- Correct QPACK HTTP/3 header recovery after authentication.
- Established-session AEAD failure after ciphertext corruption.
- A wrong unverified candidate, producing zero authenticated packets/headers.
- Missing application key, authenticated packets with no headers, blocked QPACK
  and a missing STREAM prefix, yielding distinct timeout stages.
- Bridge closure and key cleanup with preserved fixed error codes.
- Arbitrary exception text that must not appear in serialized diagnostics.

These are reproductions of possible failure paths, not byte-for-byte replay of
the previous YouTube decoder_error events. Their exact internal cause cannot be
recovered retroactively: the earlier outer status discarded it and packets were
not retained. The old failed runs remain failed. No particular new category is
asserted as their proven cause.

## Capture coverage audit

Read-only audit of the last 300 eligible successful DNS records for Huawei:

| Group | Distinct IPv4 addresses | Recorded IPv6 answers |
|---|---:|---:|
| YouTube pages | 14 | 0 |
| YouTube API | 8 | 0 |
| Video CDN | 11 | 0 |
| Images | 8 | 0 |

The union contained 41 IPv4 addresses versus the observer's 16-address limit.
This is a historical DNS-derived candidate set, not 41 proven simultaneous
connections. It cannot be fully covered by one such static allowlist. The exact
intersection for the last viewing cannot now be reconstructed: its temporary
config was removed and packet-level tuples were not retained. Earlier live
coverage checks already demonstrated exclusions, but do not substitute for a
complete per-viewing inventory.

The adapter explicitly parses its phone/destination configuration as IPv4, and
its BPF filter covers those IPv4 addresses. A synthetic IPv6 datagram regression
verifies it cannot enter the current ChromeObserver. At this audit Huawei Wi-Fi
had only a link-local IPv6 address; no global address was observed. Consequently
IPv6 is an architectural exclusion, not a proven source of this device's latest
failures. No DNS addresses or network settings were changed to force a result.

For the next test, retain a sanitized scope audit before/after (device address,
address-family coverage and destination-set overlap), rather than deleting the
only evidence of the chosen scope. New CDN addresses and connections beginning
outside the capture interval must be counted as coverage gaps, not decoder bugs.

## Executed checks and runtime preservation

- Windows: 57 passed, three opt-in Linux capture cases skipped.
- Raspberry Pi inactive candidate: 60 passed, zero failures.
- Existing generated HTTP/2/HTTP/3 positive and negative controls passed.
- No key, stream, packet, queue, memory or CPU limit was increased.
- No routing/firewall/Chameleon/DNS policy was modified; no CDN blocking was added.
- No EasyPi Mobile source, APK or settings were changed.
- Prior inactive observer source was backed up before updating its test snapshot.
  Production backend executable and running services were not replaced/restarted.
  The observer remains inactive.

Sanitized machine-readable results are in QUIC_FAILURE_CLASSIFICATION_RESULTS.json.
Private read-only audit evidence has a SHA-256 manifest in ignored
EasyPi-Mobile/.build/quic-failure-classification. interfax.pcap was untouched.

Primary protocol references:
[QUIC frame handling](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4),
[HTTP/3 streams](https://www.rfc-editor.org/rfc/rfc9114.html#section-6),
[QPACK decoding](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2).

## Readiness gates

The candidate is ready for another bounded diagnostic run, not an ad-blocking
trial. Before running it, verify scope, current phone network, fresh connections,
active delivery and monitor heartbeat. Capture must have zero unexplained drops;
every observed failed flow must expose its typed stage code. Remaining
frame.internal/other failures require investigation rather than relabelling.

An advertising-blocking trial is justified only after all these are demonstrated:

1. Authenticated player/media request recovery in the actual Chrome H2/H3 flows
   used by the test, with matching session evidence and same-packet missing/wrong
   key controls yielding no request headers.
2. Time-labelled observed advertising and ordinary video have independent,
   repeatable request attribution. A /watch request, telemetry request or a
   googlevideo.com hostname alone is insufficient. Ambiguous/shared requests
   remain Unknown for intervention purposes.
3. A bounded intervention target is demonstrated: either a proven ad-exclusive
   connection with a measured isolation test, or a supported request-level
   control mechanism. Passive decryption alone cannot edit/delete a multiplexed
   request on the wire. No such control for official Chrome is implemented here.
4. A test-specific rollback and abort condition preserve ordinary video:
   stop intervention immediately on playback failure or collateral content
   blocking. Shared YouTube CDN connections must not be blocked wholesale.

Those gates are not met yet. Fixing diagnostic output must not be advertised
as identifying YouTube ads or enabling safe selective blocking.

Rollback is a normal revert of this commit and restoration of the inactive test
snapshot if needed; there is no data migration or deployed service replacement.
