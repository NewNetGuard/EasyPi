# YouTube flow-stage diagnostic run

Date: 2026-11-03. The candidate included the earlier buffered capture changes.

## Observed result

The user observed two advertisement blocks followed by the video on Huawei in
the EasyPi test network. Mobile delivery and a fresh capture lease were checked
before opening Chrome. The final evidence contains 96 independently sampled
statuses; monitor heartbeats reported zero failed polls in inspected snapshots.

Final observer counts: 9,618 packets read, 109 full batches, 938 packet-level
missing_handshake observations and 5,790 unregistered_server_packets. No
capture_dropped_packets, capture_loss, QUIC fragment conflict, key_rejected,
key_store_full or invalid_secret was reported in the saved status. The last
three refer to decoder counters, not proof that all keys were correct.

One authenticated HTTP/3 request-header event had host_group=youtube and
route=watch_page. This category corresponds to the exact path `/watch` after
Bridge's query stripping. No video identifier, raw URL, cookies or secret was
retained. Thus official Chrome-to-Mobile-to-Pi live H3 recovery includes a
YouTube watch-page request. It does not identify an advertising media request.
HTTP/2 headers recovered in this run: zero.

## What the stage evidence narrows down

The observer opened and closed eight flows by the checked live status. Its
bounded recent-closed ring retained six entries:

- Four QUIC entries: hello_seen=true, session_key_available=true, three key
  submissions, terminal reason decoder_error and no authenticated headers.
- One TCP and one QUIC entry: hello_seen=true, session_key_available=true,
  four key submissions, matching_keys_timeout, no authenticated headers.

The earlier snapshots include the successful watch-page event and stage
transitions; the six-entry ring must not be described as a complete lifetime
inventory of all eight flows. other_session_keys_seen was also true for these
entries because keys from parallel connections were present in the bounded
store. That is expected for a multi-connection browser and does not itself
indicate a key leak or incorrect assignment.

This rules out absent delivery and absent matching session identifiers for the
listed entries. It does not prove that each matched key authenticated data:
session identifiers and correct secret bytes are different checks. A generic
decoder_error currently collapses internal QUIC parser/decoder failures; its
precise internal cause is not retained in the outer status. No invalid_secret
event was reported, so AEAD failure must not be asserted as the cause either.

Likewise the two matching-key timeouts could involve incomplete buffered data,
protocol support or timing; their reason is not an automatic finding that the
delivered key was wrong. The capture covers only 16 selected IPv4 addresses,
not every possible CDN address or IPv6. Packet-level missing-handshake counters
are not counts of distinct failed sessions.

## Conclusion and next action

Live YouTube HTTP/3 watch-page recovery is confirmed, as was H2 YouTube-category
recovery in the preceding buffered run. Advertising playback was observed, but
advertising request reconstruction and selective blocking remain unproven.

The next diagnostic work is inside QUIC decode failure classification, using
allowlisted internal error codes rather than echoing exception text. Reproduce
the relevant frame, QPACK, stream and budget paths offline before asking for
another browser viewing. Do not turn decoder_error into a guessed key failure,
raise limits indiscriminately, or block general media connections.

## Preservation and cleanup

Private evidence is hashed under EasyPi-Mobile/.build/youtube-flowdiag; root-only
sampling and firewall snapshots remain in
/var/lib/easypi/rollback/youtube-flowdiag-20261103. No PCAP or key values were
copied into Git or printed. The normal 36-check candidate acceptance preceded
this viewing; no new negative-control capture was performed on these browser
packets.

The observer/monitor were stopped, temporary override/config removed and rollback
timer cancelled. The original main configuration hash matched. Normalized full
before/after IPv4 and IPv6 firewall snapshots matched. Backend, NetProtection and
FlowGraph stayed active. No filtering or blocking policy changed.

Mobile's UI confirmed stopped delivery and forgotten document permission.
After the user confirmed the Chrome flag was Default and relaunched, Chrome
was stopped. The argument file was removed only after matching this test's exact
arguments; the temporary export and empty directory were deleted. Default UI
state was user-confirmed, not independently inspected; forensic erasure is not
guaranteed. The transient service's already-unloaded reset-failed operation
reported unit-not-loaded; subsequent inactivity/configuration checks completed.
