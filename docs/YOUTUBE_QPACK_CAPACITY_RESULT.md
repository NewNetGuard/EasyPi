# YouTube QPACK-capacity live finding

Date: 2026-11-03. Official Chrome on the non-root Huawei,
standard Mobile sender and isolated Pi observer were used. No blocking policy
was enabled. The user observed two advertising blocks and normal video.

## Confirmed failure stage

Five admitted flows closed in the checked status. Four QUIC flows terminated
with decoder_error / decoder_code=limits.qpack_capacity. They had matching
session keys and respectively 2, 27, 2 and 2 authenticated QUIC packets before
closing. Thus these packets passed AEAD; the observed failures occurred in
QPACK processing, not merely in acquisition of keys or initial matching.

The current QPACK guard uses the same code for two capacity checks: a requested
dynamic-table capacity above its configured capacity, and an entry's guarded
name/value size above that capacity. This run did not record which check fired
or the requested size. Raising the capacity without that measurement is not
justified. Nor does one successful packet authenticate every key of a session.

One TCP flow with matching keys closed on matching_keys_timeout. Its cause is
not explained by the QUIC finding and remains separate. key_rejected,
key_store_full and invalid_secret stayed zero in the saved decoder counters.

One authenticated HTTP/3 request had host_group=youtube / route=watch_page,
corresponding to `/watch` with query parameters stripped. No player_api,
media_request or advertising request was recovered. The category event does
not identify the two displayed advertisements.

At final evidence collection: 9,237 packets read, 109 full batches, zero reported
capture drops/loss, 917 packet-level missing_handshake observations and 6,496
unregistered_server_packets. Three packets had arrived before the initial lease.
Those packet counters are not unique connection counts. No payload/secret was
printed or copied to the development host.

## Scope evidence retained this time

The actual temporary configuration and starting DNS row ID were retained in a
root-only private scope file. Comparing DNS answers after that row with the
exact configured address set yielded:

| Group | IPv4 addresses in DNS | In scope | Outside scope | IPv6 answers |
|---|---:|---:|---:|---:|
| YouTube pages | 14 | 10 | 4 | 0 |
| Video CDN | 3 | 2 | 1 | 0 |
| Images | 8 | 0 | 8 | 0 |
| YouTube API | 0 | 0 | 0 | 0 |

No new API DNS query is not proof of no API traffic; cached addresses/connections
can exist. This is DNS-derived scope evidence, not per-app ownership of every
flow or a complete active-connection inventory. The observer remains IPv4-only.

## Preservation and cleanup

The independent monitor produced its status file and heartbeat. Private result,
setup and cleanup evidence with SHA-256 manifest resides in ignored
EasyPi-Mobile/.build/youtube-errorcodes. The Pi retains root-only scope,
status and firewall evidence in
/var/lib/easypi/rollback/youtube-errorcodes-20261103.

The observer/monitor were stopped, temporary override/config removed and cleanup
timer cancelled. The original main configuration hash matched. Full normalized
IPv4/IPv6 firewall snapshots matched. Backend, NetProtection and FlowGraph stayed
active; the observer is inactive. A reset of an already-unloaded transient state
reported unit-not-loaded, followed by successful inactivity/config checks.

Mobile's UI confirmed Stop delivery and Forget export permission. The user
confirmed returning the Chrome flag to Default and relaunching. Chrome was
stopped, the argument file matched against the exact test setup and removed,
then the exact temporary export and empty directory were deleted. The flag's
UI state was not independently inspected. Forensic flash/RAM erasure is not
guaranteed. No new source changes were needed during the viewing.

## Next action

Distinguish and measure the two QPACK-capacity checks using bounded numeric
metadata, then reproduce that capacity/entry behavior offline. Any change must
fit a measured resource budget and retain the expansion guard. Diagnose the TCP
timeout independently. Another blind video run or broad CDN block is not the
next step. Advertising identification and safe selective intervention remain
unproven, despite confirmed watch-page decryption and the now-concrete QPACK
failure stage.
