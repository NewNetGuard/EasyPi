# Buffered YouTube observation result

Date: 2026-11-03. This is a partial technical result,
not successful ad identification or selective blocking.

## Evidence

At final status the observer had read 11,194 packets in the configured scope,
including 129 full batches. No capture_dropped_packets, capture_loss or QUIC
fragment conflicts were reported. Thus the previous burst-loss mechanism did
not recur in this bounded browser experiment. This is not a general throughput
or duration guarantee.

Three authenticated HTTP/2 request-header events were recovered. One had the
enumerated host group youtube and route other; the remaining two were other.
No HTTP/3 headers were recovered. The YouTube-category event occurred after the
phone returned to the test network and before the final advertised playback.
No additional YouTube-category event was recovered during the final playback.
No raw header, URL, query parameter, cookie or secret was retained in the
diagnostic output. Request categories are not advertising-content verdicts.

The user observed two advertisement blocks followed by normal video playback
on the test network. Earlier, five video starts without visible ads occurred
after the phone switched to another network, outside the configured capture
scope. Foreground package identity confirmed official Chrome.
The capture packet count did not grow for that out-of-scope interval. Those
five starts cannot be attributed to Bridge or counted as successful analysis.

The phone’s return to the test network and its active lease were checked before
the final fresh Chrome launch. The observer saw 800 missing_handshake events
by the final snapshot. These count packet observations without an accepted
connection beginning, not 800 unique failed TLS sessions. They do not identify
the root cause. key_rejected reached nine, invalid_secret and key_store_full
were zero; rejection reasons were not retained and must not be inferred.

The selected 16 IPv4 addresses were a subset. A point-in-time DNS comparison
showed 10 of 16 recent YouTube page addresses outside that subset, one of four
media addresses outside it, and six of eight image addresses outside it.
Coverage was therefore insufficient to claim all browser/media connections
were observed. Dynamic CDN choice, IPv6, existing connections, other handshake
limitations and key matching remain distinct possibilities requiring diagnostics.

## Monitoring and cleanup

Unlike the prior repeat, the independent monitor was started after socket
readiness, retried failed polls and wrote a heartbeat. It retained 224 status
samples before final evidence collection. No failed polls were reported in the
checked heartbeats. Status snapshots and SHA-256 evidence remain under ignored
EasyPi-Mobile/.build/youtube-buffered; root-only source evidence remains in
/var/lib/easypi/rollback/youtube-buffered-20261103.

The temporary observer and monitor were stopped; their runtime configuration
and service override were removed and the independent timer cancelled. The
original configuration hash matched. Full before/after firewall snapshots
matched after generated comments and chain counters were excluded. Backend,
NetProtection and FlowGraph remained active. No blocking behavior was added.

Mobile's UI confirmed Stop delivery and Forget export permission. The user
confirmed returning Chrome's non-root command-line flag to Default. Chrome was
then stopped, its exact test argument file matched and removed, and the exact
temporary export file and empty directory deleted. Flag UI state was not
independently rechecked; flash/RAM forensic erasure is not guaranteed.

## Interpretation

The buffer change eliminated reported drops in this experiment and live
non-root Chrome-to-Mobile-to-Pi HTTP/2 recovery included a YouTube host group.
It did not identify player_api, media_request or ad_telemetry events and did not
recover the advertisement's request. No ad-blocking claim is justified.

Next work should inspect per-flow closure/key-match reasons and bounded capture
admission coverage before requesting another viewing session. It must distinguish
out-of-scope traffic, missing capture beginnings, keys with no corresponding
session and actual AEAD failure. Disabling integrity checks or blocking general
googlevideo.com connections would not address these evidence gaps.
