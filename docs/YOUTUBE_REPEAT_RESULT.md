# YouTube observer repeat result

Date: 2026-11-03. Result: **not accepted**.

The user observed two advertisements and normal playback. Mobile selected the
fresh export using the system document picker and established an authenticated
lease before Chrome was opened. All 24 relevant tests passed on Pi before the
repeat. These checks did not substitute for the runtime outcome below.

## Actual runtime evidence

Final status saved by the development host:

| Counter | Value |
|---|---:|
| capture_packets_read | 7,924 |
| capture_full_batches | 47 |
| capture_dropped_packets | 1,212 |
| capture_loss resets | 50 |
| missing_handshake | 390 |
| recovered authenticated headers | 0 |

The separate conflict counter was absent (zero). Candidate keys were observed
on Pi (eight at an intermediate status), but loss resets cleared observation
state. This repeat establishes real libpcap-reported drops, unlike the first
attempt's ambiguous counter. It does not establish why libpcap dropped packets,
and the deltas can include interface and capture-buffer drop reports.

At one intermediate check the service cgroup reported 10 throttled CPU periods
and about 0.66 seconds throttled time; memory.events showed zero max/OOM/OOM-kill
events. This proves some CPU throttling, not that throttling caused all drops.
No CPU, key-store, capture-buffer or memory limit was increased during the run.

The scope was 16 recent IPv4 addresses allocated among media, API, YouTube and
image destinations from 44 available recent addresses. It was not complete
YouTube coverage and did not include IPv6. Cached DNS and newly selected CDN
addresses can escape this scope. Advertising payload attribution remains
unavailable: no authenticated HTTP request was recovered.

## Monitoring limitation

The independent status process exited before saving a time series. The
preparation restarted the observer after adjusting its destination allocation;
the status collector stops when its socket disappears. Therefore neither
continuous monitoring nor maxima over the full repeat are claimed. The saved
interactive statuses are point-in-time evidence. The independent cleanup timer
was separate and remained available; explicit cleanup ran before its deadline.

Fixing collector reconnection and recording real libpcap drop components plus
read/drain latency are prerequisites for another load experiment. Increasing
limits or disabling loss invalidation would not establish correct decryption.

## Cleanup

The temporary observer was stopped, its runtime override and temporary config
removed, and the independent rollback timer cancelled after explicit cleanup.
The original /etc/easypi/chrome-bridge.json hash matched; normalized IPv4 and
IPv6 firewall snapshots matched. Backend, NetProtection and FlowGraph were
active. Some transient units had already unloaded, so their stop/reset reported
unit-not-loaded; subsequent service/configuration verification completed.

On Huawei, the existing Mobile UI was used to stop delivery and forget the
document permission; both state messages were confirmed. Chrome was stopped.
The command-line file was removed only after matching the expected test
arguments, then the exact temporary key file and empty test directory were
removed. The user was asked to return the Chrome flag to Default, but its UI
state was not independently verified. No forensic-erasure guarantee is made.

Private status/setup/cleanup evidence and SHA-256 manifest reside in ignored
EasyPi-Mobile/.build/youtube-tls-repeat. No real secret values were copied to the
development host, no PCAP was created and no advertising blocker was added.

The attempt does not prove that Prism can distinguish or selectively block
YouTube advertisements. The observed advertisement playback and successful
ordinary video are retained as the user's findings; the next engineering work
is reliable packet observation and evidence collection, not an ad-block verdict.
