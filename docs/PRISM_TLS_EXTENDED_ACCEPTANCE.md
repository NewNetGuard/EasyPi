# Prism TLS Endpoint Bridge: extended functional acceptance

Snapshot date: 2026-10-31. This report is a bounded functional snapshot, not a
completed six-hour stability result. Runtime evidence is private under ignored .build; this document contains
aggregate observations only.

## Isolation and preservation

The running six-hour controller was not stopped, restarted or reconfigured, and
the Raspberry Pi was not rebooted during this stage. Its singleton observer
socket, shared environment, enable file, service instances and UDP relay ports
were not reused by the additional tests.

Browser observations were taken from completed cases of that ongoing run.
Additional phone captures ran in separate short-lived transient units with
CPUQuota=5%, MemoryMax=64M, MemorySwapMax=0 and a maximum of 1,200 packets or
25 seconds per window. Capture was limited to the authorized phone and ports
443/53 on the gateway. No promiscuous capture was requested.

Offline Bridge replay and generated parallel tests used independent source
snapshots and dependencies in a private temporary directory, with CPUQuota=5%,
MemoryMax=128M and MemorySwapMax=0. They opened no forwarding ports. No production
package, normal backend, Prism, Chameleon, route, certificate store or pinning
configuration was changed. Shared hardware still means zero CPU/latency impact
cannot be established merely from process isolation.

The final target check found all core services active. Backend and guard PIDs
were unchanged from their post-boot baseline. The Chameleon mobile-link agent
was active with no restart. Firewall rules and ipset-schema fingerprints matched
the ongoing duration run's baseline. No capture was attached to the duration
observer and no actual signal was sent to the production guard.

## Per-application matrix

| Application | TLS / protocol evidence | Same-session secrets | Plaintext recovered | Connection coverage |
| --- | --- | --- | --- | --- |
| Firefox Desktop | TLS 1.3 / HTTP2 and QUIC / HTTP3 | Matched exported secrets; authenticated headers | 100 request headers | 25/25 with-key scoped flows |
| Chrome Desktop | TLS 1.3 / HTTP2 and QUIC / HTTP3 | Matched exported secrets; authenticated headers | 92 request headers | 23/23 with-key scoped flows |
| Edge Desktop | TLS 1.3 / HTTP2 and QUIC / HTTP3 | Matched exported secrets; authenticated headers | 92 request headers | 23/23 with-key scoped flows |
| Telegram Desktop | Test process had TCP/443; TLS not established by a capture | No keylog generated in isolated empty profile | None | Not measurable |
| WhatsApp Desktop | App and its WebView2 descendants ran; TCP/443 observed | No configured exporter; no matched secrets | None | Not measurable |
| Chrome Android | Launch window contained TLS and QUIC Initial metadata; test-domain corroboration | None supplied | 0 request headers | App-specific percentage unavailable; 9 visible transport tuples |
| YouTube Android | TLS/QUIC launch-window metadata with YouTube-domain corroboration | None supplied | 0 request headers | App-specific percentage unavailable; 14 visible transport tuples |
| Telegram Android | Launch window had TLS/QUIC metadata; no Telegram-domain corroboration | None supplied | 0 request headers | App-specific percentage unavailable; 9 visible transport tuples |
| WhatsApp Android | TLS and opaque-QUIC launch-window metadata; WhatsApp-domain corroboration | None supplied | 0 request headers | App-specific percentage unavailable; 18 visible transport tuples |
| EasyPi Mobile Android | Launch window had TLS ClientHello metadata; VPN/Protection not toggled | None supplied | 0 request headers | App-specific percentage unavailable; 2 visible transport tuples |

Browser coverage is restricted to the one explicitly admitted transport flow
per controlled case, with correct endpoint keys and four returned test requests.
It excludes deliberate missing/wrong-key controls and does not describe every
connection made by the browser or arbitrary Internet traffic. HTTP2 and HTTP3
were both verified for all three browsers.

Android rows describe phone-wide launch windows, not proven per-UID attribution.
A gateway capture alone cannot identify the Android UID that owned each packet.
The visible transport tuples are not a denominator of established TLS sessions
for that application. Background traffic, reused connections and partial captures
remain possible. All five captures were replayed through an independent Bridge
without supplying any TLS key; none emitted a request-header event. HTTP2/HTTP3
negotiation was not demonstrated for those Android app windows. QUIC Initial
parsing uses public initial-key derivation and does not decrypt application data.

Both Android messengers were installed by the owner before their capture. Only
launcher/startup activity was exercised; no account was logged in and no messages
were sent or read. These are not authenticated messaging, call or video-playback
acceptance tests. The checked production Android packages did not allow run-as;
no root, instrumentation or certificate-pinning bypass was attempted.

## Primary proof and negative controls

The browser snapshot contains 71 verified with-key flow cases and 284 recovered
request headers. Each source report was independently checked for a ready
observer, nonzero exported-key submissions, four authenticated header events,
four HTTP 200 responses and an explicit negative secret-leak audit result.
All successful HTTP3 reports additionally passed client/server UDP payload
integrity checks. A private SHA256 manifest identifies these source reports.

Native AEAD authentication and HTTP header reconstruction establish key/packet
leg compatibility, rather than merely a matching ClientRandom or visible SNI.
The observer diagnostics intentionally suppress real request paths and stream
IDs. The live-browser evidence is therefore scoped flow/header-count evidence,
not independent per-path matching. Packet captures remain encrypted/private.

Only request headers are exposed by the current Bridge. Every relevant decoded
event reports body_inspected=false. Full response bodies, video content and
messenger contents have not been recovered by these tests. Detection of TLS,
SNI, QUIC Initial or an offered ALPN is not counted as application decryption.

At the frozen snapshot the continuing run had returned 340/340 controlled HTTP
responses: 284 headers from with-key cases and 56 responses from negative/fault
controls. Three wrong-key HTTP2 cases remained automated failures: Firefox,
Chrome and Edge each returned four HTTP 200 responses and zero decoded headers,
but reported Unknown/decoder_error instead of the validator's expected
matching_keys_timeout. No exported secret string was detected in those audited
observer logs. Those failures were retained, not rewritten or silently counted
as passes. They require review of the expected failure reason before the final
stability result. The run was still active, approximately 29 minutes into its
six-hour window, at this report's functional snapshot.

## Parallelism and memory

Eight distinct generated TLS1.3/HTTP2 sessions were constructed independently
and fed by eight producer threads to one BridgeWorker. All eight flows recovered
the two expected header blocks, including exact synthetic path/flow matching:
16/16 headers. Eight rotated sets of secrets from adjacent sessions recovered
0 headers, demonstrating that unrelated flow keys did not satisfy the decoder.
These are in-memory generated sessions, not eight concurrent browser handshakes.

With max_connections reduced to four, exactly four of eight flows were admitted
and all eight expected headers for those four flows were recovered. Four flows
were rejected by the admission budget. Filling a deliberately paused two-item
input queue rejected the third packet and immediately exposed Unknown with
input_queue_overflow; this is a worker queue test, not a live capture overflow.
All retained key counts returned to zero on worker close.

The independent Linux cgroup exposed memory.max=134217728, memory.swap.max=0
and cpu.max=5000/100000. Its memory events recorded no OOM. Peak process RSS was
38,830,080 bytes; cgroup peak charge was 23,707,648 bytes. These are distinct
accounting measures, especially for shared library pages. The parallel scenarios
took about 0.70 seconds and about 0.24 user CPU seconds; the figures exclude
fixture generation and are not Internet-throughput measurements. Under this
small CPU quota, the maximum sampled worker queue wait in the eight-flow case
was about 196 ms.

The earlier real observer OOM test remains separate evidence: systemd reported
oom-kill while the browser returned four HTTP 200 responses. OOM was not repeated
against the duration observer. No new Internet-speed comparison was performed
in this stage, so a zero throughput impact is not claimed.

## Export mechanisms and concrete integration limits

Firefox used its process-local SSLKEYLOGFILE mechanism. Chrome and Edge used
Chromium's process-local ssl-key-log-file switch in fresh controlled profiles.
Keys travelled through the authenticated private collector rather than public
listeners. They must come from the exact TLS leg visible at the capture point.
See [NSS key-log documentation](https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html)
and [Chromium key-log handling](https://chromium.googlesource.com/chromium/src/+/8158347f9da44cab5ec0ef0073c0181b46a5f37d/content/browser/network_service_instance_impl.cc).

Telegram Desktop was launched in a separate empty workdir with process-local
SSLKEYLOGFILE. The process opened a TCP/443 socket, but created no keylog in the
observed startup interval. This does not prove universal lack of export support,
particularly because no same-leg TLS capture was available. Telegram's MTProto
transport and message encryption are not generally TLS/HTTP2/HTTP3; a TLS keylog
for ancillary HTTPS would not decrypt MTProto messages. An authorized test build
would need an export callback on the actual TLS context for HTTPS, and a distinct
protocol module for non-TLS MTProto. No MTProto authorization key was accessed.
See [Telegram transport specification](https://core.telegram.org/mtproto/mtproto-transports)
and [OpenSSL keylog callbacks](https://docs.openssl.org/3.5/man3/SSL_CTX_set_keylog_callback/).

The installed WhatsApp Desktop uses WebView2 descendants, established by process
parentage. Full validation needs a supported fresh test profile with a keylog
switch passed to its actual network process at creation time, then a capture of
that same TLS leg. WebView2 exposes startup arguments through its embedding API
and, where honored, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS. This was not enabled
for an existing account or assumed to work in the packaged WhatsApp app. Even
outer-TLS plaintext would not remove WhatsApp's independent end-to-end message
encryption. See [WebView2 flags](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/webview-features-flags)
and [Meta's encryption architecture](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/).

The Windows host's default route does not traverse this Pi. Normal Desktop
messenger traffic therefore cannot be claimed as observed there. The available
Windows packet-capture driver also denied access with the current OS token.
No default route, system proxy or personal application profile was changed to
work around this. A future Desktop test needs a supported per-profile opaque
route through the Pi or an authorized independent host capture, plus actual
same-leg key export. Browser success does not supply either capability to a
separate native app automatically.

For Android, setting a shell environment variable does not configure an already
running app/zygote's TLS stack. A supported managed debug build must export via
its real TLS implementation and deliver scoped secrets through the protected
collector. For an owned Go TLS client this can use tls.Config.KeyLogWriter;
for an owned OpenSSL/BoringSSL client it requires the relevant keylog callback.
The checked EasyPi Mobile sources contain no configured keylog exporter. Such
integration was not added to production code in this task. Closed production
YouTube/WhatsApp builds cannot be assumed to expose that interface. No pinning
or certificate verification must be disabled to add an authorized test exporter.
See [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config).

## Read-only backend / IPv6 guard diagnosis

The installed backend has After, Requires and BindsTo dependencies on the guard.
The guard is Type=simple with Restart=on-failure. Its startup script performs
initialization and takes its lock before installing the USR1 trap. Meanwhile the
NetworkManager dispatcher can observe the service as active and send SIGUSR1.
The previous boot journal recorded a guard process terminated by SIGUSR1 and
an automatic guard restart; the dependent backend did not recover automatically.

An unprivileged instrumented copy reproduced the signal window in local Linux:
SIGUSR1 before trap registration exited with signal 10; the same signal after
registration was survived. Network actions, privilege checks and the actual
production lock were removed/stubbed in that copy. No guard signal, production
edit, service restart or Raspberry Pi reboot was used for this reproduction.
This establishes a reproducible startup race consistent with the boot evidence;
a complete repeated target-boot reproduction was deliberately not attempted.

Type=simple is not an application-readiness handshake. Dependency-triggered
stops/start failures are not repaired merely by restarting the guard, and the
backend's own Restart=on-failure does not guarantee a new dependent start job.
A later fix should preserve the fail-closed BindsTo protection, establish signal
handling before startup exposure, and address readiness/recovery explicitly.
No such fix was applied here. See [systemd service semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and [unit dependency semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).

## Remaining acceptance work

The six-hour outcome is still pending. Its live private status file, including
all failed negative cases, remains authoritative. Android authenticated-app
coverage, strict per-UID attribution, Desktop same-leg capture/export, HTTP body
reconstruction, live multi-application throughput impact and target boot recovery
have not been demonstrated. No universal HTTPS decryption is claimed.


## Post-snapshot HTTP3 integrity exception

After the 71-case verified matrix was frozen, a further ordinary Firefox HTTP3
case returned all four HTTP 200 responses and four authenticated headers, but
failed the strict UDP integrity oracle. Its capture contained 15 client-to-Pi
datagrams versus 14 Pi-to-origin datagrams, and 24 origin-to-Pi versus 17
Pi-to-client datagrams. All 14 and 17 forwarded payload hashes respectively had
counterparts on ingress; the complete ingress/egress multisets did not match.
The unmatched data was not exclusively after the last matched packet, so a
simple shutdown-tail explanation is not established. Reported kernel capture
drops were zero. The scoped observer itself reported four headers and zero
capture drops; that does not make the forwarding-integrity check pass.

This case remains failed and is not included in the earlier 71 fully verified
cases. The cause of the unmatched datagrams needs separate packet/relay-scope
analysis. No capture window was trimmed to manufacture a pass and no running
fixture or duration-test criterion was changed. At the subsequent preservation
check the six-hour controller was still running, with four automated failures
(three wrong-key reason mismatches and this integrity failure). Consequently
neither complete live forwarding integrity nor six-hour stability is accepted
as universally successful. The extended short-lived units had all finished,
and the Raspberry Pi boot identity was unchanged.


## Later live snapshot: decryption versus complete case acceptance

The following later snapshot includes the HTTP3 integrity exception instead
of silently treating successful decryption as complete case success. All rows
are controlled with-key flow cases; body reconstruction remains untested.

| Browser | Decrypted scoped flow cases | Headers | Fully accepted cases |
| --- | --- | --- | --- |
| Firefox | 31/31 | 124 | 30/31 |
| Chrome | 29/29 | 116 | 29/29 |
| Edge | 30/30 | 120 | 30/30 |

Snapshot UTC: 2026-10-31T06:41:54.388190+00:00. The duration run was running.
There were 5 automated failures in total, including
negative controls. The browser decryption column and the full-case acceptance
column deliberately answer different questions. The earlier primary-proof
manifest remains a frozen audit of its original 71 cases.


## Independent key-error diagnosis while the duration run continues

No live fixture, validator, production service or current duration-test
expectation was changed for this diagnosis. A separate low-quota process
replayed three distinct generated TLS1.3 sessions against the same source
Bridge with its default eight-record per-flow secret bound.

| Input to the observed flow | Recovered headers | Visibility/reason | Key rejections |
| --- | --- | --- | --- |
| Its own four correct secret records | 2 | Decrypted / authenticated_request_headers | 0 |
| No secrets | 0 | Metadata only / matching_keys_timeout | 0 |
| Secret records from another session | 0 | Unknown / matching_keys_timeout | 0 |
| Correct identifiers with corrupted secret values | 0 | Unknown / decoder_error | 0 |
| Eight unrelated records first, then four correct records | 0 | Unknown / matching_keys_timeout | 4 |

The source explains the distinction: the exact-identifier lookup can select a
corrupted secret, causing an InvalidTag/AEAD authentication failure. Session
emits analysis_unavailable and Bridge currently maps that category to the
public decoder_error reason. A missing/unmatched secret instead waits until
the key-matching deadline. The live wrong-keys fixture changes secret values
while retaining identifiers, so its unconditional expectation of a timeout is
too narrow. A subsequent validator revision should distinguish those controls
and retain an explicit authenticated-decryption rejection check; arbitrary
decoder errors must not become a blanket success condition. Existing failed
results remain failed and were not rewritten.

A further normal Chrome HTTP3 case in the live duration run returned four HTTP
200 responses but recovered zero headers, with matching_keys_timeout. Its
collector reported 28 submitted secret lines. Packet integrity checks passed
for all 17 client and 20 server datagrams, and the observer reported zero
capture drops. Thus the earlier 90/90 decryption snapshot is not a statement
about every later case in the ongoing run.

Candidate-key pollution is a demonstrated possible failure mechanism: an
unfiltered process-wide keylog can fill a bounded per-flow store before the
observed connection's keys arrive. Submitted-line counts do not establish
accepted or matched keys. The live H3 collector currently submits every supported
keylog label from the browser file to its one scoped flow, without per-session
filtering. However, admission/rejection counters and original identifier-to-key
mapping were not retained for the failing Chrome case, so this experiment does
not independently establish its root cause. Do not enlarge retention without
bounds or claim that it is fixed. A later controlled run needs safe key-admission
counts and scope correlation while preserving ECH/AEAD-based matching.

## Managed Android preparation

Source review identified two independent Mobile stacks: Go's native DoH HTTP
client and Android SSLContext/HttpsURLConnection pairing. Go KeyLogWriter will
only cover a client actually configured with that writer, not the Java stack
or other Android apps. The Mobile repository now contains a design-only
experiments/tls-endpoint-bridge/ANDROID_EXPERIMENT.md describing a separate
lab application ID/native artifact, explicit opt-in, a bounded own-client
TLS1.3/HTTP2 probe, same-leg capture/export, cleanup and negative controls.
No instrumented APK has been built or installed by this preparation. Production
DNS, pairing TLS, pinning, Chameleon and guard remain unchanged. HTTP3 and live
Android worker synchronization are separately gated follow-up tests.


## Duration run ended automatically before six hours

The later run terminated with status failed after 3,787.11 seconds (about
63 minutes), because the controller observed a filtering-configuration hash
mismatch. No operator stop or Raspberry Pi reboot was used. Its normal cleanup
stopped the separate endpoint observer and removed its gate. This run must not
be presented as a completed six-hour test.

It completed 184 cases with 736/736 returned HTTP 200 responses. Of 152 ordinary
with-key flow cases, 151 recovered the expected headers (604 headers total),
and 150 passed every acceptance check. One Firefox HTTP3 case failed UDP
multiset integrity despite four headers, and one Chrome HTTP3 case recovered
no headers. Eight negative cases also failed the validator: seven wrong-key
HTTP2 cases returned decoder_error, and one no-key HTTP3 case lacked the
expected terminal reason in its retained report. Raw outcomes remain unchanged.

A read-only check after the abort found both firewall and ipset-schema hashes
back at the run's original baseline. Core service PIDs/restart counts were
unchanged and the services were active. The original controller did not retain
the exact mismatching snapshot, so a transient legitimate update, temporary
set/rule publication or another change cannot be distinguished after the fact.
Do not label this a false positive or a production configuration change without
that missing evidence.

The local controller now retains the exact normalized rule/schema inputs used
for each fingerprint and writes the mismatching snapshot before failing. Those
inputs can contain private network configuration and remain only in the private
ignored evidence directory. No comparison, stop condition or old test outcome
was relaxed. A regression verifies that the changed snapshot survives cleanup
and prevents the next browser case. Nineteen selected tests passed, one frozen
binary test was skipped without an explicitly supplied binary, and Ruff passed.
A real read-only Pi snapshot confirmed that retained inputs reproduce the hashes.

The failed run is preserved separately before a fresh diagnostic duration run.
The new run has its own timeline; interrupted durations must not be added together
to claim six-hour continuity. It uses the existing candidate and no reboot/link
interruption flags. The only controller change is additional retained evidence
for the next fingerprint mismatch. The new run is not preclassified as passed.


## Follow-up: bounded admission, gateway repair and Android proof

The later diagnostic run also ended automatically before six hours. Exact
transient snapshots and timer correlation identified repeated gateway-script UFW
reloads. The authorized test-server repair, bounded key-admission changes,
version-2 acceptance rules and real Android Lab proof are described in
[PRISM_TLS_KEY_ADMISSION.md](PRISM_TLS_KEY_ADMISSION.md). Earlier design-only
Android statements above describe the state at that earlier checkpoint and are
superseded by this follow-up. Old failures are retained without rescoring.
