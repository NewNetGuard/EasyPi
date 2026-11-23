# Prism TLS Endpoint Bridge: target acceptance

## Scope and provenance

These are controlled Raspberry Pi arm64 acceptance observations, not a claim
of arbitrary HTTPS decryption or production readiness. The phone used the Pi
as its Wi-Fi gateway. EasyPi Mobile VPN was not enabled. The main backend and
existing Prism filtering services were not replaced or reconfigured.

The first installed observer binary failed cold startup under its CPU quota.
A separately built experimental observer corrected the ready/heartbeat race.
Browser results below use that temporary candidate, not the unchanged normal
backend executable. The candidate was not a full EasyPi release build.

## Observed results

| Scenario | Result | Interpretation |
| --- | --- | --- |
| Firefox, Chrome, Edge: HTTP/2 | 4/4 headers per browser | Scoped controlled requests with exported endpoint secrets |
| Firefox, Chrome, Edge: HTTP/3 | 4/4 headers per browser | Real QUIC relay and native decoder; UDP payload integrity checked |
| Missing secrets, HTTP/2 | 0 decoded; 4 HTTP 200 responses | Metadata only, then matching-key timeout |
| Incorrect secrets, HTTP/3 | 0 decoded; 4 HTTP 200 responses | No plaintext recovery with wrong keys |
| Decoder SIGKILL | 0 decoded; 4 HTTP 200 responses | Observer reported process exit |
| Decoder SIGSTOP | 0 decoded; 4 HTTP 200 responses | Observer reported heartbeat timeout |
| Gateway YouTube launch window | TLS/QUIC metadata observed | No keys and no HTTP content decrypted |
| Bounded synthetic Pi replay | 20,000 headers, 10,000 logical flows | Active flow limit 16; not concurrent live Internet connections |
| Bulk network transfer with observer | All four bodies delivered | Capture loss caused Unknown; this was not an HTTP/2 decoding test |
| Queue-overflow attempt | Not demonstrated | Capture loss occurred first; not accepted as queue-overflow evidence |
| Whole-service OOM | Blocked | Kernel memory controller disabled; MemoryMax declaration was ineffective |
| Six-hour live stress / reboot / link interruption | Not completed | Unattended stress is gated on real memory-controller availability |

The six browser/protocol cases recovered 24/24 expected request headers across
the controlled tuples. Diagnostics deliberately omit paths and real HTTP stream
IDs, so this is count-based coverage within these flows, not independent
per-path matching or an Internet-wide coverage percentage. A failed initial
Firefox launch preceded the successful retry and is retained in private logs.

The synthetic replay took approximately 6.08 seconds (about 3,290 headers/s).
RSS grew from about 40.0 MB to 40.5 MB. It used bounded generated traffic with
RLIMIT_AS/CPU isolation; it does not establish real browser throughput.

A single relay-path comparison delivered four 1 MB bodies in each condition:
approximately 46.8 Mbit/s without the observer and 47.7 Mbit/s with it. One noisy
pair cannot establish a speed impact. The endpoint did not negotiate HTTP/2
for the measured path, so these values must not be reported as HTTP/2 decoder
performance. The observer detected six capture drops while all bodies arrived.
A later 32 MB attempt detected 127 capture drops and also delivered all bodies.
These are observer capture losses, not evidence of dropped forwarded traffic.

The YouTube launch-window capture contained 1,264 packets with zero reported
kernel capture drops. Offline analysis using the existing FlowGraph parser
observed TLS and QUIC metadata including public YouTube domains. This does not
attribute every flow to an Android UID or demonstrate playback inspection.
Telegram and WhatsApp were absent and were not tested.

## Safety and unresolved prerequisites

Normalized firewall rules and ipset schemas matched the pre-test fingerprints
after these runs. The backend, existing Prism shadow service and FlowGraph
service remained active. Dynamic set membership and packet counters were not
used as configuration fingerprints. This verifies the checked configuration
and scenarios; it does not prove absence of every possible performance effect.

The observer socket and active observer instances were stopped and its runtime
enable file removed after the bounded tests. The experimental candidate and
acceptance-only systemd override remain installed but inactive for follow-up.
Remove that override before relying on a future normal backend update; otherwise
the observer would continue using the temporary candidate. No ordinary filtering
service needs to be stopped to remove the experimental override.

The target kernel command line disables the memory controller. Whole-service
MemoryCurrent was unavailable even though systemd accepted MemoryMax. The
attempted low-memory test is therefore not an OOM pass. A persistent boot-option
change and reboot require the pending explicit approval; no such change was made
as part of the bounded tests. The duration driver refuses unattended stress when
the memory controller is absent. CPU/RAM enforcement, actual OOM isolation,
queue overflow and long-duration recovery still need target acceptance.

In audited runs, exact exported secret/capability strings were not found in the
observer journal records inspected in memory. Earlier runs without that audit
field remain unaudited. This is not a forensic proof of zeroization or an audit
of every host log. Native browser keylogs were created only in private temporary
profiles and deleted after each run. Runtime material and raw captures remain
in owner-private ignored .build evidence, outside source control.

## Reproducible local driver

The opt-in Windows harness is tests/acceptance/prism_tls_target_suite.py. It
requires a private .build/prism-target-current.json containing runtime (an
owner-private evidence directory under .build), ssh (a known-host SSH target),
and test_network_confirmed=true. Create this metadata locally; never commit it.
The target must already have the separate observer socket/account/unit and a
verified experimental candidate. This harness does not install the main backend.

Run from the repository root. A bounded controller smoke uses --hours 0.01
--max-cases 1. A long run uses --hours 6; --allow-reboot and
--allow-network-disruption explicitly opt into those isolated-network tests.
Do not pass those flags on a shared household or production gateway.

The driver writes aggregate status and private per-case evidence beneath the
configured runtime directory. Creating a STOP file there requests shutdown
after the current bounded case. Its cleanup stops only the endpoint observer.
The loop currently covers browser/protocol pairs and selected missing/wrong-key
and child-exit cases. It is not the complete Android, high-concurrency, OOM and
throughput matrix requested for final acceptance.

HTTP success and observer failure are distinct results. Network-only probes
report worker validation as unavailable, and fault validation requires the
specific observed reason. Capture loss cannot satisfy queue-overflow validation;
a configured memory limit cannot satisfy OOM validation. Coverage is unavailable
when the count of known returned requests is zero or inconsistent.


## Approved memory-controller follow-up

The owner subsequently approved the persistent boot change and reboot. The
original firmware command line was backed up privately before appending only
cgroup_enable=memory. After a verified new kernel boot, the memory controller
became available and whole-service MemoryCurrent returned numeric samples.
The root cgroup has no memory.current file; controller availability is checked
at the root and actual accounting is checked on the observer service cgroup.

The first reduced-RAM-limit attempt reclaimed memory into swap and did not
produce OOM. It remains a failed OOM test. With swap disabled for the observer,
a repeat reported systemd Result=oom-kill, ExecMainStatus=9. All four controlled
browser requests still returned HTTP 200; no TLS secret string was detected in
the audited observer diagnostics. The pre-injection whole-service memory peak
was about 135 MB; that peak must not be compared to the subsequently lowered
24 MB limit as if both had applied throughout startup.

MemorySwapMax=0 is now part of the local observer unit template and the
acceptance-only target override. It applies only to this experimental service.
No global swap setting, ordinary backend unit or primary filter was changed.

The reboot exposed an independent recovery failure: the IPv6 guard exited
from SIGUSR1 and restarted, while the dependent backend remained inactive.
After confirming the guard was active, the existing backend was started without
configuration edits. This was manual recovery, not a successful unattended
reboot test. Normalized firewall rules later matched the original fingerprint;
ipset schemas changed during boot/runtime restoration, so cross-boot schema
identity is not claimed. All three core services were active after recovery.
Repeated reboot/link-disruption tests are deferred pending that failure's
investigation. A browser-only duration run must be reported separately from
those incomplete recovery tests; its private status file is the live authority
for whether it started, completed, failed or was stopped.


## Interrupted first duration run

The first intended six-hour background run was stopped after about 13 minutes.
Four HTTP/3 wrappers hit the 110-second outer timeout before writing their
relay/observer journals. The run is failed/incomplete, not a six-hour pass.
The available evidence does not establish a TLS-decoder fault: those cases did
not reach the recorded observer stage. Successful returned requests must not
hide failed attempts in a headline coverage percentage.

The harness now reports failed cases and HTTP success over all attempted
requests during the run, alongside its separately scoped returned-request
header coverage. One-shot fixture SSH commands use no stdin and a 20-second
command timeout, with secret-free start/completion markers. This bounds and
localizes startup failures; it does not establish their underlying cause.
Independent HTTP/3 rechecks precede any new duration run. The interrupted run's
raw evidence is retained privately rather than merged into a new run.

The subsequent hidden-process recheck recovered 4/4 HTTP/3 headers in each of
Firefox, Chrome and Edge (12/12 total), with all twelve HTTP 200 responses.
That bounded recheck passed; it does not prove six-hour stability or identify
the original intermittent SSH startup cause.

The subsequent application matrix, isolated parallel/memory checks and read-only
guard diagnosis are recorded in [PRISM_TLS_EXTENDED_ACCEPTANCE.md](PRISM_TLS_EXTENDED_ACCEPTANCE.md).
