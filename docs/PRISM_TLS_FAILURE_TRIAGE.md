# Duration-run failure triage without changing the experiment

Date: 2026-10-31. Read-only analysis of the three retained failures in the current
six-hour run. The controller, decoder, deployed candidate, rules and running
browser workload were not modified or restarted. Failures remain in the original
statistics. Raw logs, addresses, identifiers, captures and exact journal snapshots
remain private under ignored .build.

## Two Firefox HTTP2 no-traffic cases

Both process logs contain repeated Firefox failures to launch tab subprocesses
(18 and 14 occurrences respectively), plus utility and socket subprocess launch
failures through GeckoChildProcessHost / SpawnTarget, with HRESULT 0x80070057
(invalid argument). The parent process stayed alive until the controlled timeout;
creating the parent was not proof that its content/network children were ready.

The Pi relay and independent observer reported ready. Neither case submitted a
key frame or an in-scope packet, and neither returned an HTTP response. Decoder
queues, capture loss and key-store-pressure counters did not report an error.
The retained evidence places the observed failure in browser subprocess startup,
before a successful scoped HTTPS exchange. It does not establish why Windows /
Firefox rejected child creation: resource pressure, sandbox/launcher interaction,
security software or another cause must not be asserted without more evidence.

A comparison of completed Firefox HTTP2 cases at triage time found 62 accepted
cases without these spawn messages, the two failed cases with repeated tab / utility
/ socket errors, and one accepted case with a single socket-launch warning but
no tab-launch warning. Thus an isolated socket warning is not by itself a failure
classifier. Shell shortcut/token warnings also occur in successful browser runs
and do not independently identify the cause. No sandbox or security control was
disabled for diagnosis.

## Firefox HTTP3: registration timeout before the first datagram

The browser returned four HTTP 200 responses, with both browser and server
reporting HTTP3. Relay evidence preserves all 14 client and 19 server UDP payloads
across the two legs, with no fragments and zero reported capture drops. The
observer captured/submitted 33 scoped packets. The host collector submitted four
key frames; this alone is not proof the worker accepted or matched them.

Retained Pi journal timestamps and original Pi PCAP timestamps establish this
ordering on the same Pi clock:

| Event | Time relative to observer ready |
| --- | --- |
| matching_keys_timeout / active flow count becomes zero | 5,035.517 ms |
| Last capture-health sample still containing zero packets | 6,025.948 ms |
| First client datagram on the registered upstream tuple | 6,030.787 ms |
| First positive periodic capture-health sample | 7,028.494 ms |

The first client datagram arrived 995.270 ms after the registered flow had
already timed out. The retained monotonic journal timeline corroborates the
realtime/PCAP comparison. This is a demonstrated registration/capture-start timing
failure, not evidence that a live admitted QUIC flow rejected matching AEAD keys.

The current Bridge starts its five-second no-header/matching-key deadline at
open_flow (flow.created). The fixture registers that flow before starting Firefox
and its Marionette navigation. Bridge.poll closes the flow when that deadline
expires, even if no packet has arrived. Later capture counters can continue to
increase, although the worker no longer has an active flow to decode. Its
submit counters are consequently not accepted-key or decoded-packet counters.
Zero key_rejected / key_store_full counters do not prove later frames were applied
to an active flow. Secrets were intentionally deleted; their exact correlation
cannot be reconstructed from the sanitized reports and must not be invented.

This resolves why this particular HTTP3 flow was no longer decoded when traffic
started. It does not prove that the four submitted secrets would decrypt the
capture if replayed, or that every historical HTTP3 timeout has the same cause.

## Changes deferred until the duration run ends

Do not extend or reset deadlines, loosen acceptance, edit the harness, restart the
observer or rescore these cases during the run. After preserving the final report,
test a distinct bounded capture-arming phase and handshake/key-matching phase.
A first-packet anchor needs its own bounded no-traffic lease, original memory/key
limits and delayed-start regressions; simply increasing every timeout can hide
unbounded startup waits. Registering closer to a verified browser-ready handshake
is another fixture option to evaluate. Neither option is implemented by this report.

For future Firefox diagnostics retain sanitized parent/child readiness, controlled
page arrival, proxy CONNECT initiation and key-export milestones, with monotonic
timestamps. Do not retain raw keys just to diagnose launch failure. Windows event
correlation should use the specific failed-run time ranges. Preserve failed
attempts separately from successful repeats.
