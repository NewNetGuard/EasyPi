# Prism DPI

No-MITM transport classification using inline kernel matchers, without a
background packet-inspection process.

Some apps can't be blocked by IP, domain, or SNI without collateral. **WhatsApp**
is the case that drove this: its chat channel (chatd) rides Meta's shared IPs (the
same ranges as Facebook/Instagram) using its own protocol with no readable SNI, so
IP/SNI blocking either misses it or takes down FB/IG too, and static IP lists leak
(it roams edges). But its first client bytes are always `45 44` ("ED", an edge
routing header), while everything else on :443 — FB/IG/browsers/CDNs — opens with a
TLS ClientHello (`16 03`). So it is cleanly separable by the **first packet alone**.

## How it works

- Each supported target has its own module. The module owns its signatures while
  the shared signature types and firewall-rule generator remain in the Prism core.
- Active blocking signatures generate an iptables **`-m u32`** match and the
  firewall installs a `-j DROP` rule that drops that first packet **in-kernel,
  before it is forwarded**.
- The rule is added **when the app's block is enabled** for a device (by
  `setup_app_blocking.sh`) and removed when it is disabled.

WhatsApp also has a cleartext HTTP fallback on TCP/80. A live Android capture
showed `POST /chat HTTP/1.1`, `Host: c.whatsapp.net`, then the same `ED` Noise
handshake inside HTTP chunked framing. Prism requires both WhatsApp-specific HTTP
fields in one request before dropping that fallback, so shared Meta addresses
used by Facebook and Instagram remain available.

## Facebook exact-flow policy

`modules/facebook/` consumes FlowGraph metadata from fully reassembled TLS ClientHello
records. It emits a short exact-flow block only when the source device currently
has the Facebook toggle enabled and the parsed SNI belongs to the Facebook
service family. A shared Meta address or TLS fingerprint alone is never enough;
Instagram and WhatsApp names on the same endpoint fail open. Malformed, stale,
already-served, or policy-disabled flows also fail open. The backend rechecks the
device policy immediately before submitting the bounded 5-tuple to the existing
PRISM stream enforcer.

## TikTok exact-flow policy

`modules/tiktok/` consumes fully parsed TCP ClientHello and decrypted QUIC Initial
metadata from FlowGraph. It acts only when the source device currently has the
TikTok toggle enabled and the SNI belongs to a TikTok-specific service family.
The policy blocks one exact TCP or UDP flow at a time; Akamai, Fastly, Google,
and other shared CDN addresses are never classification evidence by themselves.
Malformed, stale, policy-disabled, already-served TCP, and non-443 flows fail
open. The observed European fallback families `tiktokcdn-eu.com` and
`tiktokv.eu` are also covered by the per-device DNS policy.

## Mobile ad shadow

`modules/mobile_ads/yandex` is a separate ad-technology detector, not an app-specific
rule. It observes a compact 512-byte TLS ClientHello record when SNI is exactly
`yandex.com` or `yandex.ru`. One such connection is not a classification:
ordinary browser traffic produced the same record shape during live controls.

This detector is deliberately **shadow-only**. `setup_prism_shadow.sh` installs
counter rules and records matching source addresses with `xt_recent`; it contains
no `DROP` or `REJECT` target. Subdomains such as `mail.yandex.ru` and
`cloud-api.yandex.net` do not match.

The shadow candidate is behavioral. It requires, from one device and within
three seconds:

- at least two exact events for each SNI class; and
- at least five exact events in total.

Two YoWindow captures produced `3+3` bursts in 1.26 and 0.92 seconds. A third
live run produced `2+3` in about 2.37 seconds.
Two ordinary-browser controls produced zero events and one `yandex.com` event,
respectively. Exact matches remain visible in `easypi_prism_raw_recent`; burst
candidates are retained temporarily in `easypi_prism_yandex_burst`. Neither set
is a block target. The earlier device-wide correlation with unrelated DNS
denials was removed after a browser control demonstrated a false positive.

A later active canary control produced `36` compact `yandex.com` and `23`
compact `yandex.ru` events while ordinary Yandex search remained usable. The
browser therefore can produce the same temporal burst and recover through other
connections. The burst is a transport-activity signal, not a standalone ad
classification and not grounds for global blocking.

A Yandex Mail ad-refresh capture used a different first-party path: five
`yandex.com` connections spread over about 42 seconds, no matching `yandex.ru`
event, and shared `avatars.mds.yandex.net` image traffic. That case is retained
as a negative eval. Blocking those shared Mail endpoints would risk normal mail
content, so this detector does not classify that delivery path.

A clean-start Yandex Mail Disk capture exposed a second fallback. The app opened
`disk.yandex.ru`, DNS filtering denied `mc.yandex.ru` and `ads.adfox.ru`, and an
alternate, larger ClientHello to exact `yandex.ru` succeeded at the same time.
The same alternate profile succeeded while the narrow canary was active and the
ad still rendered. This is evidence of a bypass, not yet evidence that all such
root-SNI traffic is advertising.

### Canary blocking

The normal `enable` action remains observation-only for every device. An
explicit `canary-enable PRIVATE_IPV4` action adds one private LAN address to a
separate timeout set for ten minutes. Only that device's exact compact-TLS
`yandex.com` and `yandex.ru` ClientHello packets are dropped; all other Prism
observations continue to pass. `canary-disable PRIVATE_IPV4` removes the device
immediately. This mode exists only for controlled validation before any blocking
policy is considered. It must not be enabled globally: a browser control proved
that normal Yandex traffic can use the same transport even though the browser
continued working by retrying through other connections.

A temporary split-safe canary was validated with a clean Yandex Mail start: ten
root-SNI flows received zero response bytes, while `disk.yandex.ru` received
about 242 KB and `1.downloader.disk.yandex.ru` about 166 KB. The Disk view loaded
and its ad did not. A separate ordinary-browser control then rejected the rule
as a global policy: Yandex live suggestions and other pages loaded, but
submitting a search failed while exact-root traffic was blocked. The Mail
fallback and browser search also shared the same TLS capabilities after GREASE
normalization; their extension order was randomized in both cases. A
single-flow TLS fingerprint therefore cannot separate them. Production blocking
needs an additional causal context signal. The rejected wide-canary action was
removed from the privileged runner surface after this control.

### Rejected two-event context

A second canary tested `disk.yandex.ru` followed by an exact-root SNI inside a
30-second client window. A browser control before opening Disk passed with zero
context matches. After Disk opened, its ad disappeared and useful Disk content
loaded, but a browser search from the same device also failed: the gateway sees
both applications behind one client IP. The rule dropped 77 `yandex.ru` packets
during that control. The two-event context is therefore insufficient and its
canary action was removed. Any future production operator needs a third causal
signal or flow attribution that does not apply to a simultaneous browser flow.

## Google Mobile Ads mediation

`modules/mobile_ads/google` models Google Mobile Ads as a causal multi-flow
cycle rather than a domain verdict. Learned transport signatures assign flows
to adapter, WebView, creative, media, and tracker stages. The temporal operator
then requires an entry stage, creative or media delivery, and a post-delivery
tracking burst from at least two source families inside a bounded window. It
also records adapter fanout, sequential waterfall transitions, and cross-source
delivery as additional evidence.

The exact `googleads.g.doubleclick.net` control hostname is retained only as an
observation anchor. It cannot classify a complete ad cycle by itself. The module
emits no kernel rule until adapter and delivery fingerprints have passed both
positive advertising captures and negative controls on shared infrastructure.

## Runtime modes

PRISM has two deliberately separate execution paths:

- inline signatures are emitted once by `python3 -m prism_dpi.rule <app>` and
  enforced in the kernel; and
- `prism_dpi.flowgraph` is a stateful, metadata-only shadow observer used when a
  single packet cannot carry enough causal evidence.

FlowGraph groups individual 5-tuples into short causal sessions using timing,
normalized TLS capabilities, destination locality, source-port locality, DNS
outcomes, record sizes, and connection fanout. It never stores packet payloads,
never decrypts TLS, and has no firewall API. Its verdicts are `allow`,
`ambiguous`, or `candidate`. Ambiguous traffic is always fail-open.

The separately reviewed candidate policy runs in the backend account and tails
only fresh structured assessments. It keeps one root-owned validating runner
open and checks for new assessments every 10 ms, so enforcement does not pay a
new `sudo`, runner, and shell startup cost for each decision. The stream accepts
only five tab-separated validated fields, including a fixed `tcp|udp` protocol,
and acknowledges the exact ipset add;
if it is unavailable, the backend falls back to the original one-shot runner.
A candidate with the required causal evidence can add its exact client-IP/
client-port/server-IP/protocol tuple to a dedicated kernel set for 180 seconds.
Enforcement is additionally constrained to server port 443. For the
first 12 seconds, new compact ClientHello retries from the same client are also
dropped; established TLS and large-browser ClientHello flows are unaffected.
Stale, malformed, non-private-client, non-public-server, and non-443 events
fail open.

Packets belonging to the selected exact tuple refresh its 180-second timeout
before they are dropped. An actively retransmitting TCP flow or active UDP flow
therefore cannot resume while traffic continues; the entry disappears 180
seconds after that flow becomes quiet.

The active policy accepts independently validated operators. The compact
root-profile transition after dense application activity requires either two
matching root setup flows plus four compact subdomain flows, or one root setup
flow plus a stronger fanout of at least eight compact subdomain flows. A lone
root profile change remains ambiguous. This older operator retains a bounded
12-second compact retry guard.

The large-root causal operator requires a large ClientHello on a root name after
at least two distinct subdomain names from the same domain family have joined
the same short causal session. It blocks only that exact client-IP/client-port/
server-IP flow and never enables the device-wide compact retry guard. A compact
root retry is also an exact-only candidate when it follows a confirmed large
causal root within three seconds and matches its client, server IP, server name,
port, causal session, and same-family fanout. Unrelated endpoints remain
fail-open.

The cross-session large-root operator handles TLS-profile splits without merging
their sessions. It requires at least three distinct large-ClientHello subdomain
names from the same semantic domain family, spread across at least two causal
sessions from one client during the preceding three seconds. It also blocks only
the exact root flow. Five independent Mail/Disk captures, including the
clean-start immediate-ad retry, select this branch; seven browser controls emit
zero policy actions.

A delayed large-root retry is accepted only after an already confirmed causal
root and only when client, server IP, server name, and server port are identical.
Its window is six seconds, it remains exact-flow-only, and a retry does not renew
the causal confirmation. This closes a measured fallback that opened 3.43
seconds after the last confirmed root and otherwise received about 161 KB.

A longer continuation never blocks on elapsed context alone. For up to 45
seconds after a confirmed root, the same exact endpoint becomes eligible only
when an established subdomain flow from the same client and semantic family
starts a new TLS request during the preceding one second. Confirmations are
bounded to 128 per client, and continuation actions do not renew them. This
places the decision before the root response while avoiding the rejected
device-wide 30-second context.

The uniform root-exchange conveyor operator handles ad feeds that open many
short TLS flows instead of retrying one causal root. It retains only the first
completed exchange from compact root-SNI flows for ten seconds. A later flow is
eligible after either three uniform exchanges completed within one second or
eight completed within ten seconds. Every exchange must match the same client,
exact server name, server IP, port, and TLS fingerprint and have tightly
clustered request and response sizes. The rapid branch acts before a measured
Weather conveyor can deliver most of its repeated responses; the sustained
branch retains coverage for slower feeds. History is bounded to 512 exchanges
per client. The policy independently validates the count, time window, relative
spreads, compact/root shape, and exact-endpoint flag, then blocks only the new
5-tuple. It does not enable a retry guard. The positive Weather captures select
the operator; two browser controls and all retained Mail, Disk, photo, archive,
and download controls select zero flows through it.

The endpoint-multiplex branch moves enforcement ahead of a companion response.
It requires a completed compact root exchange plus at least three concurrent
compact root flows carrying at least two distinct names to the same client,
server IP, and port within one second. Confirmation reassesses only active root
peers opened within two seconds on that exact endpoint, and remains usable for
three seconds for newly opened companions. Both the trigger and companions are
exact-flow-only actions. No server name, domain family, or address is encoded
in this operator. The retained browser, Mail, Disk, photo, archive, and download
controls emit zero endpoint-multiplex or companion actions.

The cross-endpoint lineage branch handles the same compact root conveyor when
its companion moves to a different server address. It activates only after an
already confirmed conveyor and requires the new root flow to match both the
complete TLS fingerprint and the lineage fingerprint from that confirmation.
The client and destination port must match, the server endpoint must differ,
and the ClientHello must fall within the same bounded three-second causal
window. The confirmation does not propagate through companions, and each
action remains limited to the selected 5-tuple. The failed Weather capture
selects eight companion flows before their first server payload; the retained
browser, search, Mail, Disk, photo, archive, and download controls select zero.
No server name, domain family, or address is encoded in this branch.

The active setup-cohort branch covers delivery channels that opened immediately
before a different uniform conveyor was confirmed. It requires at least two
still-active compact root flows with the same endpoint, server name, TLS
fingerprint, and lineage fingerprint; both must have no PSK identity and be at
most two seconds old. The confirmed conveyor must use a different endpoint,
server name, and TLS fingerprint. FlowGraph then reassesses only that bounded
cohort, and the policy independently validates every condition before blocking
the exact 5-tuples. A lone flow, a stale cohort, or a same-profile transition is
fail-open. This branch contains no server name, domain family, or address
constants and does not create a retry guard or device-wide block.

A setup-resumption descendant branch follows only a setup cohort already
confirmed by that operator. For six seconds it retains at most 128 bounded
context records per client. A resumed descendant must reuse the exact setup
endpoint and root name, change the setup TLS profile, carry a PSK identity, and
have at least one peer with the same resumed fingerprint and lineage opened
within 250 ms. Both peers must still have zero server payload. Confirmation
reassesses the synchronized peer and emits each flow at most once. The policy
revalidates the two setup contexts, two resumed peers, time bounds, profile
transition, zero-response boundary, and exact endpoint/name before issuing
exact-flow-only actions. A lone or stale resumed flow is fail-open; no domain or
address constant and no device-wide block is introduced.

The intra-flow successor branch covers a later delivery channel that reuses a
confirmed conveyor endpoint instead of opening another short-flow burst. The
new compact root setup must start within 30 seconds of an independently
confirmed uniform conveyor, use the same endpoint but a different root name and
TLS fingerprint, and carry no PSK identity. It becomes actionable only when
four completed exchanges fit within four seconds: every request is 800-4000
bytes, at least three responses are 1500-5000 bytes, and at least one response
is 20 KB or larger. The measured Weather feed completes this bimodal sequence
after its first item and before the repeated feed; retained search, Mail, clean
start, photo, and mixed-traffic controls contain no matching sequence. Exchange
history is bounded to eight records per active flow. The policy revalidates all
limits and blocks only that exact 5-tuple, with no retry guard, domain constant,
address constant, or device-wide context block.

A successor-resumption descendant branch closes the measured endpoint
migration after that intra-flow decision. A confirmed bimodal successor creates
one non-renewing ten-second context for its exact client, root name, and
destination port. The context is not actionable until two compact PSK-resumed
flows with the same new TLS fingerprint and lineage open within 250 ms on two
different server endpoints, both before any server payload. Their profile and
endpoint must also differ from the confirmed successor. That synchronized pair
fixes the only resumed profile eligible for the remainder of the original
window; later exact-name descendants may be selected, but cannot extend the
deadline. Contexts are bounded to 128 per client. The policy revalidates the
origin age, pair size, endpoint count, timing, profile transition, lineage, and
zero-response boundary before blocking only the selected 5-tuple. A lone pair
member, same-endpoint pair, changed lineage, or late descendant remains
fail-open. No domain, address, or device-wide block is introduced.

The compact root-profile cycle operator handles a delivery channel that keeps
one endpoint and root name but rotates TLS state. It recognizes a bounded
state-machine sequence: setup profile A, two PSK-resumed flows sharing profile
B, then two synchronized setup flows returning to profile A. Both B/B and A/A
pairs must open within 250 ms; the setup-to-resumed and resumed-to-return
phases are independently limited to six seconds. The returned setup pair must
still have zero server payload, and every phase must use the exact client,
server endpoint, port, and root name. A confirmed cycle retains only the two
derived TLS profiles for ten non-renewing seconds so an exact-endpoint resumed
B descendant can also be stopped before its response. Context is bounded to
128 records per client. The policy independently validates all counts,
timings, profile transitions, endpoint/name equality, PSK state, and the
zero-response boundary. Actions remain exact-flow-only with no retry guard;
an absent setup phase, lone pair member, endpoint change, stale transition, or
different lineage stays fail-open. The operator contains no domain, address,
ASN, or application constants.

The paired root first-exchange operator covers synchronized setup channels
whose first responses carry a large transfer before a longer feed begins. It
requires exactly two compact non-PSK root flows with the same client, name,
port, TLS fingerprint, and lineage. The pair may use one or two endpoints.
Their ClientHellos and observed first-exchange progress must each be within
400 ms. Both requests must be 800-4000 bytes, both responses must be at least
1500 bytes, and at least one response must be 10 KB or larger. The engine
assesses these bounds while the first exchanges are still in progress instead
of waiting for the next request. Once the bounds are met, only those two
established 5-tuples are selected. A later non-PSK root flow with the exact
setup fingerprint, lineage, name, and port is selected before server payload,
including after endpoint migration. For a one-endpoint origin, a PSK-resumed
root flow on that same endpoint may
establish the new fingerprint and lineage during the following ten seconds,
before server payload. If the confirmed origin pair already spans two
endpoints, that initial resumption may establish the profile on another
endpoint. The exact resumed lineage may then migrate across endpoints for the
remainder of an initial 45-second context. Three exact descendants promote the
lineage to an active retry context, which expires after 45 seconds without
another exact descendant. Contexts are bounded to 128 per client, and
descendants remain exact-flow-only with zero server payload at decision time.
Pairs without a large response, unsynchronized pairs, wide requests, changed
names, changed profiles, and stale descendants are fail-open. The policy independently
revalidates every count, byte range, timing, profile transition, and lineage; no
retry guard, domain/address constant, or device-wide block is added.

The mirrored root-resumption operator acts before a conveyor has enough
completed responses to become uniform. It requires two compact root names on
two server addresses to first open with one shared setup fingerprint and then,
within one second, both move to a second shared resumed fingerprint. Each pair
must be synchronized within 250 ms, the setup and resumed profiles must differ,
and both selected resumed flows must still have zero server payload. Detection
reassesses only the matching active peer and blocks the two exact 5-tuples; it
does not create persistent state or a retry guard. The retained controls select
zero mirrored transitions, while the partial Weather canary selects both
resumed flows 918 ms before the older conveyor decision. This operator also
contains no server name, domain family, or address constants.

When a new subdomain supplies late fanout evidence, FlowGraph reassesses at most
32 still-active root peers from the same client and semantic domain family.
Same-session evidence may come from either ClientHello profile; cross-session
evidence counts only large ClientHello flows. Large roots are evaluated before
compact retries. The root-to-subdomain transition remains
shadow-only because a live retry cascade selected ordinary Mail, cloud, avatar,
favicon, and messenger flows without preventing the ad.

The hardened `easypi-prism-flowgraph.service` runs as `easypi` with only
`CAP_NET_RAW`. It does not receive `CAP_NET_ADMIN`. Bounded JSONL metadata is
written to `/var/lib/easypi/prism/flowgraph.jsonl` and rotated at 20 MiB.

Offline replay uses the same parser and model:

```
python3 -m prism_dpi.flowgraph replay capture.pcap > replay.jsonl
python3 -m prism_dpi.flowgraph.replay_eval replay.jsonl
```

The evaluator reports model candidates and production-policy actions as
separate stages. It applies the same structured evidence validators as the live
follower, deduplicates revisions of one flow, and evaluates archived event time
without weakening the live freshness boundary. This makes a content-control
capture with zero policy actions distinguishable from an ad capture whose exact
causal root flows are actionable, even when both contain cautious model
candidates.

FlowGraph also decrypts the public-key-derived protection on QUIC v1/v2 Initial
packets and reassembles bounded CRYPTO fragments to recover ClientHello metadata.
This is not MITM: no application data, session keys, certificates, or QUIC
1-RTT payloads are decrypted. QUIC observations use the separate
`quic_initial_observation` event, have no candidate verdict, and cannot enter the
active FlowGraph policy. Connection IDs are used only as short-lived in-memory
reassembly keys and are not written to telemetry.

When an established QUIC connection uses an unreadable short header, FlowGraph
emits only bounded `opaque_quic_flow_observation` metadata: the exact 5-tuple,
datagram size, and header form. Payload and connection IDs are not logged. At
most six observations are emitted per flow at one-second intervals, with 4,096
short-lived states globally. The TikTok module may act on one of these exact UDP
flows only when the same blocked device presented a validated TikTok
ClientHello to the same server IP within the preceding ten seconds. An IP or
ASN match alone remains non-actionable, so shared CDN addresses are never
blocked as a whole.

UDP/443 traffic that does not expose the QUIC fixed bit is emitted separately
as bounded `udp_443_flow_observation` metadata and carries no protocol claim.
It uses the same exact 5-tuple, six-observation limit, short-lived 4,096-state
cap, and TikTok endpoint-correlation boundary. Without a fresh validated TikTok
ClientHello for the same blocked device and server IP, it remains telemetry and
cannot reach the firewall.

For established TCP/TLS flows, FlowGraph also emits bounded
`tls_exchange_observation` records when encrypted traffic changes from a server
response back to a new client request. These observations preserve only record
counts, encrypted byte totals, response delay, next-request delay, flow age,
the response-size step from the preceding exchange, and derived TLS
fingerprints. They make repeated request/response timing
measurable without decrypting or storing application data. The event has no
verdict and is not accepted by the active candidate policy.
An open final exchange is emitted when its flow closes, expires, the monitor
stops, or offline replay ends. Such an observation records a null
`next_request_delay_ms` and an explicit `completion_reason` instead of inventing
a client request that was never observed.

`prism_dpi.flowgraph.sequence` projects a five-second exchange window into a
bounded temporal and feature-hashed topology vector. Raw server names and TLS
payloads are not retained in the vector. Its leave-one-out evaluator requires
at least three independent samples for every label, perfect nearest-label
agreement and a separation margin before it can approve a canary experiment.
The evaluator is shadow-only and has no firewall or Lineage Gate integration.

FlowGraph also emits at most one bounded `tls_record_sequence_observation` per
TLS flow. It contains no payload: only the first 96 application-record lengths,
their directions, and interarrival times. Partial sequences are finalized with
the flow or replay lifecycle. The record-level vectorizer uses 50 ms temporal
bins and feature hashing, so raw server names are not retained in its vector.
This observation is excluded from active policy.

The record evaluator can also build a ten-second bag of overlapping one-second
windows with a 250 ms stride. A shared-motif evaluation compares every positive
window against separate positive captures and every negative window. It fails
closed unless at least three captures exist per label, the motif repeats across
positive captures, and both an absolute distance margin and separation ratio
exclude all negative nearest windows. No motif is stored as an enforcement rule.

## Counterfactual Flow Lab

`prism_dpi.counterfactual_lab` is a separate causal experiment harness. It does
not classify or permanently block traffic. A root-owned plan may select only
one private client, TCP or UDP, and the ordinal of one newly observed flow. The
lab then drops packets from only that flow for at most five seconds or 64
packets, whichever comes first. Discovery expires after 30 seconds and every
parse, plan, queue, or runtime error fails open.

For retry-cascade experiments, a second root-only plan mode selects one public
server IP. It drops only connections to that server that begin after the plan is
armed, including concurrent siblings. This manually controlled mode may wait and
intervene for at most five minutes and 4096 packets; its one-device canary expires
after six minutes as an independent emergency release. Existing connections are
never added to the cohort. The selected address is experiment input and is not
retained as a detector or production policy. Ordinal experiments retain their
short five-second and 64-packet limits.

A third experimental selector follows service rotation without storing target
names or address ranges. It recognizes a structurally root-level SNI from the
cleartext TLS ClientHello and drops the ClientHello plus later packets from every
root-SNI flow that begins during the manual canary. Deeper names continue to pass.
This mode is TCP-only and uses the same five-minute intervention, packet, and
emergency-release bounds as the server cohort. It is a causal lab control, not a
production classifier: simultaneous root-domain browser traffic from the same
device would also be selected.

The narrower first-root cohort records the first complete root SNI seen after
arming and selects only later flows with that same observed name. A different
root name and every deeper name pass. Bounded, sequence-aware TCP reassembly
handles a ClientHello split across packets; gaps, invalid records, and resource
limits fail open. The name is experiment state, not configuration or a stored
target.

The causal-root cohort removes the ordering assumption from that experiment.
It selects a root SNI only after at least two distinct subdomain names beneath
that root were observed during the preceding 15 seconds. An earlier unrelated
root therefore passes. The evidence and selected name are bounded, in-memory
experiment state and are cleared on arm or disarm; no domain list is used.

The dedicated `easypi_prism_counterfactual` ipset is empty after installation,
holds at most one address, and expires entries after 120 seconds. Its NFQUEUE
rules use queue `4243` with `--queue-bypass`. A client cannot be armed while it
is present in the Lineage Gate canary. The lab has no backend API or runner
entry; experiments require an explicit root command on the test server.

The service runs as `easypi-prism` with only `CAP_NET_ADMIN`. Its plan is a
root-owned, non-writable, no-symlink JSON file with an exact schema. Telemetry
contains flow metadata and verdicts but no packet payload.

## TLS Lineage Gate

`prism_dpi.lineage_gate` is a separate, bounded enforcement experiment for TLS
session-resumption lineages. It does not decrypt payloads or retain PSK identity
bytes. The parser keeps only structural metadata such as identity and binder
lengths, key-share groups, supported versions, and a derived lineage fingerprint.

The gate receives only compact Yandex TLS ClientHello packets from a dedicated
NFQUEUE. The firewall path is additionally restricted by the
`easypi_prism_lineage` source-IP canary set, which is empty after installation.
For one structurally eligible flow the gate waits at most 200 ms. A second,
distinct flow from the same client with the same server name and lineage structure
confirms the pair: both initial packets are dropped and that lineage is rejected
for 30 seconds. A lone flow is accepted when its timer expires.

A 750 ms canary was rejected after a live Weather run. The delivery used a
roughly one-second uniform exchange conveyor, so widening the packet hold added
latency without preventing the ad. That slower behavior belongs in FlowGraph,
not in this bounded packet gate.

A live canary showed that the application could recover from correctly blocked
TCP lineage traffic over concurrent QUIC. While a lineage remains confirmed, the
gate therefore applies a 30-second transport quarantine to UDP/443 in both
directions for that canary client. UDP passes immediately before confirmation;
there is no Google, Yandex, or advertising-network IP range in this operator.

Safety boundaries:

- NFQUEUE rules use `--queue-bypass`, so an absent listener fails open.
- At most 128 packets may be pending; overflow is accepted.
- Retransmissions of a held ClientHello remain held under the same packet limit.
- Parse and callback errors are accepted.
- Service shutdown releases every retained packet.
- The service runs as `easypi-prism` with only `CAP_NET_ADMIN` and a read-only
  filesystem except for `/var/lib/easypi/prism-lineage`.
- The new lineage evidence remains outside the older FlowGraph active policy.

Canary controls are intentionally explicit and temporary:

```bash
sudo /opt/EasyPi/scripts/runner settings/setup_prism_lineage.sh canary-enable 10.23.1.10
sudo /opt/EasyPi/scripts/runner settings/setup_prism_lineage.sh canary-disable 10.23.1.10
sudo /opt/EasyPi/scripts/runner settings/setup_prism_lineage.sh status
```

An enabled canary entry expires automatically after 900 seconds.

## Layout

```
prism_dpi/
  flowgraph/
    events.py       typed flow, DNS, TLS, and assessment events
    packet.py       Ethernet/IP/TCP/DNS metadata parser
    tls.py          bounded TLS record and ClientHello parser
    model.py        5-tuple graph, causal sessions, fail-open assessment
    monitor.py      live observer and classic-PCAP replay
    policy.py       strict fresh-candidate validation for exact-flow requests
    source.py       AF_PACKET and PCAP sources
  lineage_gate/
    decision.py     bounded semantic pair state and fail-open verdicts
    packet.py       strict queued IPv4/TCP/TLS ClientHello extraction
    runtime.py      NFQUEUE adapter and bounded JSONL telemetry
  modules/
    apple_music/
    dailymotion/
    ...             one package per supported service
    mobile_ads/
      google/
        behavior.py    mediation, creative/media, and tracker cycle operator
        signatures.py  learned per-stage transport selectors
      yandex/
        __init__.py
        signatures.py  shared Yandex mobile-ad fallback observation
    whatsapp/
      __init__.py
      signatures.py  WhatsApp chatd signatures (:443 and HTTP fallback on :80)
    facebook/
      __init__.py
      policy.py       policy-gated exact Facebook TLS flow classification
  signatures/
    base.py         shared prefix, HTTP-host, and TLS ClientHello types
    __init__.py     public shared-type exports
  registry.py       central module registry
  rule.py           stable CLI that emits typed firewall matchers
```

## Adding a detector

1. Capture the app's first client bytes (`tcpdump -i eth0 -s0 host <ip> and tcp
   port <p> -w x.pcap`, look at the first payload bytes of its flow).
2. Add the detector under the relevant technology directory and export the
   module's `SIGNATURES`.
3. Register the module in `registry.py`, then connect it to
   `setup_app_blocking.sh`.

## Scope / limits

No MITM and no certificates. Prefix signatures inspect anchored first bytes;
HTTP fallback signatures inspect only the cleartext request line and Host
header; TLS shadow signatures inspect the record shape and exact cleartext SNI.
FlowGraph retains only derived metadata and bounded counters, never payload bytes.
Traffic over **cellular** is out of scope because it never reaches the gateway.
