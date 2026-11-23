# Chameleon (EasyPi Stealth): technical audit

Date: 2026-11-17. Code state: the TCP streams branch
plus the uncommitted integration of TCP streams into Stealth (described
separately, not installed on the Pi). The audit is based on the sources, the tests,
the measurements saved in `docs/` and passive observations of the running system.
Code and infrastructure were not changed during the audit, and no load tests were
run.

Labels:

- **[Code]** — confirmed by the source code (file and function given);
- **[Test]** — confirmed by an automated test;
- **[Measured]** — confirmed by a measurement (document or conditions given);
- **[Observed]** — a single passive observation on the live system;
- **[Hypothesis]** — a conclusion not checked by a direct experiment;
- **[Not checked]** — no data.

---

## 0. Summary

- Chameleon is its own combination of known mechanisms (TLS 1.3 through a real
  nginx, HTTP/2, inner AEAD encryption, imitation of browser behaviour) built into
  the EasyPi home router. There are no fundamentally new cryptographic or protocol
  inventions. Its defining traits are the gateway-level integration (devices
  need no app; kill switch, protected DNS and device selection all work) and the
  number of on-the-wire behaviour controls.
- The Chrome 157 TLS handshake disguise is confirmed by a test against captured
  ClientHellos. Traffic behaviour (record sizes, rhythm, idle) has **never been
  compared** with real Chrome under identical conditions; only Chameleon's own
  metrics exist. "Indistinguishable from Chrome" cannot be claimed.
- Speed: the new TCP streams reach the direct-path speed on downloads (about
  20 MB/s, the line limit), and pages open about twice as fast as through the old
  packet tunnel. Uploads after the nginx change: 5–9 MB/s versus 9.8 direct.
  Measurements come from one location at one time of day.
- Security: the inner XChaCha20-Poly1305 layer with replay protection and
  session-bound requests is implemented carefully and covered by tests, but
  **without forward secrecy** (session keys derive only from the PSK and public
  nonces). Forward secrecy comes from the outer TLS 1.3. There is no independent
  audit.
- Main open risks:
  - the new stream path has no protection against TLS-in-TLS detection;
  - long device TCP connections break when the transport epoch changes (every
    20 minutes to 4 hours);
  - on the VPS the packet tunnel is not restricted by destination: the VPS's own
    services are reachable, and the rules also allow wg0 (docker0 is closed by
    Docker's rules).
- Readiness outside EasyPi is low: the client is a Linux binary only, and all
  routing, the kill switch and deployment live in EasyPi scripts.

---

## 1. Architecture

### 1.1 Path from the device to the VPS

```
Device (no app)
  │  LAN
  ▼
EasyPi (Raspberry Pi), scripts/settings/stealth_vpn.sh
  │  mangle PREROUTING: mark 0x51822 by MAC of the selected devices
  │  FORWARD: ADMISSION → VPNM (anti-bypass) → PRISM → Stealth kill switch → QUIC guard
  │
  ├── UDP and other IP ──► cham0 (TUN) ──► chameleon-client: IP packets
  │                                         in HTTP/2 (packet transport)
  └── TCP (new) ──► veth chtcp0 ──► netns easypi-chtcp: TPROXY
                                       ──► chameleon-client: one HTTP/2
                                           request per TCP connection
  ▼
TLS 1.3 (uTLS, Chrome 157 ClientHello), one HTTP/2 connection
  ▼
VPS: nginx 1.28 (real, Let's Encrypt certificate) ── 127.0.0.1:9080 HTTP/1.1
  ▼
chameleon-server (Go): session check, decryption of the inner layer
  ├── packets → TUN chameleon0 → NAT → internet
  └── streams → net.Dial to the website (with an address filter) → internet
```

Sources:

- Device mark and ip rule — **[Code]** `stealth_vpn.sh`,
  `install_device_routing()`.
- FORWARD order — **[Observed]** `iptables -S FORWARD` on the Pi. The stream
  path's rules are appended at the end (`tcp_stream_forward_rules()`,
  `iptables -A`). **[Test]**
  `test_stealth_tcp_streams_keep_every_forward_policy_and_fall_back` checks this.
- Packet transport — **[Code]** `clientcore/transport.go`. Behind nginx it uses
  separate upward and downward HTTP/2 streams rather than CONNECT, because nginx
  talks to the backend over HTTP/1.1. **[Test]**
  `TestSyncDoesNotAdvertiseConnectCarrierBehindNginx` checks this.
- Stream path: `cmd/chameleon-client/tcp_relay.go` (`relayTCP`),
  `clientcore/tcp_stream.go` (`OpenTCPStream`), `server/tcp_stream.go`
  (`handleTCPStream`).
- nginx frontend: **[Code]** `backend/app/services/stealth_components/tls.py`,
  `_nginx_frontend_config()`; **[Observed]** the live server serves TLS 1.3, ALPN
  h2 and a Let's Encrypt certificate (ECDSA P-256).

### 1.2 Protocols and encryption

| Layer | Mechanism | Where |
|---|---|---|
| Outer | TLS 1.3, nginx on the server (TLS_AES_256_GCM_SHA384 in the check), ALPN h2 | [Observed] openssl s_client |
| ClientHello | uTLS v1.8.2: Chrome 133 template plus the Chrome 157 differences (trust_anchors 0xca34, GREASE in signature_algorithms, shuffled extensions) | [Code] `clientcore/fingerprint.go`, `chrome157ClientHelloSpec()` |
| HTTP/2 | Go `x/net/http2` with changes: stream window 6 MiB, connection window 15 MiB, WINDOW_UPDATE sent in batches of half the window | [Code] `fingerprint.go`, `createRealityHTTP2Transport()`; `shared/h2_window_coalescer.go` |
| Login | challenge-response: the server issues a challenge (30 s TTL), the client answers with HMAC-SHA256(PSK, …), the server proves it knows the keys | [Code] `server/crypto_sessions.go` (`challenge`, `establish`); `shared/session_crypto.go` (`ComputeBootstrapMAC`, `ComputeServerProof`) |
| Session keys | HKDF-SHA256(PSK, salt = SHA256(client nonce ‖ server nonce), info = protocol ‖ session ‖ client ‖ client instance) → request key, two direction keys, two nonce bases, stream key | [Code] `DeriveSessionKeys()` |
| Every HTTP request | `Authorization: Bearer HMAC(authKey, time ‖ nonce ‖ client ‖ session ‖ method ‖ path)`, ±120 s tolerance, nonce cache up to 200,000 entries | [Code] `server/auth.go`, `sessionAuthMiddleware()` |
| Payload | XChaCha20-Poly1305, 64-bit counter in the nonce, replay window 128 | [Code] `shared/inner_crypto.go` |
| TCP streams | a separate key per stream: HKDF(StreamKey, salt = the stream's 16 random bytes); frames `[4-byte length][ciphertext]`, up to 16 KiB of plaintext | [Code] `shared/tcp_stream.go`, `NewTCPStreamCipher()` |
| REALITY marker | HMAC in the ClientHello SessionID; not used behind the nginx frontend, only in "direct" mode | [Code] `shared/reality.go`, `server/reality_listener.go` |

### 1.3 New TCP streams versus the old transport

| | Packet (cham0) | Streams (chtcp0) |
|---|---|---|
| What is carried | the device's IP packets, including its TCP acknowledgements | application bytes only; the TCP connection ends on the Pi and the server opens a new one |
| Retransmission and congestion control | double: device TCP over carrier TCP | single layer: Pi↔VPS TCP and VPS↔site TCP separately |
| Reverse traffic during downloads | 7.2 MB/min (device TCP acknowledgements) | 83 KB/min — [Measured] `CHAMELEON_TCP_STREAMS_COMPARISON.md` |
| UDP, ICMP | yes | no (they stay on the packet path) |
| IPv6 | no (Stealth blocks IPv6) | no, IPv4 only (`EncodeTCPStreamTarget`) |
| Destination protection on the VPS | FORWARD rule `-i chameleon0 -j ACCEPT` (see section 4) | private, special-purpose and own VPS addresses refused (`deniedTCPStreamPrefixes`) |
| Padding of the TLS handshake inside the tunnel | yes, 1200–3000 bytes (`shared/inner_handshake.go`) | **no** |
| Fallback | — | the client keeps the route into the stream path only while the server offers it; otherwise TCP uses cham0 ([Code] `manageStreamRoute()`, uncommitted) |

### 1.4 What was built in the project

Own implementation (all logic is written in the project; only cryptographic and
network libraries are used: uTLS, x/net/http2, x/crypto):

- a session protocol with challenge-response, binding to the client instance and
  no fallback to obsolete modes (`TestOldPSKAuthenticatorHasNoFallback`);
- a packet transport with cumulative ACKs, downlink retransmission, transport
  epochs and roaming;
- WINDOW_UPDATE interception and batched credit, as in a browser
  (`h2_window_coalescer.go`);
- TLS record size variation (`shared/record_shaping_conn.go`);
- padding of nested TLS handshakes;
- TCP streams with TPROXY in a separate netns and socket activation through
  systemd;
- gateway integration: device selection, kill switch, fail-closed DNS,
  protection before the client starts (prestart guard).

---

## 2. Chrome disguise

### 2.1 What matches and how it was checked

| Feature | Status | Evidence |
|---|---|---|
| ClientHello extension set, trust_anchors, signature_algorithms | matches captured Chrome 157 ClientHellos | [Test] `TestChrome157HelloMatchesCapturedChrome`: 64 builds, ≥32 different extension orders, ≥8 GREASE values |
| JA4 | prefix `t13d1517h2` as in Chrome; the tail varies with random GREASE | [Measured] `CHAMELEON_SHAPE_BENCH_RESULT.md`; variant `33f857a189cb` also appeared from real Chrome 157 (according to the document; the capture itself is not kept in the repository) |
| User-Agent and client hints | Chrome 157, desktop or Android; one profile for the whole connection | [Code] `desktopFingerprintProfiles`, `GetProfile()` |
| Number of connections | one long connection to the origin, as a browser | [Measured] shape bench: connections over 1 MB — 1, simultaneously open — at most 1 |
| Response to a plain login attempt without a key | an ordinary nginx 404 with the same size, headers and content as any missing page | [Observed] external requests: `/<prefix>/tcp` and `/<random>/tcp` → 404, 146 bytes, headers and body hash identical |
| Server certificate and TLS | real nginx, Let's Encrypt certificate, TLS 1.3, h2 | [Observed] openssl s_client |
| HTTP/2 credit | in batches of half the window, as in Chromium, not every 4 KiB | [Code] `h2_window_coalescer.go`; measured result: "dozens instead of about 4000 updates" over 64 MiB |
| Downstream record sizes | varied, up to 16 KiB (nginx `proxy_buffer_size 16k`); previously a constant 4122 bytes | [Measured] shape bench: the most frequent sizes are 16401, 35 and 30 bytes |

### 2.2 What was not checked against real Chrome

**No measurement in the repository compares Chameleon's traffic with real Chrome
under identical conditions** for record sizes, intervals, directions or idle
behaviour. The shape bench (`scripts/dev/chameleon_shape_bench.sh`,
`chameleon_shape_analyze.py`) measures only Chameleon. Claims about behavioural
similarity are [Hypothesis].

### 2.3 Known differences and detectable features

1. **Upload rhythm during downloads** — [Measured]: the client writes about 43
   times a second, and the server answers each write with a small control record
   (30 bytes, WINDOW_UPDATE from nginx). Echo share is 0.92: 92% of client records
   get such a reply without delay. This is not typical of a browser during a
   download. The document explicitly lists it as unresolved.
2. **Idle** — [Measured]: 8 packets per minute when idle (idle1) and 59 per minute
   after load, but that includes a download tail. [Hypothesis] about the cause:
   the connection is opened with `net.DialTimeout` (`fingerprint.go`, `dialUTLS`),
   and Go's default TCP keepalive is every 15 seconds. That is 4 probes and 4
   replies a minute, exactly 8 packets. Chrome uses a keepalive of about 45
   seconds. Not confirmed by a direct idle capture.
3. **HTTP/2 fingerprint** (SETTINGS, pseudo-header order, PRIORITY) is Go x/net,
   not Chrome — [Code]. It is visible only to whoever decrypts TLS, that is, our
   own nginx; a passive observer cannot see it.
4. **TLS inside TLS on the stream path** — [Code]: stream frames are not padded.
   The size of the device's first TLS message (about 1.5 KB) and of the site's
   replies passes into the outer TLS records almost unchanged, plus the frame
   header and the AEAD tag. `record_shaping_conn.go` changes only large records
   (3 KiB threshold). The packet path has protection (`IsInnerTLSHandshake`,
   1200–3000 bytes of padding). [Hypothesis]: the stream path is more visible to
   TLS-in-TLS classifiers until padding is added.
5. **Volume and duration** — [Hypothesis]: one connection carries the whole
   home's traffic for hours, gigabytes downstream, to a site with one domain on
   one IP. That is unusual for a browser talking to a small website.
6. **A POST body lasting hours** — [Code]: the packet transport's uplink is one
   long request. It is not visible inside TLS, but it produces a long one-way
   flow without pauses. [Hypothesis] about how noticeable this is.
7. **ClientHello drift between Chrome builds**: the profile is assembled by hand
   on top of the Chrome 133 template. As new Chrome versions come out the
   fingerprint will age, so it needs regular review ([Code] comment in
   `fingerprint.go`).

### 2.4 Active probing

- **[Observed]** An outside observer without a key gets an ordinary website on
  `/` (200) and identical 404s on the tunnel path and on a random path.
- **[Observed]** The negotiation address `/<prefix>/sync` answers 200 with a JSON
  challenge (165 bytes) without login. The prefix is 8 characters `[A-Za-z0-9]`,
  derived through HMAC from the transport key (`shared.DeriveRoutePrefix`) and
  visible only inside TLS. Brute force is unrealistic (about 2·10¹⁴ variants), but
  if the prefix leaks, this response reveals the service.
- **[Test]** `test_chameleon_uses_real_nginx_and_keeps_the_go_backend_private`
  checks that the backend listens only on loopback and that login errors turn
  into 404.
- The "direct" mode with its own REALITY listener, which forwards probers to the
  cover site, exists in the code (`reality_listener.go`) but is not used in the
  production setup.
- **[Not checked]**: probing by real DPI systems (TSPU, GFW), TLS-level replay
  attacks, long passive observation by a third party.

---

## 3. Speed and stability

### 3.1 Throughput and latency

Conditions: Raspberry Pi 5 (arm64), one VPS, Pi↔VPS RTT 23–35 ms, one location, one
time of day, 3 runs per test (2 for the parallel test). **[Measured]**
`CHAMELEON_TRANSPORT_BASELINE.md` and `CHAMELEON_TCP_STREAMS_COMPARISON.md`.

| Test, MB/s (median) | Direct | Packet, baseline | Packet, second run | Streams |
|---|---|---|---|---|
| Download 50 MB, Cloudflare | 19.96 | 13.65 | 8.37 | 19.52 |
| Download 50 MB, Hetzner | 19.73 | 5.28 | 1.06 | 14.46 |
| 4 parallel downloads | 19.93 | 14.11 | 8.83 | 19.94 |
| Upload 25 MB | 9.77 | 1.45 | 0.79 | 1.03 (before the nginx change) |

Uploads after the nginx buffer change (one stream, new connection, Stealth off)
— **[Measured]**: 16 KiB — 0.99 and 1.69; 256 KiB — 5.99 and 5.19; 512 KiB — 8.91
and 5.11; 1 MiB — 7.21 and 8.22 MB/s. Production uses 512 KiB. The packet path was
not re-measured after the change.

Opening websites, 6 sites × 3 runs, median — **[Measured]**:

| | Time to first byte, ms | Total, ms |
|---|---|---|
| Direct | 96 | 190 |
| Packet | 207 | 663 |
| Streams | 182 | 302 |

Client CPU on the Pi (share of one core) — **[Measured]**: Cloudflare download —
27% through streams, 34–49% through the packet path.

TCP retransmissions — **[Observed]**, passive counters, not a controlled
experiment: on two live carrier connections 0.013% and 0.15% of bytes were
retransmitted; across the whole Pi, 0.18% of segments. Under load and with packet
loss **[Not checked]**.

Measurement limits: one location; the Pi's line is limited to about 20 MB/s, so
anything higher is not visible. The spread is large: the packet path gave 13.7 and
8.4 MB/s in two runs, cause unknown.

### 3.2 Robustness

| Situation | Result | Status |
|---|---|---|
| VPS server restart | new streams did not open for about 5 s, then the client renegotiated the session on its own | [Measured] 2026-11-17, `recov.sh` output |
| Pi→VPS link down for 20 s | new streams work 1 s after it returns | [Measured] |
| Leaks around the tunnel during outages | 0 packets on the kill-switch counter | [Observed] |
| Packet loss (artificial, e.g. 1–5%) | — | [Not checked] |
| Long connections through streams | break when the transport epoch changes: minimum 20–40 min, maximum 90 min – 4 h, or 256 MiB – 1 GiB of traffic; the change happens in a quiet period of 3–15 s; streams are force-closed after 2 s | [Code] `clientcore/transport_epoch.go`; comment in `OpenTCPStream`. [Not checked] by measurement |
| Session renegotiation (server rejected the session) | open streams break, new ones use the new session | [Code] `MobileClient.OpenTCPStream` |
| Two client instances with one account | they displace each other's sessions | [Observed]; by design ([Test] `TestNewInstanceRevokesPreviousInstanceOfTheSameDevice`) |
| Server without stream support | TCP stays on the packet path | [Test] `TestStreamRouteFollowsServerSupport` (uncommitted); not checked on the device |
| Pi reboot with the new path | — | [Not checked]: the integration is not installed yet |

### 3.3 Remaining speed limits

- Uploads are limited by nginx's HTTP/2 window; 512 KiB gives 5–9 MB/s. The cause
  is confirmed by a measurement that changed one variable.
- Packet path: double TCP; on downloads it is 1.5–14 times slower than streams.
- Every new TCP connection through a stream costs an extra Pi↔VPS round trip plus
  the VPS↔site connection before the first byte.
- No QUIC transport and no congestion control tuned for lossy links.

---

## 4. Security

### 4.1 Algorithms

- Outer layer: TLS 1.3 from nginx and OpenSSL, forward secrecy through ECDHE
  ([Observed]).
- Inner layer: XChaCha20-Poly1305 (`golang.org/x/crypto`), HKDF-SHA256,
  HMAC-SHA256 ([Code]).
- PSK — 32 bytes per installation (`buildMobileConnection` requires 32 bytes);
  the transport key is separate.

### 4.2 Login, keys, sessions

- One-time challenge: 30 s TTL, deleted after use, at most 4096 at once. [Test]
  `TestBootstrapChallengeCanBeConsumedOnlyOnce`,
  `TestBootstrapReplayFailsAfterServerRestart`.
- Mutual proof: the server sends an HMAC over the session parameters ([Test]
  `TestServerProofMatchesNegotiatedSession`).
- Every request is signed and bound to the session, method and path. [Test]
  `TestSessionAuthenticatorIsBoundToRequestPath`,
  `TestSessionAuthenticatorFailsAfterServerRestart`,
  `TestReplayNonceSurvivesFullTimestampValidityWindow`.
- The client identity is derived from the PSK and cannot be chosen ([Test]
  `TestAuthRejectsCallerSelectedClientIdentity`).
- Revoking a device credential also ends existing sessions ([Test]
  `TestDeviceCredentialRevocationRejectsFreshAndExistingSessions`,
  `TestSessionRevocationInterruptsAStreamingRequestBody`).
- Limits: global and per-IP before login ([Test]
  `TestPreAuthAdmissionHasGlobalAndPerIPBounds`), 8 tunnel requests and 256
  streams per session ([Test] `TestTCPStreamsArePerSessionLimited`,
  `TestTCPStreamsDoNotUseTunnelRequestSlots`).
- **The inner layer has no forward secrecy** — [Code] `DeriveSessionKeys`: key
  material = HKDF(PSK, nonces sent in clear inside TLS). Whoever recorded the
  traffic, later obtained the PSK *and* removed the outer TLS (for example the
  VPS operator or a compromised nginx) can decrypt the inner layer. The outer TLS
  does have forward secrecy.

### 4.3 Replay protection

- Packets: 64-bit counter and a sliding window of 128 ([Code] `counterWindow`).
- HTTP requests: time ±120 s and a nonce cache ([Code] `replayNonceStore`).
- Streams: a separate key per stream (HKDF with a 16-byte salt), with a counter
  and window inside the stream ([Test] `shared/tcp_stream_test.go`: streams do
  not share keys).

### 4.4 Threat model and checks

Covered in code and tests:

- passive observer (disguise, padding, one connection);
- prober without a key (404, real website);
- replay of requests and packets;
- brute force of client identities;
- resource exhaustion (limits);
- leaks in logs — 21 tests in `privacy_logging_test.go` (server 11, client 9,
  CLI 1), for example `TestEveryOperationalErrorClassDropsOriginalErrorText`;
- devices bypassing the tunnel (kill switch, prestart guard, fail-closed DNS —
  tests `tests/security/test_chameleon_*`, `test_stealth_*`);
- streams reaching the VPS's internal networks ([Test]
  `TestDefaultTCPStreamPolicyBlocksInternalDestinations`).

Problems found:

1. **The packet tunnel on the VPS is not restricted by destination** —
   [Observed] `iptables -S FORWARD` on the VPS: `-A FORWARD -i chameleon0 -j ACCEPT`,
   INPUT policy ACCEPT. A separate check through the tunnel (one TCP connection
   per address) showed:
   - the VPS's own SSH opens at the tunnel address 10.10.0.1:22. The other VPS
     services are reachable the same way, because INPUT from chameleon0 is not
     restricted;
   - a container on docker0 did not answer: Docker's and EasyPi's own rules close
     it, not Chameleon's;
   - wg0: the rules let traffic through, but the only WireGuard peer has no
     handshake at all, so it cannot be checked in practice.

   The stream path refuses such addresses, so the policy is inconsistent.
2. The inner layer has no forward secrecy (see 4.2).
3. `/<prefix>/sync` answers without login (see 2.4) — low risk.
4. The client has `CAP_NET_ADMIN` in the Pi's main network namespace
   (`write_chameleon_unit`). TUN needs it, but a compromised client could change
   the Pi's routing. Other isolation: a separate user, `NoNewPrivileges`,
   `ProtectSystem=strict`, `RestrictNamespaces`, `MemoryDenyWriteExecute` ([Test]
   `test_stealth_client_runs_as_restricted_systemd_service`).

There is **no** independent external audit. All checks are the project's own
tests and this review.

---

## 5. Project quality

### 5.1 Tests

- Go: shared — 19, server — 63, clientcore — 34 (+3 new methods),
  cmd/chameleon-client — 6 (some Linux-only), plus the mobilelink and prismlink
  packages. All pass ([Test] `go test ./...` 2026-11-17).
- Python, Stealth and Chameleon security: 56 pass, 6 are skipped on Windows (they
  need Linux network namespaces), and 1 fails because of a Windows path, unrelated
  to the changes (`test_ufw_cleanup_preserves_existing_ssh_access`).
- On-device acceptance scenarios: `tests/acceptance/chameleon_*` (firewall,
  recovery, reconnect, strict DNS, runtime connectivity). Not run during the
  audit.
- Measurement stands: `chameleon_shape_bench.sh`, `chameleon_transport_baseline.sh`.
- Missing: load tests with packet loss, fuzzing of the frame parsers
  (`ReadTCPStreamFrame`, the demasker), comparison with a real Chrome capture,
  client/server version compatibility tests.

### 5.2 Known unfixed problems

1. No TLS-in-TLS padding on the stream path (2.3 item 4).
2. An epoch change breaks long device TCP connections (3.2).
3. When the site closes the connection, the stream closes completely; a
   half-close from the site is not propagated ([Code] `handleTCPStream`: on a read
   error from upstream the handler returns).
4. No IPv6 in Stealth or in streams.
5. Upload rhythm of about 43 records a second with 30-byte replies (2.3 item 1).
6. Periodic packets when idle, probably Go's 15 s keepalive (2.3 item 2).
7. Open FORWARD on the VPS for the packet tunnel (4.4 item 1).
8. The documentation disagrees with the code: the README says ACKs are batched
   every 50–120 ms or 64 packets, while the code uses 400–1200 ms and 768
   (`downlink_ack_batch.go`).
9. The TCP stream integration into Stealth is not installed and not committed;
   the new path on the Pi is currently enabled by a debug script and disappears
   after a reboot.

### 5.3 Readiness outside EasyPi

- Server: a standalone Go binary with a systemd unit, but installation, nginx and
  certificates are deployed by the EasyPi backend over SSH
  (`stealth_components/deployment.py`).
- Client: a Linux binary that only creates the TUN and moves packets. Routing,
  kill switch, DNS, the stream path and configuration delivery live in
  `stealth_vpn.sh` and the EasyPi backend. The repository has no standalone
  cross-platform client.
- Conclusion: not ready as a standalone product outside EasyPi. As an EasyPi
  component it works on one installation with one VPS.

---

## 6. What it takes for the assessment to become evidence-based

1. A capture of real Chrome 157 on the same scenarios (idle, pages, video,
   download, upload), run through the same analyzer, and a table of differences.
2. Loss experiments (netem 1%, 3%, 5%, delay 100–300 ms) for the packet and stream
   paths, with retransmission counters.
3. An idle capture to check the keepalive hypothesis.
4. A TLS-in-TLS classifier (from open research) against the stream path before
   and after padding.
5. An external audit of the session cryptographic protocol.

Items 2 and 4 require load tests, which the audit's conditions excluded.
