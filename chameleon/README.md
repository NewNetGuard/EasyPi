# Chameleon — the transport behind EasyPi Stealth

Chameleon is an encrypted tunnel disguised as an ordinary HTTPS website. It carries
the internet traffic of devices on the home network (through the Pi running
EasyPi) and of phones (through Mobile Link) to the user's own VPS and from there to
the internet. To a filtering system (DPI, the Russian TSPU) the connection looks
like Chrome working with one nginx website for a long time.

Chameleon is a project of its own: its version is in `VERSION`, its license in
`LICENSE`, and a tagged version builds and tests without anything outside this
tree. EasyPi vendors a tagged version under `chameleon/` and its build compiles
all of it from there; the test and measurement tools live here too. Detailed
reports are in `docs/` (links in the last section).

This vendored copy, Chameleon 1.1.5, is distributed under `LICENSE` in this
directory. The standalone Chameleon project, version 1.2.1, is distributed
separately under the Mozilla Public License 2.0 (MPL-2.0); MPL-2.0 does not
apply to the rest of EasyPi.

The wire protocol keeps its `easypi/...` key-derivation and authentication labels
(PrismLink, Mobile Link, mobile credentials): they are part of the protocol, and
renaming them would cut off every installed phone and server.

Labels used below:

- **[Measured]** — measured on a test stand or on the live system;
- **[Code]** — follows from the code;
- **[Estimate]** — expert estimate, not verified by measurement.

## Contents

1. [How it works](#1-how-it-works)
2. [Components and where they run](#2-components-and-where-they-run)
3. [Protocol: session, encryption, carrier](#3-protocol-session-encryption-carrier)
4. [TCP streams — the main Stealth transport](#4-tcp-streams--the-main-stealth-transport)
5. [Masking](#5-masking)
6. [Stealth on the Pi](#6-stealth-on-the-pi)
7. [Server on the VPS](#7-server-on-the-vps)
8. [Mobile Link — the home tunnel for phones](#8-mobile-link--the-home-tunnel-for-phones)
9. [Build, installation, updates](#9-build-installation-updates)
10. [Tests and tools](#10-tests-and-tools)
11. [Measured results](#11-measured-results)
12. [Limits and possible improvements](#12-limits-and-possible-improvements)
13. [Operations](#13-operations)
14. [Documents](#14-documents)

---

## 1. How it works

```
 device on the LAN ──► Pi (EasyPi Stealth)
                        │  device TCP → TPROXY → Chameleon stream
                        │  everything else (UDP, ICMP) → TUN cham0 → packet tunnel
                        ▼
              one TLS 1.3 + HTTP/2 connection
              (Chrome ClientHello, no SNI or the server's domain)
                        ▼
 VPS: nginx :443 (real TLS, cover website, secret path prefix)
                        │  proxy_pass to 127.0.0.1:9080
                        ▼
      chameleon-server ── TCP streams: dials the website itself
                       └─ packets: TUN chameleon0 + NAT
                        ▼
                     internet
```

Key properties:

- **Real TLS and a real website.**
  - TLS on the VPS is terminated by Ubuntu's ordinary nginx with a Let's Encrypt
    certificate.
  - Without the secret path it serves an ordinary website, and a tunnel route
    answers an outsider with nginx's standard 404.
  - A prober opening the server in a browser or scanner sees a website on nginx.
- **One carrier.** All of a device's data travels inside one long-lived HTTP/2
  connection, like a browser working with one site.
- **Two encryption layers.** The outer layer is nginx's TLS. The inner layer is
  Chameleon's end-to-end XChaCha20-Poly1305 between client and server, so nginx
  only ever sees encrypted request bodies.
- **Two data paths:**
  - device TCP travels as separate HTTP/2 streams (the main mode);
  - everything else travels through the packet tunnel over TUN: UDP, ICMP, and
    TCP whenever the server does not offer streams.

## 2. Components and where they run

| Directory | Binary | Runs on | Purpose |
|---|---|---|---|
| `cmd/chameleon-client/` | `chameleon-client` | Pi, `/opt/EasyPi/bin/chameleon-client` | Stealth client: TUN `cham0`, accepts TCP streams (socket from systemd), stream route |
| `server/` | `chameleon-server` | VPS, `/opt/chameleon-server/chameleon-server` | tunnel server: sessions, TCP streams, packet tunnel, DNS |
| `server/` | `chameleon-server-home` (arm64) | Pi, `/opt/EasyPi/bin/chameleon-server-home` | Mobile Link home server for phones |
| `cmd/chameleon-mobile-link-relay/` | `chameleon-mobile-link-relay` | VPS | Mobile Link relay: phone → VPS → Pi |
| `cmd/chameleon-mobile-link-agent/` | `chameleon-mobile-link-agent` | Pi | Mobile Link agent: keeps the connection to the relay |
| `clientcore/` | — | library | client core: transport, session, epochs, streams, fingerprint |
| `shared/` | — | library | shared code: cryptography, formats, stream frames, record shaping |
| `mobilelink/`, `prismlink/` | — | library | Mobile Link and PrismLink UDP tunnel protocols |
| `server/nginx/` | `easypi-chameleon-nginx` + patch | VPS, `/usr/local/sbin/` | builds and maintains nginx with the WINDOW_UPDATE patch |
| `server/site/` | — | VPS, `/opt/chameleon-server/site` | cover website |
| `tools/` | — | development | test stands and measurements (section 10) |

Parts of EasyPi outside this directory:

- `scripts/settings/stealth_vpn.sh` — turns Stealth on the Pi on and off: routing,
  guards, DNS, the client unit, the stream path;
- `scripts/settings/mobile_link_agent.sh` — Mobile Link on the Pi;
- `backend/app/services/stealth_components/` — server deployment to the VPS
  (Deploy & Start, nginx and server config templates);
- `scripts/maintenance/verify_runtime_health.py` — network health check after
  installs and updates.

## 3. Protocol: session, encryption, carrier

### Session

- The client fetches a one-time server challenge (`/sync`) and establishes a
  session. The previous protocol is never accepted as a fallback.
- **Keys.** HKDF-SHA256 derives separate keys from the installation key, two
  fresh nonces, the session ID and the client process ID:
  - a request-authentication key;
  - a client→server key;
  - a server→client key;
  - a stream key (`StreamKey`).
- **Data.** Every tunnel packet and every DNS query is encrypted with
  XChaCha20-Poly1305.
- **Replay protection.** 64-bit counters and a sliding window.
- **Request authentication.** HTTP authenticators are bound to the session,
  method and path.
- **A server restart** invalidates old sessions.
- **Credentials.**
  - The home client (Pi) authenticates with `client_auth_key`.
  - Each phone uses its own key `HMAC(client_auth_key, "easypi/mobile-auth/v1/" + id)`
    from the `mobile_clients.json` registry.
  - The registry holds at most 200 devices, with addresses in the tunnel /24.
  - One credential has one live session: a new client process replaces the old
    one.

### Routes

The path prefix is derived from `psk_key`: `HMAC(psk, "chameleon-route-prefix-v1")`,
8 characters. Without it nginx answers 404.

| Path | Purpose |
|---|---|
| `/sync` | challenge, session establishment, capability exchange |
| `/upload` | persistent uplink stream (request body) |
| `/stream` | persistent downlink stream (response body) |
| `/push`, `/poll` | fallback mode with separate requests |
| `/tcp` | one device TCP stream (section 4) |
| `/dns` | DNS through the tunnel |

nginx turns authorization errors (401) into 404, so the tunnel path cannot be told
apart from a missing page. On the tunnel path the client treats 401 and 404 as a
rejected session and negotiates a new one after 3 s. After a server restart the
tunnel recovers on its own within 2–6 s [Measured].

### Carrier and epochs

- **One HTTP/2 connection:**
  - uplink is the body of a long `/upload` request;
  - downlink is the body of a long `/stream` response;
  - every device TCP stream has its own `/tcp` request in the same connection.
- **Acknowledgements are batched:** one per 400–1200 ms or per 768 packets,
  piggybacked on useful uplink data where possible [Code].
- **No heartbeat.** There are no empty keepalive packets and no periodic HTTP/2
  PINGs. After a long silence there is one check with a random delay.
- **Epochs.** From time to time the connection is replaced by a new one, as a
  browser would:
  - the replacement age is random, from 20–40 min up to 90 min – 4 h;
  - the data budget is 256 MB to 1 GB;
  - a replacement happens only in a quiet pause of 3–15 s [Code];
  - the new connection is authenticated first and only then replaces the old
    one; a failed attempt leaves the old one untouched.
- **Epochs and open streams:**
  - an old connection is not cut while device TCP streams are open in it;
  - it closes when its last stream ends, or after 2 h without traffic;
  - at most 4 old connections are kept [Code];
  - stream bytes count only toward their own epoch's budget.
- **Network changes.** The client can move its session to a new address once the
  old path has been silent for 5 s. Unacknowledged downlink data is kept for
  retransmission.

## 4. TCP streams — the main Stealth transport

All traffic used to travel as IP packets through TUN. Now every device TCP
connection travels as its own HTTP/2 stream: the Pi terminates the device's TCP
locally and the server dials the website itself. This means:

- no TCP inside TCP, so no double retransmissions and no sawtooth throughput;
- uploads and downloads run at full speed;
- device packets are not visible as TLS inside TLS.

### On the Pi

- **Data path.**
  - TCP from devices covered by Stealth gets mark `0x51822`.
  - Rule `5092` sends it to table `51824`.
  - From there it goes through veth `chtcp0` (169.254.77.1) into network
    namespace `easypi-chtcp` (`chtcp1`, 169.254.77.2).
  - Inside, TPROXY hands the connection to port 15080.
- **Accepting connections.**
  - systemd creates the listener: unit `easypi-chameleon-tcp.socket` with
    `NetworkNamespacePath=` and `Transparent=yes`.
  - systemd passes the socket to the client, so the client needs no extra
    privileges.
- **TCP to the VPS itself** (rule `5091`) uses `cham0`, not a stream.
- **The client manages the stream route.**
  - The client installs the route in table `51824` only while the server offers
    streams, and checks every 2 s.
  - Without the route, TCP falls through to the ordinary device rule (`5096`) and
    uses the packet tunnel, so a server without stream support never cuts the
    network.
  - The route is removed when the client stops.
- **Early data.** The client waits up to 20 ms for the device's first bytes and
  sends them together with the stream request. For TLS that is the ClientHello:
  one request instead of an "open → data" exchange.
- **Where the namespace is created.**
  - It is created and removed through `systemd-run` in the host mount namespace.
  - The EasyPi backend runs with `PrivateTmp=yes`, and an `ip netns` mount made
    from the backend is invisible to systemd. Before this fix Stealth turned on
    from the panel always ran without streams.

### On the wire

- The request body starts with a 16-byte random stream nonce.
- Frames follow: `[4-byte length][ciphertext]`, at most 16 KB of data per frame.
- Every stream has its own keys: HKDF over `StreamKey`, the session ID and the
  stream nonce, so cipher counters of different streams never overlap.
- The first frame names the destination address.
- **Handshake masking** (header `X-Chameleon-Tcp-Shape: 1`):
  - it applies to the first 4 frames in each direction;
  - small frames are padded to 512–576 bytes;
  - the first large frame is padded to a random size: up to 4 KB upstream
    (ClientHello) and up to 8 KB downstream (the server's reply);
  - the frame format is `[2-byte length][data][padding]`;
  - bulk transfer goes unpadded, in full frames.

### On the server

- **Destinations.** The server dials only public IPv4 addresses. Private and
  special-purpose networks and the VPS's own addresses are refused
  (`deniedTCPStreamPrefixes`).
- **Limits.**
  - At most 256 streams per session.
  - Streams do not use the tunnel's request slots (`max_requests_per_session`):
    a browser opens dozens of connections.
  - A session with open streams counts as busy and is never removed as idle.
- **The response** starts at once (`EnableFullDuplex`); the stream is
  bidirectional.

## 5. Masking

| What | How | Verified |
|---|---|---|
| First TLS message | uTLS with its own Chrome 157 profile (cipher suites, extensions, groups, GREASE, shuffled order, X25519MLKEM768, ALPN h2) | [Measured] matches real Chrome 158 by JA4 `t13d1517h2_8daaf6152771` |
| TCP keepalive | 45 s, as in Chrome | [Measured] from socket timers |
| TLS records | full-size records for bulk transfer, no record-size warm-up | [Measured] 97% full-size records with a large window |
| HTTP/2 window | as in Chromium: 6 MB per stream, 15 MB per connection; credit returned in large batches (`inflowMinRefresh` 8 MB in a private copy of `x/net`) | [Code] |
| HTTP/2 opening | the client's opening SETTINGS carry Chromium's four entries: the record shaper drops the default `MAX_FRAME_SIZE` that `x/net` repeats | [Measured] first record after the handshake 87 bytes, as in Chrome (was 93) |
| Connection opening | session setup requests carry a cache-busting query of random length; the server answers them after a random 4–44 ms with padding of random length, so the client's SETTINGS acknowledgement precedes the answer | [Measured] 80 openings: request sizes 11 → 50 distinct values, answer sizes 6 → 74 |
| Record shaping | negotiated after authentication; adds random padding of at most 2 KB to records that carry payload | [Code] |
| Packet path | packets are padded to sizes from a fixed set of buckets; in a write carrying less than 4 KB of packets, where single packet sizes could show, the bucket is also raised at random | [Measured] bulk transfer on the Pi: framing overhead 19% → 13%, download 15 → 17 MB/s on a 21 MB/s line |
| TLS inside TLS | the website handshake inside a stream is masked (section 4) | [Measured] the exact ClientHello size leak is gone |
| Server replies during upload | nginx patch: window credit returned in portions of at least 256 KB | [Measured] ~80 WINDOW_UPDATE per 25 MB instead of ~1500 |
| Active probing | real nginx and website, 404 on the tunnel path, Let's Encrypt certificate for a domain | [Measured] |
| Marker in SessionID | `HMAC(psk, pub ‖ nonce)[:16]` with a fresh random nonce every time; used only in `direct` mode (not needed behind nginx) | [Code] |
| Background traffic | none is generated: an idle connection stays silent | [Code] |

## 6. Stealth on the Pi

`scripts/settings/stealth_vpn.sh` turns Stealth on and off (`up`, `down`, `status`,
`reconcile`, `guard`, `resume`). The backend calls it through `scripts/runner`.

### Scope

- `all` — the whole network;
- `selected` — devices by MAC address.

### Routing and guards

- `5090` — private networks (10/8, 100.64/10, 172.16/12, 192.168/16, 169.254/16)
  always go direct, so access to the Pi and the LAN is never lost.
- `5091`, `5092` — TCP streams (section 4).
- `5093`, `5094` — Stealth DNS: the `easypi-stealth-dns` service (its own user)
  can only use table `51823`. Without the tunnel DNS is blocked instead of leaking
  to the ISP.
- `5096` — marked device traffic goes to table `51821` (`cham0`).
- **Pre-start guard** — chain `EASYPI_STEALTH_PRESTART`. It is the first FORWARD
  rule; it lets through only `cham0`, `chtcp0` and private networks and drops
  everything else. The `easypi-stealth-guard` service installs it before the
  network comes up.
- **Kill switch** — chain `EASYPI_STEALTH`. Without the tunnel, device traffic
  never goes out directly.
- **Invalid packets** (`INVALID`) toward `cham0` and `chtcp0` are dropped: after a
  Stealth toggle they arrived un-NATed and broke the stream.
- **QUIC** (UDP 443) is blocked by default (`EASYPI_STEALTH_QUIC`), so browsers
  fall back to TCP, that is, to streams.

### Client

- Unit `easypi-chameleon-client.service`, user `easypi-chameleon`.
- Privileges: only `CAP_NET_ADMIN`.
- Hardening: read-only file system, `MemoryMax=256M`, `TasksMax=128`,
  `LimitNOFILE=4096`.
- Log: `/var/log/easypi/stealth.log`.
- Status: `/run/easypi-stealth/status/`.

### Status

```sh
sudo bash /opt/EasyPi/scripts/settings/stealth_vpn.sh status
```

Returns JSON. Important fields:

- `running`, `connected` — the client runs and is connected;
- `tcp_streams` — device TCP currently travels as streams;
- `killswitch` — the kill switch is active;
- `dns_protected` — DNS goes only through the tunnel;
- `quic_blocked` — QUIC is blocked.

After an EasyPi update the backend itself brings Stealth back up. The recovery
services are `easypi-stealth-guard` and `easypi-stealth-resume`.

## 7. Server on the VPS

EasyPi installs and updates the server with **Deploy & Start**
(`backend/app/services/stealth_components/deployment.py`). New installs and
updates use the same idempotent procedure.

### What Deploy & Start installs

1. `iptables`, certbot 5.4 in its own environment, `flock`, and the
   `easypi-vps-guard` (port 80 closed except while a certificate is issued).
2. A Let's Encrypt certificate for a domain or an IP, renewed twice a day by
   `chameleon-cert-renew.timer`.
3. nginx from the Ubuntu package, the config `/etc/nginx/conf.d/easypi-chameleon.conf`
   and the cover website.
4. `easypi-chameleon-nginx install` — nginx with the patch (below).
5. `chameleon-server` with `server_config.json` and the units `chameleon-server`
   and `chameleon-network` (TUN `chameleon0`, NAT).

### nginx configuration (template in `tls.py`)

- `listen 443 ssl http2`, TLS 1.2–1.3, session cache.
- Tunnel location `^~ /<prefix>/` → `http://127.0.0.1:9080`:
  - `proxy_request_buffering off`, `proxy_buffering off`;
  - `client_body_buffer_size 1m` — the size the patch was measured with;
  - `client_body_timeout 24h` — long request bodies;
  - `keepalive_requests 1000000` — no GOAWAY in the middle of work;
  - `proxy_buffer_size 16k`, `proxy_buffers 8 16k` — downlink records are not all
    4122 bytes;
  - the client address is not passed to the server (`X-Real-IP ""`);
  - 401/403/404/405 → 404.
- All other paths serve the cover website or 404.

### nginx with the WINDOW_UPDATE patch

**The problem.** With an unbuffered request body, nginx returns flow-control credit
to the client after every portion it forwards. A 25 MB upload produced ~1500–2800
short control records. Chrome talking to Cloudflare produces ~1, and an ordinary
nginx website produces 0 [Measured].

**The patch** `server/nginx/h2-unbuffered-window-update-threshold.patch`:

- changes only two nginx functions
  (`ngx_http_v2_read_client_request_body_handler` and
  `ngx_http_v2_read_unbuffered_request_body`);
- credit is sent once at least min(half the buffer, 256 KB) has accumulated;
- result: about 80–96 records per 25 MB at the same speed, with no stalls on
  small, final or intermittent portions of data [Measured].

**How it lives on the VPS** — `easypi-chameleon-nginx`:

- **Diversion.** `dpkg-divert` moves the packaged `/usr/sbin/nginx` to
  `/usr/sbin/nginx.distrib`. Ubuntu updates put the new binary there and leave
  the patched one alone.
- **Build.** The patch is built from the source of the installed package version
  (`apt-get source` with private source lists, so the system's own apt runs never
  download source indexes). Configure options come from `nginx.distrib -V`,
  without the dynamic modules. Ubuntu's security fixes stay in the binary.
- **Ubuntu updates.** After every package change the apt hook
  `80easypi-chameleon-nginx` runs the new packaged nginx at once, and
  `easypi-chameleon-nginx-rebuild.service` rebuilds the patch in the background.
- **Failed build.** If the patch no longer applies or builds, the packaged nginx
  keeps running: the tunnel works, just without the patch. A daily timer retries.
- **Archive ahead of the VPS.** The Ubuntu archive keeps only the current source.
  If the archive already has a newer version while the package has not been
  updated yet, the patch is built after the update lands.
- **Limits:**
  - `worker_connections 4096`, `worker_rlimit_nofile 16384`;
  - nginx memory ceiling: MemoryHigh 25%, MemoryMax 35% of RAM;
  - past the ceiling the nginx master replaces the worker, and the VPS and SSH
    stay reachable.
- **Commands:** `status`, `rebuild`, `remove` (the last one puts the packaged
  nginx back).

[Measured] On 2026-11-19 on the VPS: nginx updated from `.12` to `.13`; the hook
ran the packaged `.13` at once, and the patch was built on the VPS itself (1 vCPU)
in about 95 s.

### Server configuration (template in `tls.py`)

- `frontend_mode nginx`, backend `127.0.0.1:9080`.
- `max_connections 4096` — the session ceiling. The real limit is the registry:
  one live session per device, at most 201 devices.
- `max_requests_per_session 8`, `max_sessions_per_source 8`.
- **Source quota**:
  - behind nginx or a relay every client arrives from `127.0.0.1`;
  - that address used to count as one subscriber network, and the ninth device
    was refused;
  - a local source no longer counts as a subscriber network; real networks keep
    the quota.
- **VPS isolation.** Tunnel clients cannot reach the VPS's internal networks
  (Docker, WireGuard, the tunnel subnet) or its own services. This comes from
  the `chameleon-network-setup` rules and the same list of refused destinations
  used for streams.
- **Unit `chameleon-server`:**
  - user `chameleon`, no privileges (`CapabilityBoundingSet=`);
  - `MemoryHigh=60%`, `MemoryMax=75%`, `TasksMax=512`, `LimitNOFILE=65536`.

## 8. Mobile Link — the home tunnel for phones

A phone connects to the **relay** on the VPS, the relay to the **agent** on the
Pi, and the agent to the Chameleon **home server** on the Pi:

- `127.0.0.1:9081` — TCP;
- `127.0.0.1:9083` — UDP PrismLink.

The phone gets the home address and EasyPi protection.

- Setup: `scripts/settings/mobile_link_agent.sh`.
- Home server config: `/etc/easypi-mobile-home/server_config.json`.
- Services: `easypi-mobile-home-tunnel` and `easypi-mobile-home-tunnel-agent`.

**Fixed:**

- **Source quota.** The same defect as on the VPS: the agent arrives from
  `127.0.0.1`. [Measured] Stand `tools/chameleon-load/run_home_quota.sh`, 10
  phones: the old build gave 22 refusals with 503, the fixed one 0.
- **Mobile Link nginx endpoint during installation**. The installer
  ran the script from the temporary update directory, so the nginx config got
  certificate paths that do not exist. On updates this produced a false warning;
  a fresh install outside `/opt/EasyPi` never got the endpoint at all.

## 9. Build, installation, updates

### Build

```sh
./build.sh          # server amd64+arm64, relay, clients and agents for both architectures
./build.sh arm64    # for installation on the Pi (arm64)
GO=/path/to/go ./build.sh
```

- Go 1.27.4 is required. If it is missing, `ensure-go.sh` downloads the official
  toolchain into `.build/` and verifies its SHA256.
- Build caches (`.build/`: toolchain, patched `x/net`) belong to the project that
  owns the tree: a Chameleon checkout keeps them in its own `.build/`; a project
  that vendors Chameleon (EasyPi) keeps them in its `.build/` one level up, where
  its installer and updater manage them. `CHAMELEON_BUILD_ROOT` overrides this.
- `tools/prepare_http2_modfile.sh` makes a private copy of `golang.org/x/net` and
  changes only `inflowMinRefresh` to 8 MB (a Chromium-like window). If that line
  changes in a new version, the build stops and asks for review.
- Flags: `CGO_ENABLED=0 -trimpath -buildvcs=false`.

| File in `bin/` | Installed to |
|---|---|
| `chameleon-server-amd64` | Pi → uploaded to the VPS by Deploy & Start |
| `chameleon-server-arm64` | Pi: `/opt/EasyPi/bin/chameleon-server-home` |
| `chameleon-client-arm64` / `-amd64` | Pi: `/opt/EasyPi/bin/chameleon-client` |
| `chameleon-mobile-link-relay-amd64` | VPS (Mobile Link) |
| `chameleon-mobile-link-agent-*` | Pi (Mobile Link) |

`build.sh` does not work under Git Bash on Windows: Go for Windows does not
understand `/c/...` paths in the `replace` directive. Releases are built on Linux.

### EasyPi installation and updates

- The EasyPi build packages everything from the main project directory. The
  installer (`install.sh`) checks the Chameleon sources, builds the binaries on the
  target machine and installs them into `/opt/EasyPi/bin/`.
- **Updates** go through `scripts/maintenance/apply_update.sh`:
  - signature check of the archive;
  - snapshot of the current version;
  - `install.sh`;
  - health check;
  - automatic rollback on any error.
- **The health check** (`verify_runtime_health.py`) compares the Stealth guard
  with the reference, including the `chtcp0` rule, and requires it to be the
  first FORWARD rule. Before the check the installer puts the guard back on top
  (`stealth_vpn.sh guard`, no client restart), because NetProtection, PRISM and
  the backend insert their own rules at the top when they start.
- **The VPS server** is updated with Deploy & Start after an EasyPi update.

## 10. Tests and tools

### Tests

```sh
go test ./...                                   # all Go tests
```

Python security tests:

```sh
PYTHONPATH="backend;." DATABASE_URL=sqlite:///./t.db SECRET_KEY=... \
  backend/.venv/Scripts/python.exe -m pytest tests/security
```

- Chameleon and Stealth tests: `test_chameleon_runtime_hardening.py`,
  `test_runtime_health_gate.py`, `test_security_invariants.py`.
- Acceptance tests must run on Linux as root:
  - `tests/acceptance/chameleon_firewall_regression.sh` builds the guard with the
    real `stealth_vpn.sh` and checks it with `verify_runtime_health.py`;
  - `tests/acceptance/chameleon_vps_isolation_regression.sh` checks VPS isolation.

**Important:** test Stealth the way the backend starts it. Running it as root in
the host mount namespace can hide a bug (section 4):

```sh
nsenter --mount=/proc/$(systemctl show -p MainPID --value easypi-backend)/ns/mnt -- \
  /opt/EasyPi/scripts/runner settings/stealth_vpn.sh up <conf> <scope> <ips> <quic> <macs>
```

### Test stands (`tools/`)

- **`tools/nginx-h2-window/`** — the nginx patch:
  - `build.py`, `build_tls.sh`, `build_ubuntu.sh` — builds without installation;
  - `bench.py` — h2c stand: speed, WINDOW_UPDATE, slow receiver, pauses, final
    portions;
  - `run_tls.sh` — TLS stand with the real client (`TestNginxWindowBench`);
  - `run_mem.sh` — nginx memory (`TestNginxMemoryBench`);
  - `test_vps_tool.sh` — end-to-end check of `easypi-chameleon-nginx` on Ubuntu:
    install, redeploy, package update, failed build, removal.
- **`tools/chameleon-load/`** — load:
  - `run_load.sh` — isolated stand in WSL: 1 vCPU and 1 or 2 GB in a cgroup,
    separate network namespaces for devices and for "the internet", 30 ms RTT,
    the real server and nginx;
  - the generator is `TestChameleonLoad`: a device is a separate Chameleon
    session with several TCP streams;
  - `run_home_quota.sh` — reproduces the Mobile Link quota.
- **`tools/connection-opening/`** — how connections open:
  - `run_opening.sh` — WSL stand on the prepared `chameleon-load` directory:
    many fresh sessions and epoch changes one after another
    (`TestOpeningCapture`), captured next to the client and next to the server;
  - `evaluate.py` — runs CensorLab detectors over the capture and reports the
    share of openings each one acts on.

### EasyPi scripts

- `scripts/dev/chameleon_shape_bench.sh` and `chameleon_shape_analyze.py` —
  capture and analysis of the traffic shape: TLS records, rhythm, idle;
- `scripts/dev/chameleon_transport_baseline.sh` — compares the packet tunnel,
  streams and the direct path.

The stand tests are skipped by a plain `go test`: they need the stand's
environment variables.

## 11. Measured results

**Speed** through the tunnel: a computer on the Pi's network, VPS 1 vCPU / 2 GB,
2026-11-19 [Measured].

| | Download 50 MB | Upload 25 MB | WINDOW_UPDATE per 25 MB |
|---|---|---|---|
| Packet tunnel (no streams) | 12.5–13.8 MB/s | 1.6–1.7 MB/s | — |
| Streams, unpatched nginx | 17–19 MB/s | 6.6–9.3 MB/s | ~1500 |
| **Streams + nginx patch (current)** | **16.6–19.4 MB/s** | **8.8–9.6 MB/s** | **~80** |

**Comparison with real Chrome 158** (Chrome → Cloudflare versus Chrome through
Chameleon) [Measured]:

- the first TLS message matches up to JA4;
- speed and volume per phase match;
- remaining differences: server control replies during uploads (reduced by the
  patch) and activity on one connection caused by the computer's background
  traffic.

**Load** — stand with 1 vCPU, 30 ms RTT [Measured]:

| | 100 active devices | 200 active | 200 idle |
|---|---|---|---|
| CPU of one core (avg / peak) | 21% / 35% | 41% / 62% | 2% |
| nginx + server memory | 219 MB | 414 MB | 253 MB |
| Errors | 0 | 0 with `worker_connections` 4096 | 0 |

- With `worker_connections 768` (the Ubuntu default) 84–90% of streams were
  refused at 200 devices. The limit is now 4096.
- 2 GB of RAM brings nothing over 1 GB up to 200 devices.
- [Estimate] On a slower real VPS vCPU a reasonable limit is about 150
  simultaneously active devices.

**nginx memory** with 128 concurrent streams [Measured]:

| State | unpatched nginx, 512 KB buffer | patched nginx, 1 MB buffer |
|---|---|---|
| Idle | +3 MB | +3 MB |
| Active upload | +20 MB | +22 MB |
| Worst case: the receiver does not read | +44–66 MB | up to +121 MB |

The worst case is bounded by the nginx memory ceiling.

## 12. Limits and possible improvements

**Limits:**

- The registry holds at most 200 mobile devices plus the home client; the tunnel
  network is a /24.
- Mobile Link's pre-authentication limit (at most 32 handshakes per address)
  applies to the relay's shared `127.0.0.1`.
- The backend on the Pi is a signed release. Deployment changes reach the Pi only
  with a new EasyPi release.
- The nginx patch is rebuilt on the VPS after every Ubuntu update, so build tools
  are installed there (marked as automatically installed).

**Improvements, by value for effort:**

1. A Firefox profile.
2. An own domain instead of DuckDNS.
3. Tests on several Russian ISPs, especially mobile ones.
4. A CDN mode — a large piece of work, but the only one that survives
   "whitelist" filtering.

## 13. Operations

**Pi:**

```sh
sudo bash /opt/EasyPi/scripts/settings/stealth_vpn.sh status   # Stealth status
systemctl status easypi-chameleon-client easypi-chameleon-tcp.socket
sudo ip netns exec easypi-chtcp ss -Htn state established | wc -l   # open streams
sudo tail -f /var/log/easypi/stealth.log
sudo python3 /opt/EasyPi/scripts/maintenance/verify_runtime_health.py
```

**VPS:**

```sh
systemctl status nginx chameleon-server chameleon-network
/usr/local/sbin/easypi-chameleon-nginx status   # running=patched / packaged
journalctl -u chameleon-server -n 50
journalctl -t easypi-chameleon-nginx -n 20      # patch builds and switches
grep -E 'worker_(connections|rlimit)' /etc/nginx/nginx.conf
```

**Backups** from the 2026-11-19 update:

- VPS:
  - `/root/easypi-pre-integration-20261119.tgz` — the server, its config,
    `/etc/nginx`, nginx;
  - `/root/easypi-nginx-13/pre.tgz` — the state before the nginx update;
  - `/root/easypi-nginx-rollback-12/` — the nginx `.12` packages.
- Pi: files `*.pre-integration-20261119` and `stealth_vpn.sh.pre-hostns-20261119`.

**Back to the packaged nginx:**

```sh
/usr/local/sbin/easypi-chameleon-nginx remove
```

**Common problems:**

- **`tcp_streams: false` while Stealth runs:**
  - the server does not offer streams — look for `TCP streams negotiated` in the
    client log;
  - or the stream socket did not start — `systemctl status easypi-chameleon-tcp.socket`.

  TCP then uses the packet tunnel, which is slower.
- **An EasyPi update rolled back with an error about the Stealth guard.** Run
  `verify_runtime_health.py`: the guard must match the reference and be the first
  FORWARD rule.
- **`running=packaged` on the VPS.** The reason is in `REASON` from
  `easypi-chameleon-nginx status` and in the `easypi-chameleon-nginx` journal.
  Rebuild with `easypi-chameleon-nginx rebuild`.
- **Do not use Deploy & Start from an old EasyPi backend:** it overwrites the
  nginx and server templates with old values.

## 14. Documents

| Document | Topic |
|---|---|
| [`docs/CHAMELEON_TECHNICAL_AUDIT.md`](docs/CHAMELEON_TECHNICAL_AUDIT.md) | technical audit |
| [`docs/CHAMELEON_TLS_IN_TLS_STREAMS.md`](docs/CHAMELEON_TLS_IN_TLS_STREAMS.md) | TLS-in-TLS masking inside streams |
| [`docs/CHAMELEON_CHROME_COMPARISON.md`](docs/CHAMELEON_CHROME_COMPARISON.md) | paired comparison with real Chrome |
| [`docs/CHAMELEON_H2_FLOW_CONTROL_OPTIONS.md`](docs/CHAMELEON_H2_FLOW_CONTROL_OPTIONS.md) | nginx WINDOW_UPDATE: options, patch, measurements |
| [`docs/CHAMELEON_LOAD_TEST.md`](docs/CHAMELEON_LOAD_TEST.md) | load test and limits |
| [`docs/CHAMELEON_TCP_STREAMS_COMPARISON.md`](docs/CHAMELEON_TCP_STREAMS_COMPARISON.md) | streams versus the packet tunnel |
| [`docs/CHAMELEON_TRANSPORT_BASELINE.md`](docs/CHAMELEON_TRANSPORT_BASELINE.md) | transport baseline measurements |
| [`docs/CHAMELEON_SHAPE_BENCH_RESULT.md`](docs/CHAMELEON_SHAPE_BENCH_RESULT.md) | traffic shape on the wire |
| [`tools/nginx-h2-window/README.md`](tools/nginx-h2-window/README.md) | nginx patch test stands |
