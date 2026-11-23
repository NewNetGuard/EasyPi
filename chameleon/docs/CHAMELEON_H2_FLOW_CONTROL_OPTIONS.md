# Short nginx replies during uploads: options without replacing nginx

Date: 2026-11-19. This is an analysis of options, not a decision: no code or
servers were changed.

## The problem (what was measured)

During uploads through the tunnel nginx answers the client with short HTTP/2
WINDOW_UPDATE control records (30 bytes):

| Conditions | Short replies per 25 MB |
|---|---|
| Live tunnel | 1747–2815 |
| Isolated nginx, tunnel setup (`proxy_request_buffering off`), 20 MB/s | 521–553 for any buffer from 512 KB to 8 MB |
| Isolated nginx, ordinary site (buffered body) | 0 |
| Chrome → Cloudflare | 1 |

Details are in `CHAMELEON_CHROME_COMPARISON.md`.

**Cause.** With an unbuffered body nginx returns flow-control credit after every
portion it forwards. The tunnel needs an unbuffered body: both the packet stream
and the TCP streams are long requests whose data must flow at once, not after the
body ends.

## Options

### 0. nginx settings (HTTP/2 stays with nginx)

| Setting | Expectation | Status |
|---|---|---|
| `client_body_buffer_size` | fewer replies | **[Measured]** does not help at 20 MB/s |
| `http2_body_preread_size` (initial stream window) | delays the first replies by its size, then the same | [Hypothesis], not checked |
| `http2_recv_buffer_size` | affects the read size, not the reply frequency | [Hypothesis] |

Expected conclusion: settings cannot fix it. Checking `http2_body_preread_size` is
cheap — the same isolated experiment, about 5 minutes.

### A. Uploads as a series of short requests (nginx stays as it is)

- **Idea.** Send the upload of a TCP stream (and optionally of the packet path)
  not as one endless request body but as consecutive POST requests of
  256 KB – 1 MB to a separate address where the body is buffered. An ordinary
  nginx site with a buffered body sends no credit: measured 0 per 25 MB.
- **What is visible from outside.** Instead of a reply every ~46 KB, one "204"
  reply per chunk: 25–100 per 25 MB instead of 1747–2815. This is what resumable
  uploads of large files in browser services look like.
- **Everything is kept:** nginx's TLS and HTTP/2, the cover site, the behaviour
  under active probing.
- **Cost:**
  - a change to the stream protocol: chunk numbers, reassembly on the server,
    handling of loss and retries;
  - headers for every chunk (under 1%);
  - an in-memory body buffer in nginx for every chunk, otherwise nginx writes the
    body to the VPS disk;
  - several chunks must be in flight at once, otherwise the speed drops.
- **Risks to check by measurement:** upload speed (now 9–10 MB/s) and the latency
  of interactive protocols (SSH, messengers) — small chunks cannot wait until they
  fill up.
- **Amount of work:** medium to large: client, server, a new nginx location, tests.

### B. nginx terminates TLS, Chameleon handles HTTP/2

- **Idea.** nginx switches to the `stream` module: it still terminates TLS
  (OpenSSL, the same certificate, the same ServerHello, ALPN through `ssl_alpn`) but
  passes the decrypted stream to Chameleon's own server. That server speaks HTTP/2
  without TLS (h2c, available in `x/net`) and returns the window in batches like a
  browser. This already exists for `direct` mode.
- **What is visible passively:** the same nginx TLS handshake, and replies during
  uploads come in batches, as with browser-facing servers.
- **The cost is active probing.** The cover site would also answer through
  Chameleon's HTTP/2 server: either it serves the site itself (the code has
  `newCoverHandler`) or it forwards requests to nginx inside the VPS. A prober who
  opens TLS and speaks HTTP/2 would see Go's HTTP/2 parameters rather than nginx's
  (SETTINGS, error behaviour). Some of them can be tuned to look like nginx, but
  not all.
- **Amount of work:** medium: nginx `stream` setup, h2c on the server, moving the
  404 interception from nginx into Chameleon, tests.

### C. `direct` mode, already in the code

The Chameleon server itself accepts TLS from its clients by the marker and forwards
everyone else to nginx. **Not recommended:** the same IP would answer its clients
with Go's TLS handshake and everyone else with OpenSSL's. An observer comparing the
server's replies would see two different stacks. That is exactly why nginx was
chosen.

### D. Leave it as it is

The feature appears only during bulk uploads (file uploads, video upstream) and
distinguishes the tunnel from an ordinary nginx site and from Cloudflare. It is
absent during downloads and ordinary browsing.

## Recommendation

1. First, two cheap isolated experiments with the same setup as before, about
   10 minutes:
   - `http2_body_preread_size` — confirm that settings cannot do it;
   - a series of 256 KB and 1 MB POSTs to a buffered location, one at a time and 4
     at once: the number of short replies and the speed.
2. If the experiment shows 0 replies and keeps the speed, option **A** is
   preferable: nginx stays as it is, the face under active probing does not
   change, and the remaining pattern looks like a browser's chunked upload.
3. If A loses speed or latency, option **B** with HTTP/2 parameters tuned to
   nginx's, or **D**.
4. Do not consider option **C**.

## Experiment: a WINDOW_UPDATE threshold patch for nginx 1.28.3

Date: 2026-11-19. Local only (WSL). The VPS, the Pi, the production nginx and
Chameleon were not changed.

**Patch.**

- Ubuntu sources `1.28.3-2ubuntu1.12` with all 22 package patches.
- Only the two credit functions for unbuffered bodies changed:
  `ngx_http_v2_read_client_request_body_handler` and
  `ngx_http_v2_read_unbuffered_request_body`.
- Credit is sent only once at least min(half the buffer, 256 KB) has accumulated.
- All other logic is untouched.
- File: `h2-unbuffered-window-update-threshold.patch`.

**Stand.**

- Two nginx builds without SSL (h2c); the system nginx was not replaced.
- Settings as in the tunnel: `proxy_request_buffering off`, `proxy_buffering off`,
  HTTP/1.1 to the receiver, `client_body_timeout 24h`.
- Network emulator: 15 ms each way (30 ms RTT); upload capped at 20 MB/s or
  uncapped.
- An own HTTP/2 client counts WINDOW_UPDATE frames.
- The receiver measures the delay of every record.
- Every test is 25 MB.

**[Measured] 25 MB upload at 20 MB/s** (average of three):

| Buffer | nginx | MB/s | WINDOW_UPDATE | Record delay p50/p99, ms | Parallel small stream delay p50/p99, ms |
|---|---|---|---|---|---|
| 512 KB (as now) | stock | 15.6 | 1322 | 17.5 / 30.7 | 16.3 / 33.4 |
| 512 KB | patched | **10.2** | 101 | 23.3 / 49 | 17.2 / 28.4 |
| 1 MB | stock | 19.1 | 1417 | 37.7 / 58 | 36.8 / 60.9 |
| 1 MB | patched | 19.1 | **99** | 31.3 / 54 | 29.8 / 58.1 |
| 2 MB | stock | 19.1 | 1276 | 89.9 / 110 | 89.2 / 112.9 |
| 2 MB | patched | 19.1 | **95** | 83.1 / 106 | 82.3 / 109.1 |
| 4 MB | stock | 19.1 | 1207 | 194.7 / 216 | 194.0 / 219.3 |
| 4 MB | patched | 19.1 | **96** | 187.4 / 211 | 187.1 / 215.4 |

**[Measured] Uncapped** (the limit is set by the window and the 30 ms RTT):

| Buffer | Stock, MB/s / WINDOW_UPDATE | Patched |
|---|---|---|
| 512 KB | 15.4 / 383 | 12.1 / 118 |
| 1 MB | 28.3 / 335 | 26.1 / 108 |
| 2 MB | 53.4 / 497 | 50.2 / 84 |
| 4 MB | 54.6 / 407 | 56.0 / 83 |

**[Measured] Stalls and edge cases.** Not a single stall, error or `error.log`
entry in any variant. Checked:

- slow receiver at 3 MB/s: exactly 2.99 MB/s everywhere;
- 400 small records of 112 bytes: 16–18 ms delay with both nginx builds;
- 3.2 MB, then idle, then single small records and a final record with the end of
  the body: 16–17 ms delay, no waiting for credit;
- the window fully exhausted 15 times in a row: credit always arrives, at most
  34 ms later (one RTT); with the patch 12–14 ms on average instead of 1–2 ms;
- the last 1 byte with the end of the body after a 1 s pause, and a separate empty
  end of body after a pause: the body arrives complete.

**Conclusions.**

1. The patch cuts WINDOW_UPDATE frames 13–14 times (about 100 per 25 MB instead of
   1200–1400). The average credit is 256–300 KB instead of 19–25 KB.
2. With the current 512 KB buffer the patch loses a third of the speed: too little
   credit stays in flight. With the patch the buffer has to grow.
3. With a 1–4 MB buffer there is no speed loss at 20 MB/s. Uncapped, the spread is
   −8%…+3%: noise and the same window limit.
4. The cost comes from the larger buffer, not the patch. When the line is
   saturated, the window fills the queue in front of the bottleneck, and the delay
   of small data on a parallel stream grows:
   - about 30 ms with 1 MB;
   - about 85 ms with 2 MB;
   - about 190 ms with 4 MB;
   - versus 16–33 ms now.

   [Inference] On the live path the queue will sit in the Pi's socket buffer or at
   the ISP; the picture should be similar, but it was not measured.
5. [Inference from code] The buffer is allocated for every long request, that is,
   for every device TCP stream, in full in virtual memory. Only the part actually
   filled becomes resident.
6. The best trade-off is the patch with a 1 MB buffer: no speed loss at 20 MB/s,
   about 100 credits per 25 MB, about 30 ms delay on a parallel stream.

### Repeat with TLS and the real Chameleon client stack

**Conditions.**

- nginx built with TLS: OpenSSL 3.5.5, the system `libssl.so.3`, TLS 1.3, h2. The
  location settings are the same.
- The client is the real carrier stack: `CreateTLSTransport`, the REALITY path, the
  uTLS Chrome profile, the HTTP/2 transport with Chromium settings, record shaping.
- The request body is streamed, as in a TCP stream.
- The same network emulator: 30 ms RTT.
- WINDOW_UPDATE frames are counted outside TLS: a lone frame is a 30-byte record.
- Test `TestNginxWindowBench` in `clientcore`, run by
  `tools/nginx-h2-window/run_tls.sh`.

**[Measured] 25 MB upload at 20 MB/s** (three runs):

| Configuration | MB/s | WINDOW_UPDATE (30-byte records) | Parallel small stream p50/p99, ms |
|---|---|---|---|
| Stock nginx, 512 KB (as now) | 15.2 | 1245–1264 | 16.8 / 34.0 |
| Stock nginx, 1 MB | 19.0 | 1136–1154 | 36.3 / 64.2 |
| **Patched, 1 MB** | **19.0** | **95–96** | 30.3 / 59.1 |

Other TLS measurements:

- Uncapped:
  - 512 KB stock — 15.0 MB/s and 165 credits;
  - 1 MB stock — 29.0 MB/s and 149;
  - 1 MB patched — 27.1 MB/s and 56.
- Slow receiver at 3 MB/s: 2.99 MB/s everywhere. Credits: 169, 128 and 39
  respectively.
- 400 small records: 16–18 ms delay everywhere. 401 credits with stock nginx and 1
  with the patch.
- Idle periods with single records, a last byte after a pause, an empty end of body
  after a pause: everything arrives. Not a single stall or error in the nginx log.
- During uploads almost all downstream records are lone WINDOW_UPDATE frames; nginx
  sends no other short replies.

**[Measured] Conclusions of the TLS repeat.**

1. The h2c results are confirmed on the real stack: at 20 MB/s about 96 credits per
   25 MB instead of ~1250, 92% fewer.
2. Compared with the current configuration (512 KB), the patch with 1 MB is **25%
   faster**: 15.2 → 19.0 MB/s at 30 ms RTT. 512 KB is window-limited here.
3. The cost is the delay of a small parallel stream during bulk uploads: p99 34 →
   59 ms, p50 17 → 30 ms. It comes from the 1 MB buffer, not the patch: stock nginx
   with 1 MB is worse (64 ms). Without a bulk upload the delay does not change
   (16–18 ms).

Limits: emulation on a single machine. On the live path stock nginx produced more
credits (1747–2815), because data arrives in smaller portions. How that affects the
patch can only be checked on the live path.
