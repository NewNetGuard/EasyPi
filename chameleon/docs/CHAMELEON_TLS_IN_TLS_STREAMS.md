# Chameleon: protection against TLS-in-TLS detection on TCP streams

Date: 2026-11-19. All changes and measurements were made locally; nothing was
installed on the Pi or the VPS, and nothing was committed.

Labels: **[Code]**, **[Test]**, **[Measured]** — confirmed; **[Hypothesis]** — not
checked by a direct experiment.

## 1. The earlier protection (packet transport)

- Every IP packet of the device is padded to a size step (128, 256, 512, 768,
  1024, 1280, 1456, 1600 bytes) with a random shift of one or two steps —
  **[Code]** `clientcore/padding.go`, `padPacketBinary`, `adaptivePaddingTarget`;
  the same on the server in `server/padding.go`.
- A packet whose payload *starts* with a TLS handshake header (0x16 0x03
  0x01–0x04) is additionally padded to a random 1200–3000 bytes — **[Code]**
  `shared/inner_handshake.go`, `IsInnerTLSHandshake`, `InnerHandshakePaddingTarget`.
- Packets leave in batches inside shared records, which mixes sizes further.

Limits of the old protection (**[Code]**): only the first segment of the
ClientHello and the first segment of the ServerHello get the special padding. In
TLS 1.3 the certificates and Finished are encrypted and use record type 0x17; only
the general step padding hides them.

## 2. Why the stream transport had no protection

On the stream path the device's TCP ends on the Pi, and HTTP/2 carries application
bytes rather than IP packets (`cmd/chameleon-client/tcp_relay.go` →
`clientcore/tcp_stream.go` → `server/tcp_stream.go`). The old mechanism recognises
TLS by the IP packet header, and there are no packets here. A stream frame
(`shared.WriteTCPStreamFrame`) encrypts exactly the bytes it is given, without
padding. The protection was not carried over when streams were introduced —
**[Code]**.

## 3. What is visible from outside: measurement

Stand `clientcore/tlsintls_measure_test.go` (run with
`CHAMELEON_MEASURE=1 go test ./clientcore -run Measure -v`):

- the device is a real client with a Chrome 157 ClientHello (the same profile as
  Chameleon's);
- the site is TLS 1.3 with a chain like a public site's (ECDSA leaf, RSA-2048
  intermediate);
- the path is the same relay as in the client, a real `TCPStream` and HTTP/2;
- the stream server is a copy of the data path of `server/tcp_stream.go` with the
  same shared frame functions;
- the outer TLS records on the client-server connection are recorded: size,
  direction, time.

Stand limit: there is no nginx in it, so record boundaries toward the client are
the backend's, not nginx's.

**[Measured] Before the change:**

- In 60 of 60 trials the outer record size equals the inner message size plus
  exactly 59 bytes, in both directions, correlation 1.0000.
- On a real Chrome handshake every message is visible:

  | Message | Inside, bytes | Outside, bytes |
  |---|---|---|
  | ClientHello | 1984 | 2043 |
  | Server reply | 3321 | 3380 |
  | Client Finished | 64 | 123 |
  | GET request | 137 | 196 |
  | Response | 1208 + 2345 | 1267 + 2404 |

- With ordinary TLS 1.3 cipher suites the client Finished is **always exactly 123
  bytes**, right after a large server record (30 of 30 runs, 1 value).
- Chameleon's own feature: every stream opening produced two records of constant
  size, 47 and 66 bytes (the nonce and the destination frame).

## 4. What is proposed for the stream transport

### 4.1 Early data (client only, no server change needed)

- The relay waits up to 20 ms for the device's first data. The ClientHello arrives
  right after the local connection. The data leaves together with the stream
  request: the nonce, the destination frame and the first data in one record
  (`readEarlyData`, `OpenTCPStream(..., early)`).
- Server-first protocols (SMTP and similar) send nothing: the stream opens after
  20 ms without early data.
- From outside, instead of "open → reply → ClientHello → …" there is one request
  record and a reply, like an ordinary HTTPS request.
- **[Measured]** One round trip to the VPS is saved: opening a page through one
  stream with 25 ms one-way delay takes 214 ms instead of 262 ms (median of 10).

### 4.2 Padding the start of a stream (client and server, negotiated)

- New frame layout: `[2-byte data length][data][padding]`, inside the same
  encryption. Ciphers, keys, login and sessions did not change.
- It is enabled only if the server advertises it with a separate header
  `X-Chameleon-Tcp-Shape: 1`. The stream version header `X-Chameleon-Tcp: 1` does
  not change: old clients work with the new server, and a new client works with an
  old server in the old layout but with early data.
- The padding rule was chosen from a model of "how much size information remains
  versus what it costs in bytes" (the model is a `go run`, see section 6):

  | Frame | Rule |
  |---|---|
  | First 4 frames in each direction, if the frame is ≤ 512 bytes (destination, Finished, short requests) | random size up to 576 bytes |
  | First frame > 512 bytes upstream (ClientHello) | random size up to 4096 bytes |
  | First frame > 512 bytes downstream (the server's handshake reply) | random size up to 8192 bytes |
  | Everything else, including all bulk transfer | no padding |

- The size is chosen uniformly between the frame's own size and the cap, so one
  observed record corresponds to a wide range of inner sizes. No narrow constant
  band appears.

Rejected options (**[Measured]** with the model on 20,000 sizes):

| Rule | Correlation up | Cost up | Correlation down | Cost down | Why rejected |
|---|---|---|---|---|---|
| Pad to twice the own size | 0.92 | 744 B | 0.91 | 2168 B | hides almost nothing |
| The old 1200–3000 rule | 0.51 | 851 B | 0.99 | 178 B | a narrow 1.2–3 KB band on every first message; Finished grows into 1.2–3 KB of upload, which browsers never do |
| Chosen rule | 0.64 | 1094 B | 0.62 | 1945 B | — |

## 5. Result: before and after

**[Measured]** 30 real Chrome handshakes per mode and 60 trials with random sizes:

| Mode | ClientHello outside | Server reply | Finished | Bytes per connection (up / down) | Size correlation (up / down) |
|---|---|---|---|---|---|
| Current | 1979–2075 (4 values) | 3379–3381 (3) | 123 (1) | 2565 / 7212 | 1.00 / 1.00 |
| Early data | 2030–2126 (4) | 3378–3381 (4) | 123 (1) | 2523 / 7203 | 1.00 / 1.00 |
| Padding | 2012–4101 (30) | 3715–8147 (30) | 133–626 (29) | 4302 / 10281 | 0.49 / 0.43 |
| Early data + padding | 2375–4372 (30) | 3503–8095 (30) | 193–632 (29) | 4543 / 9784 | 0.66 / 0.60 |

The correlation varies between 0.43 and 0.68 from run to run: the padding is
random and there are 60 trials.

Removed:

- the exact size leak (the constant +59 bytes);
- the constant size of the Finished record (123 bytes);
- the constant 47- and 66-byte records at every stream opening;
- the extra "open — ClientHello" round trip.

What remains (honestly):

- **Approximate size.** Correlation 0.4–0.7: a large message on average stays
  larger than a small one. Breaking the link completely would take padding of
  several kilobytes per message, which is visible by volume.
- **Exchange structure.** Request → large reply → small request → reply. That is
  the pattern of any HTTPS request, but also of nested TLS. Only mixing with other
  streams on the same connection (all of Chameleon's streams and the packet path
  share one HTTP/2 connection) and timing hide it.
- **Constant control records.**
  - The request header of every new stream — about 53 bytes.
  - The "200" response header — 33 bytes on the stand; different through nginx.
  - A record of about 48 bytes when a stream closes (client stream reset).
  - **[Hypothesis]** These are weak features: browsers have such records too, but
    Chameleon's are identical from stream to stream.
- **Uploads became more visible.** Each new connection adds about 1.9 KB of
  padding upstream, while Chrome's uploads are usually small. On a page with 60
  connections that is about 110 KB extra upstream and about 170 KB downstream.
- **Not checked:**
  - comparison with real Chrome traffic;
  - operation through a real nginx: it sets the record boundaries toward the
    client;
  - the effect of the client's record-size shaping (`RecordShapingConn` splits
    records over 3 KB; it is not on the stand).

**Not claimed:** matching Chrome's TLS fingerprint and this padding do not make
Chameleon indistinguishable from Chrome. A full comparison is the next step.

## 6. Tests and performance

New tests (**[Test]**, all pass; the race detector on Linux is clean, 5 repeats):

- `shared/tcp_stream_test.go`:
  - padded frames survive intact at every size from 0 to the maximum;
  - a corrupted length is rejected;
  - the old layout is byte-for-byte unchanged and readable by the old code;
  - padding applies only to the start of a stream and stays within the limits;
  - across 2000 streams no outer size appears more than 2% of the time: there is
    no repeating value.
- `server/tcp_stream_test.go`:
  - a stream with padding and early data: the site gets all bytes in order, the
    half-close arrives, the reply is intact;
  - the internal-address ban applies to the new layout too.
- `server/frontend_capabilities_test.go`: the server advertises the new layout next
  to version "1", not instead of it.
- `clientcore/tcp_stream_test.go`:
  - early data arrives first and in order, in both layouts;
  - the new layout is requested only if the server advertised it.
- `cmd/chameleon-client/tcp_relay_test.go`:
  - the ClientHello leaves with the stream request;
  - a server-first protocol opens after 20 ms and receives the server's greeting.
- All earlier Chameleon tests pass. The packet transport did not change.

Speed (**[Measured]**, in-memory bulk transfer, limited by this computer's CPU,
not the network):

| | Without padding | With padding |
|---|---|---|
| First version | 62–66 MB/s | 37–38 MB/s |
| After the fix | 61–69 MB/s | 57–61 MB/s |

Why the first version was slow: a frame with the prefix ended up 2 bytes smaller
than a full one, so every 32 KB relay write produced an extra tiny frame, plus a
memory allocation per frame. Fixed: full-size frames (the prefix fits in the slack
readers already allow) and one buffer per stream. The remaining 5–8% is one
in-memory copy per frame. It should not affect a ~20 MB/s line, but it was not
measured on the Pi.

## 7. Changed files

- `shared/tcp_stream.go` — `TCPStreamFramer`, the padding rule, the negotiation
  header.
- `server/tcp_stream.go` — layout chosen by the request header.
- `server/http_handlers.go` — the capability advertised on sync.
- `clientcore/transport.go` — accepting the advertisement.
- `clientcore/tcp_stream.go` — early data, opening in one record, layout.
- `cmd/chameleon-client/tcp_relay.go` — waiting for the first data (20 ms).
- The tests and the measurement stand listed above.

Installation takes two steps: first the server on the VPS (it is compatible with
old clients), then the client on the Pi. Early data works even without a server
update.
