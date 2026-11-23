# Chameleon TCP streams vs packet tunnel

Date: 2026-11-17. Experimental branch `exp/chameleon-tcp-streams`: device TCP
is terminated on the Pi (TPROXY in the `easypi-chtcp` namespace) and carried
as one HTTP/2 stream per connection; the VPS dials the site. UDP stays on
the packet tunnel. Measured from the Pi with
`scripts/dev/chameleon_transport_baseline.sh`, which now also runs the same
workload through the stream path (`streams`), then through the packet tunnel
(`cham0`) and directly (`eth0`), one after the other. Full data:
`CHAMELEON_TCP_STREAMS_COMPARISON.json`. The reference run of the packet
tunnel alone is `CHAMELEON_TRANSPORT_BASELINE.md`.

Limits of this run: one location, one time of day, three runs per transfer
test, two runs of the parallel test. The covered computer stayed on the
EasyPi network with Stealth on (it was not loaded on purpose, but its
background traffic shared the carrier). The packet tunnel measured slower
here than in the reference run (Cloudflare 8.4 vs 13.7 MB/s, Hetzner 1.1 vs
5.3 MB/s); the cause was not isolated, so the reference figures are given
too.

## Throughput (MB/s, median of runs, min-max in brackets)

| Test | Streams | Packet tunnel (this run) | Packet tunnel (reference) | Direct |
|---|---|---|---|---|
| Download 50 MB, Cloudflare | 19.52 (8.10-19.76) | 8.37 (5.80-10.05) | 13.65 | 19.96 |
| Download 50 MB, Hetzner FSN1 | 14.46 (10.54-19.43) | 1.06 (0.85-1.56) | 5.28 | 19.73 |
| 4 parallel downloads, Cloudflare | 19.94 (19.44-20.44) | 8.83 (8.37-9.28) | 14.11 | 19.93 |
| Upload 25 MB, Cloudflare | 1.03 (0.97-1.05) | 0.79 (0.76-0.80) | 1.45 | 9.77 |

## Sites (6 sites x 3 runs, median ms)

| Path | First byte | Total |
|---|---|---|
| Streams | 182 | 302 |
| Packet tunnel | 207 | 663 |
| Direct | 96 | 190 |

With streams the TCP handshake completes on the Pi, so curl's connect time
(2 ms) is not comparable; first byte and total include the server's dial.

## Client CPU (share of one Pi core, median)

| Test | Streams | Packet tunnel |
|---|---|---|
| Download, Cloudflare | 27% | 34% |
| 4 parallel downloads | 29% | 36% |

## Carrier

During downloads the stream path sends almost nothing upstream (83 KB/min
against 7.2 MB/min for the packet tunnel, which carries the device's TCP
ACKs), as a browser downloading over HTTP/2 does. Everything stayed on one
TLS connection to the VPS.

## Conclusions

- Downloads through streams reach the line rate (about 20 MB/s) on
  Cloudflare and in parallel; Hetzner reaches 14.5 MB/s against 1-5 MB/s
  through the packet tunnel.
- Page loads take about half the packet tunnel's time; first byte is still
  about 90 ms above direct (one extra round trip to the VPS for the dial).
- Upload was unchanged at about 1 MB/s on both paths in this run; see the
  follow-up below.

## Upload follow-up

During a stream upload the Pi-to-VPS TCP connection was mostly
`app_limited` with a 1 MB send window and about 35 KB per round trip (RTT
25-35 ms): the limit sat above TCP, in HTTP/2 flow control. The VPS itself
uploaded to Cloudflare at 44-52 MB/s. One variable was then changed, nginx
`client_body_buffer_size` in the tunnel location (nginx returns flow-control
credit for an unbuffered body only as this buffer drains). Fresh client
connection each time, one stream, 25 MB to Cloudflare, Stealth off:

| Buffer | Upload MB/s (two runs) |
|---|---|
| 16 KiB (default) | 0.99, 1.69 |
| 256 KiB | 5.99, 5.19 |
| 512 KiB | 8.91, 5.11 |
| 1 MiB | 7.21, 8.22 |
| Direct, for reference | 9.77 |

nginx memory with 30 idle open streams was the same at 16 KiB and 1 MiB
(about 19.5 MB in total), so the buffer is taken only while a request is
sending. 512 KiB is now in the generated nginx configuration and live on the
VPS. The packet tunnel's uplink is a request body too and should gain as
well; that was not measured.

## Robustness checks (Stealth on, computer on the network)

- Server restart on the VPS: new streams failed for about 5 s, then the
  client renegotiated by itself. Open streams end with the session.
- Pi-to-VPS link cut for 20 s: new streams worked again within a second of
  the link returning.
- No leak: during both, the computer's direct-to-internet counter (Stealth
  kill switch) stayed at 0 packets.
- Device binding: only the Stealth-selected computer's TCP entered the
  stream path.
- IPv6: unchanged; the computer's IPv6 is dropped by the Stealth kill switch
  and the stream path is IPv4 only.
- Prism: the device's TLS ClientHello still passes FORWARD in plaintext with
  the site's address before the stream divert (a temporary counter matched
  76 ClientHellos, and the string "yandex" 4 times, while the computer
  browsed). Prism's Yandex rules themselves matched nothing, with or without
  streams: they require a TLS record length of 0x02xx (512-767 bytes),
  and the browser's ClientHellos are about 1.5 KB. That is a separate Prism
  coverage gap.

Not covered yet: IPv6 TCP streams; long streams across a transport epoch
change (they are closed).
