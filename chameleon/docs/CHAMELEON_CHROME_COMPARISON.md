# Chameleon and real Chrome: paired comparison

Date: 2026-11-19. Chameleon build under test (TCP streams, TLS-in-TLS
protection, epoch fixes) on the Pi and the VPS.

## Method

- The same scenario in real **Chrome 158.0.8127.36** on the user's computer, with a
  separate temporary profile, QUIC off and Chrome's background network features
  off. A page ran the scenario automatically:
  1. page load;
  2. 3 minutes idle;
  3. 50 MB download;
  4. 25 MB upload;
  5. 3 minutes idle.

  Site: `speed.cloudflare.com` — the page, the download and the upload all on one
  address.
- **Run A:** Stealth off, Chrome connects to the site directly.
- **Run B:** Stealth on, the same Chrome through Chameleon. The Chameleon client
  was restarted at the start of the capture so that its first TLS message was
  recorded.
- Both captures were taken at the same point, on the Pi at the internet egress
  (`tcpdump`). They were parsed by the same analyzer
  (`scripts/dev/chameleon_shape_analyze.py`) and the same per-phase script. The
  captures were deleted afterwards; only the analyzer reports were kept.

Limits:

- one site, one session, one time;
- the reference is Chrome with a Cloudflare site, not with an nginx site;
- in run B the computer's background traffic (Windows) also went through
  Chameleon, so idle in B is not Chameleon's own idle;
- the page-load phase was not compared: in A it missed the capture (Chrome then
  reached the site at another address, probably IPv6), and in B it contained the
  new Chrome profile's first downloads (37 MB to Google servers);
- in B the analyzer did not parse all downstream TLS records, so the downstream
  record count in B is incomplete, while packets and bytes are complete.

## Results

### First TLS message (ClientHello)

| Field | Chrome 158 (A) | Chameleon (B) |
|---|---|---|
| Cipher suites | GREASE + 15 | the same, in the same order |
| Extensions | 17 + 2 GREASE | **the same set**, shuffled order as in Chrome |
| Signature algorithms | GREASE + 11 | the same |
| Key groups | GREASE, X25519MLKEM768, X25519, P-256, P-384 | the same |
| ALPN | h2, http/1.1 | the same |
| JA4 (a_b part) | `t13d1517h2_8daaf6152771` | `t13d1517h2_8daaf6152771` |

The third part of JA4 differs because the analyzer counts the random GREASE value
in the signature algorithms, which changes from connection to connection in Chrome
itself. **Conclusion: Chameleon's first TLS message matches Chrome 158**, although
the profile was built for 157.

### Connections and volume

|  | Chrome (A) | Chameleon (B) |
|---|---|---|
| Main connections | 1 (75 MB) | 1 (121 MB, including background) |
| Download, KB/min down | 44,459 | 44,815 |
| Upload, KB/min up | 20,827 | 20,865 |

The speed is the same, and so is the "one long connection" pattern.

### Differences visible to an observer

1. **Idle.**
   - Chrome: TCP keepalive exactly every 45 seconds (1 byte up and an
     acknowledgement), 2.8 packets per minute. A direct observation.
   - Chameleon: in an earlier measurement without background traffic, 8 packets
     per minute. That matches Go's keepalive every 15 seconds
     (`clientcore/fingerprint.go`, `dialUTLS` → `net.DialTimeout`).
   - The difference is confirmed from both sides.
2. **Upload, upstream record sizes.**
   - Chrome: almost all records are full-size, 16,401 bytes (1485 of 1487).
   - Chameleon: in this capture the analyzer parsed only some of the records
     (4108 per 25 MB), so the sizes of 986–2906 bytes seen here are unreliable.
   - An exact local measurement of the same client stack: in an 8 MB upload not a
     single full-size record; the records are random, 3 to 14 KB. This is
     Chameleon's own record-size masking (`shared/record_shaping_conn.go`), which
     splits large records.
   - The difference is confirmed. During bulk uploads it makes Chameleon *less*
     like Chrome.
3. **Upload, server replies.**
   - Cloudflare sent one record downstream during the 25 MB upload.
   - Chameleon's nginx sent 2815 records, 93% of them 30 bytes (HTTP/2
     flow-control credit, roughly every 10 KB).
   - This is nginx's behaviour. Whether an ordinary nginx site behaves
     differently was not checked.
4. **Download, reverse channel.**
   - Chrome sent 4 records upstream during the 50 MB download.
   - Chameleon had small records upstream (84–91 and 30 bytes) and small records
     downstream of 19–27 bytes.
   - Part of this is the computer's background traffic, which this experiment
     cannot separate. An earlier measurement without background showed about 43
     records a second with server replies.
5. **Idle with background traffic.** About 400 packets per minute went through
   Chameleon while idle. This is real Windows background traffic that any user
   has, but through Chameleon it shows up as activity on one connection to one
   site.

### What matches

- the first TLS message;
- one long HTTP/2 connection;
- speed and volume per phase;
- during the download most downstream records are full-size (16,401) for both
  Chrome and Chameleon.

## Experiment: short nginx replies during uploads

Question: are 2815 short replies per 25 MB normal nginx behaviour or a feature of
the tunnel?

Conditions:

- a separate temporary nginx 1.28 instance on the VPS, only on `127.0.0.1`; the
  production nginx was not touched;
- a simple upload receiver behind it;
- the client is `curl --http2`, 25 MB upload;
- capture on the internal interface;
- everything removed afterwards.

| Setting | Short replies (30 bytes, WINDOW_UPDATE) | Speed |
|---|---|---|
| As in the tunnel: `proxy_request_buffering off`, 512 KB buffer, known length | 307 | 134–227 MB/s |
| As in the tunnel, streamed body | 544 | 175 MB/s |
| Ordinary site, default settings, known length | **0** | 234 MB/s |
| Ordinary site, streamed body | **0** | 147 MB/s |

**[Measured] Conclusion:**

- Frequent flow-control credit is a feature of the tunnel's setup (an unbuffered
  request body), not of nginx in general. An ordinary nginx site, like Cloudflare,
  sends almost nothing during an upload.
- Over the network there are more replies than on the internal address (2815
  versus 300–550), because data arrives in smaller portions.
- The unbuffered body cannot be dropped: the tunnel and the streams send data
  continuously, and with buffering nginx would wait for the end of the body.
- The difference remains.

**[Measured] A larger buffer does not help.** The same isolated setup, streamed
body:

| Body buffer | No rate limit | At 20 MB/s |
|---|---|---|
| 512 KB | 497 | 542 |
| 2 MB | 459 | 553 |
| 8 MB | 56 | 521 |

At speeds close to the live ones, nginx replies roughly every 46 KB whatever the
buffer setting: the reply is tied to every portion forwarded. nginx settings
cannot fix this. What remains is an architectural change — handing HTTP/2 to
Chameleon's own server, which returns the window in batches like a browser. This
needs a separate discussion.

## After the fixes (updated client on the Pi)

**[Observed] Keepalive.** The keepalive timer of the live carrier socket counts
down 28, 27, 26… seconds; with 15 seconds it could never exceed 15. The kernel on
the test Linux shows 45 s idle and a 45 s interval.

**[Measured] Records during a live 10 MB upload.**

- 31% of the client's large records are full-size. The rest are 986, 14,520 and
  15,480 bytes, in steps of 960 bytes.
- This is not the client's masking: with a server that gives a large window, the
  client sends 97% full-size records (local test
  `TestBulkUploadUsesFullSizeRecordsLikeChrome`).
- On the live path nginx limits the upload: it grants credit in small portions
  (difference 3 above), and the client sends exactly what was granted.
- As long as the frontend is nginx with an unbuffered body, upload records will
  partly be smaller than Chrome's.

**[Measured] Speed through streams after installation:**

- download: 18.0 and 20.1 MB/s;
- 25 MB upload: 6.3, 8.4, 9.6 and 9.2 MB/s — within the earlier spread of 8.8–9.7;
  6.3 is a one-off dip.

## Repeat run through Chameleon after the fixes

The same scenario, the same Chrome 158, Stealth on, updated client. The direct
Chrome reference (run A) was not changed or re-measured.

The computer's background traffic was much heavier this time: about 14 MB of other
uploads went over the carrier during the first idle phase. So idle is not compared
here, and keepalive was checked separately from the live socket timer (see above).

| Phase | Chrome direct (A) | Chameleon before (B) | Chameleon after (B2) |
|---|---|---|---|
| Download, KB/min down | 44,459 | 44,815 | 45,564 |
| Upload, KB/min up | 20,827 | 20,865 | 20,854 |
| Upload: full-size client records among large ones | 1485 of 1487 | 16401 not among frequent sizes | 440 of 1773 (25%) |
| Upload: most frequent client records | 16401 | 986, 1946, 2906 | 986, 15480, 16401 |
| Upload: short server replies (30 bytes) | 0 | ~2600 | 1747 |
| Download: client records upstream | 4 | 113 | 152 (partly background) |

**[Measured] Conclusion of the repeat:**

- The speed is still the same as Chrome's.
- Full-size records now appear during uploads: a quarter of the large ones. The
  size of the rest is set by nginx's credit portions (986 bytes = 960 bytes of data
  + headers), which confirms the isolated nginx experiment.
- Short nginx replies during uploads remain: difference 3, which nginx settings
  cannot fix.
- Upstream records during downloads cannot be separated from background traffic in
  this kind of experiment. A run on a completely quiet computer is needed.

## Conclusion

By the first message and the overall connection picture Chameleon is
indistinguishable from Chrome. Inside the connection there are differences, and
three of them are confirmed by measurement:

- keepalive 15 s versus 45 s;
- small records during uploads;
- frequent server control replies during uploads.

Indistinguishability from Chrome is not confirmed.

Fix candidates, by value for effort (not implemented yet, need agreement):

1. Client TCP keepalive of 45 seconds, as in Chrome. One setting, a direct mismatch
   with the measurement.
2. Do not split records during bulk uploads; Chrome sends full 16 KB there.
3. Deal with the frequent nginx replies during uploads without losing speed. First
   compare with an ordinary nginx site.
4. Measure the reverse channel during downloads separately, without background
   traffic.
