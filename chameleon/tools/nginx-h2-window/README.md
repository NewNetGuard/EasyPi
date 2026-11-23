# nginx: fewer HTTP/2 WINDOW_UPDATE frames for unbuffered request bodies

Benches for the patch EasyPi deploys to the VPS. Results and conclusions:
`docs/CHAMELEON_H2_FLOW_CONTROL_OPTIONS.md`, section about the WINDOW_UPDATE
threshold patch.

## Patch

- `chameleon/server/nginx/h2-unbuffered-window-update-threshold.patch` (the
  copy EasyPi deploys; `easypi-chameleon-nginx` next to it builds and keeps it
  on the VPS), against nginx 1.28.3 as
  shipped by Ubuntu `1.28.3-2ubuntu1.12` (orig tarball plus all 22 package
  patches). Applies with `patch -p1` in the source root.
- It changes only `ngx_http_v2_read_client_request_body_handler` and
  `ngx_http_v2_read_unbuffered_request_body`. Credit is returned only when at
  least min(buffer/2, 256 KB) can be returned at once.
- Buffered bodies, the connection window and all other paths are unchanged.
- Recommended pairing, from the bench: `client_body_buffer_size 1m`. With 512k
  the patch loses about a third of upload speed.

## Bench (local, WSL; no root needed)

- `build.py <src>`: configure plus compile without make; h2c only. It does not
  install anything.
- `sink.py`: HTTP/1.1 upstream. It reads a record stream, can read slowly, and
  reports the bytes and per-record delay.
- `wan.py`: delay and rate-cap proxy.
- `bench.py <bufs> <out.json>`: stock and patched nginx side by side. A
  hand-written HTTP/2 client counts WINDOW_UPDATE frames and runs these
  scenarios:
  - bulk capped / free;
  - slow receiver;
  - parallel small stream;
  - trickle;
  - pauses;
  - credit exhaustion;
  - last-portion.
- `summary.py <out.json>`: a compact table.
- `results/`: raw output of the h2c and TLS runs (2026-11-19).

## Production build

- **On the VPS**, `chameleon/server/nginx/easypi-chameleon-nginx` builds the
  patch. "Deploy & Start" runs it, and an apt hook runs it after every nginx
  package update. It builds from the installed package's own source, so
  Ubuntu's fixes stay in.
- **Locally**, `build_ubuntu.sh` builds the same binary for testing. It uses
  the Ubuntu `1.28.3-2ubuntu1.12` package's configure arguments and hardening
  flags and builds both a stock and a patched binary.
  - Headers come from `libssl-dev`, `libpcre2-dev`, `zlib1g-dev` and
    `libcrypt-dev`, unpacked with `dpkg -x`; nothing is installed.
  - The binaries link the same libraries as the packaged one.
  - The package's dynamic modules are separate packages and are not built.

## Memory bench

- `run_mem.sh` with `TestNginxMemoryBench` measures nginx RSS, peak and
  virtual memory with 1–128 concurrent carrier-like streams.
- Modes: idle, active and stalled.

## TLS bench (real carrier stack)

- `build_tls.sh`: stock and patched nginx with `--with-http_ssl_module`.
  - Linked to the system `libssl.so.3`.
  - Headers come from `libssl-dev`, unpacked with `dpkg -x` into
    `~/ngx/ssl-dev`; nothing is installed.
- `run_tls.sh <test-binary> <out-dir> stock:512k patched:1m ...`: runs
  `TestNginxWindowBench` (`chameleon/clientcore/nginx_window_bench_test.go`)
  against each config.
  - Build the binary with `GOOS=linux go test -c ./clientcore`.
  - The test skips unless `NGINX_BENCH_ADDR` is set.
- `summary_tls.py <json>...`: a compact table.
