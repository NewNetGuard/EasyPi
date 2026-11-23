# Chameleon load test: how many devices a 1 vCPU, 1/2 GB VPS can serve

Date: 2026-11-19. Isolated WSL stand only. The production Pi, VPS and Chameleon
were not touched; nothing was installed or committed.

## Stand

- **A device** is a separate Chameleon session: its own credential, its own carrier
  connection and its own encryption keys. It is built from the real client stack,
  like a phone: `buildMobileConnection` → `Connect` → `Start`, then
  `OpenTCPStream`.
- **TCP streams** are not devices. Every device has several of them.
- **Server** — the real `chameleon-server` in nginx mode, configured from the
  deployment template (`tls.py`).
- **nginx** — 1.28.3 with the WINDOW_UPDATE patch and a 1 MB buffer:
  - the main config is Ubuntu's default: `worker_connections 768`, 1 worker (as
    `auto` gives on 1 vCPU);
  - the server block is the deployment template.
- **Network** — separate network namespaces:
  - devices ↔ VPS: 15 ms each way, 30 ms RTT;
  - VPS ↔ "the internet" (an own origin server): 5 ms each way.
- **Resources** — nginx and the server in one cgroup:
  - 1 core (pinned to CPU 0 with a 100% quota);
  - memory: the VPS RAM minus 200 MB for the system, no swap;
  - the server with its own systemd unit limits: MemoryHigh 60%, MemoryMax 75% of
    RAM, TasksMax 512.
- **Load** — the generator and the origin run on other cores.
- **A step** is 20 s of ramp-up and 120 s of measurement, then fresh nginx and
  server processes.

Device profile:

| | Idle | Active |
|---|---|---|
| Long-lived connections (messengers, push) | 2 streams, a message every 30 s | 2 streams, a message every 5 s |
| Opening websites | — | on average every 10 s: 6 parallel streams of 20–300 KB |
| Background sync | every ~60 s: 20 KB | — |
| Download | — | on average every 60 s: 5 MB |
| Upload | — | on average every 120 s: 2 MB |

On average that is about 1.7 Mbit/s downstream per active device.

## Results

Notation: CPU is the share of one core. Memory is the cgroup peak (nginx and server
together) and the peak resident memory of the processes. "Echo" is the response
time to a short message; its minimum equals the path RTT (~41 ms).

**[Measured] Configuration as currently deployed on the VPS**
(`max_sessions_per_source 8`): 2 of 10 devices got no stream at all. The server
logged "per-source session limit reached" 7 times.

**[Measured] Server limits lifted, nginx as on the VPS** (`worker_connections 768`):

| RAM | Mode | Devices | CPU avg / 5 s peak | Memory peak, MB | RSS server / nginx, MB | Traffic down/up, Mbit/s | Echo p50/p95/p99, ms | Site p50/p95, ms | Download MB/s p50/min | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 GB | idle | 10 | 0.2% / 0.4% | 39 | 27 / 13 | — | 41/42/42 | — | — | 0 |
| 1 GB | idle | 50 | 0.6% / 0.9% | 70 | 67 / 18 | — | 41/41/42 | — | — | 0 |
| 1 GB | idle | 100 | 1.0% / 1.5% | 120 | 106 / 25 | — | 41/41/42 | — | — | 0 |
| 1 GB | idle | **200** | 1.2% / 1.9% | 139 | 115 / 32 | — | — | — | — | **90%** |
| 1 GB | active | 10 | 2.7% / 4.8% | 41 | 35 / 17 | 17.5 / 2.7 | 41/42/106 | 235/238 | 16 / 13 | 0 |
| 1 GB | active | 25 | 5.5% / 8.5% | 72 | 57 / 20 | 39 / 5 | 41/42/88 | 235/237 | 16 / 16 | 0 |
| 1 GB | active | 50 | 11.2% / 15.7% | 119 | 95 / 30 | 83 / 10 | 41/43/120 | 234/237 | 16 / 13 | 0 |
| 1 GB | active | 100 | 21.2% / 35.4% | 219 | 178 / 39 | 158 / 22 | 41/46/115 | 234/251 | 16 / 11 | 0 |
| 1 GB | active | **200** | — | 127 | 98 / 33 | — | — | — | — | **84%** |
| 2 GB | idle | 10 / 25 / 50 / 100 | 0.2–1.0% | 24–126 | 28–112 / 13–25 | — | 41/42/42 | — | — | 0 |
| 2 GB | idle | **200** | 1.1% | 144 | 120 / 32 | — | — | — | — | **90%** |
| 2 GB | active | 10 / 25 / 50 | 2.6–11.5% | 40–118 | 34–95 / 16–28 | up to 84 / 11 | 41/42–43/90–111 | 234–236/238 | 16 / 11–14 | 0 |
| 2 GB | active | 100 | 19.9% / 29.6% | 219 | 175 / 39 | 161 / 22 | 41/44/109 | 234/238 | 16 / 11 | 0 |
| 2 GB | active | **200** | — | 131 | 101 / 33 | — | — | — | — | **84%** |

At 200 devices nginx answered 500. Its log had 7–25 thousand "768
worker_connections are not enough" entries. The series was stopped as overloaded.

**[Measured] The same 200 devices with `worker_connections 4096`** (everything else
the same):

| RAM | Mode | CPU avg / 5 s peak | Memory peak, MB | RSS server / nginx, MB | Traffic down/up, Mbit/s | Echo p50/p95/p99, ms | Site p50/p95, ms | Download MB/s p50/min | Upload MB/s p50/min | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 GB | idle | 1.8% / 2.3% | 253 | 219 / 40 | — | 41/41/41 | — | — | — | 0 of 2017 |
| 1 GB | active | 40.8% / 62.4% | 412 | 334 / 64 | 334 / 44 | 41/53/122 | 234/261 | 16 / 12 | 6.9 / 4.3 | 0 of 24,161 |
| 2 GB | idle | 1.8% / 2.5% | 236 | 203 / 40 | — | 41/41/41 | — | — | — | 0 of 2012 |
| 2 GB | active | 41.1% / 61.3% | 414 | 332 / 66 | 332 / 41 | 41/52/102 | 234/256 | 16 / 11 | 6.9 / 4.4 | 0 of 24,471 |

In every step: no out-of-memory kill, no server crash, no long connection dropped.

## What limits the number of devices

In the order in which the limits apply:

1. **[Measured] The "8 sessions per source" quota behind nginx.**
   - Behind nginx the server sees the same address `127.0.0.1` for every device:
     nginx clears `X-Real-IP`, and the server takes the source from `RemoteAddr`.
   - The per-/24 quota becomes shared by everyone.
   - With the deployed configuration **at most 8 devices are served at once**,
     regardless of the VPS size.
   - This is an existing defect. It also lets any 8 authenticated devices occupy
     the server.
   - **Fixed in code** (not installed, not committed): `server/session_runtime.go`.
     A local source — nginx or the Mobile Link relay — no longer counts as one
     subscriber network.
   - Sessions behind it are bounded by the global `max_connections` and by "one
     live session per device credential".
   - The client address is still not passed to the server.
   - [Measured] on the stand with the deployed configuration (`max_connections 100`,
     `max_sessions_per_source 8`):
     - 10, 50 and 100 idle devices and 50 active ones — no refusals;
     - "per-source session limit" entries in the server log — 0.
   - **Mobile Link on the Pi.** The home server has the same defect: the agent
     connects to it from `127.0.0.1`, and its quota is 8 as well.
     - [Measured] Stand `run_home_quota.sh`, 10 devices from `127.0.0.1`.
     - Old build: 22 refusals with 503 and 5 "per-source" log entries.
     - With the fix: 0 refusals.
2. **[Code] `max_connections 100`** in the deployment template: at most 100
   sessions.
   - **Changed:** now 4096.
   - The real limit is the registry: one live session per device.
3. **[Measured] nginx `worker_connections 768`** (the Ubuntu default).
   - Every carrier connection and every open device TCP stream uses nginx
     connections; a stream also uses a connection to the server.
   - With 2 long-lived streams per device, 100 devices pass and 200 do not.
   - [Estimate] Real phones keep more than 2 long-lived connections. The limit is
     roughly 768 / (2 + concurrent streams per device), for example about 70
     devices with 9 streams.
   - **Changed:** at deployment `easypi-chameleon-nginx` sets:
     - `worker_connections 4096` and `worker_rlimit_nofile 16384`;
     - an nginx memory ceiling: MemoryHigh 25%, MemoryMax 35% of RAM. Past it the
       nginx master replaces the worker, and the VPS stays reachable.
4. **[Code] The device registry:** at most 200 mobile devices plus 1 home client,
   with addresses in one /24. **500 devices on one server are impossible**, so 500
   was not tested.
5. **Machine resources** with the limits lifted:
   - 200 active devices — 41% of one core on average, 62% at peak, and 414 MB;
   - 200 idle — 2% CPU and 253 MB.

## Practical limit

| | VPS 1 vCPU / 1 GB | VPS 1 vCPU / 2 GB |
|---|---|---|
| As currently deployed | **8** devices (source quota) | **8** |
| Source quota fixed, `max_connections` ≥ 201, nginx as now (768) | [Measured] 100 pass, 200 do not. [Estimate] about 70 for real phones with more connections | the same |
| Plus `worker_connections` ≥ 4096 — connected and idle | [Measured] 200 (the code limit is 201); 253 MB of memory | [Measured] 200; 2 GB brings no advantage |
| The same — simultaneously active | [Measured] 200 without errors, CPU 41% / 62%, 414 MB | [Measured] 200, the same |

[Estimate] A slower VPS vCPU leaves less CPU headroom (see the limits below). A
reasonable limit is about 150 simultaneously active devices. Up to 200 devices 2 GB
brings nothing: the 414 MB memory peak fits in 1 GB. This is an estimate, not a
measurement.

## Limits of the test

- **CPU.** A desktop core under WSL. A VPS vCPU is usually slower and can have
  stolen time (steal). The CPU shares in the tables apply only to this core.
- **Network.**
  - No loss, 30 ms delay, unlimited bandwidth.
  - 200 active devices produced 334 Mbit/s downstream. Many VPS ports are
    100–200 Mbit/s and will run out before the CPU.
- **The packet path was not loaded.** The server ran without root, so the kernel
  tunnel was unavailable. Device UDP, DNS and QUIC were not loaded; on a live VPS
  they add CPU.
- **The profile is synthetic.**
  - 2 long-lived streams per device, websites, downloads and uploads;
  - about 1.7 Mbit/s downstream per active device;
  - video and calls were not modelled.
- **Time.** A step lasts 120 s. Long-term effects were not checked: leaks, epoch
  rotation over hours, a day of idle.
- **OS memory.** The 200 MB reserve for the VPS system is an assumption.
- **Server limits** were lifted on the steps with 10 or more devices
  (`max_connections 1000`, `max_sessions_per_source 1000`); otherwise the quota
  rather than the machine would have been measured.
- **nginx without rewrite.** It was built without that module, so in the
  non-tunnel locations `return 404` was replaced with `try_files … =404`. The tunnel
  path does not depend on this.

Raw results: `tools/chameleon-load/results/`. Stand:
`tools/chameleon-load/`. Generator: test `TestChameleonLoad` in
`clientcore/chameleon_load_bench_test.go`.
