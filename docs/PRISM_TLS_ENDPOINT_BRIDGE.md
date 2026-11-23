# Prism TLS Endpoint Bridge in EasyPi binary releases

The experimental request-header decoder is now part of the EasyPi runtime and
binary build. It is observation-only and **disabled by default**. Normal
backend startup does not open capture, create a key listener, initialize the
decoder or depend on its health. The existing firewall-based Prism shadow and
FlowGraph services keep their current names and behavior. This component uses
the distinct `easypi-prism-endpoint-bridge` name.

## What is included in a build/update

- `prism_tls_bridge`: the promoted, reviewed TLS1.3/HTTP2 and QUICv1/HTTP3
  runtime, bounded BridgeWorker, shadow supervisor and libpcap adapter.
- Frozen binary modes dispatched before ASGI/backend imports, so spawning a
  decoder does not start another web backend or touch its database.
- Pinned and hashed aioquic, pylsqpack, hpack and cryptography dependencies,
  collected into PyInstaller including native extension modules.
- All runtime source modules and this document in the full release archive.
  The release validator rejects an archive missing the component.
- Two optional systemd units installed for binary installations using a
  dedicated non-login system account. Installation does not start/enable the
  private socket or capture. No new sudoers or backend API grant is added.

The full release archive, rather than a manually copied executable alone,
is the supported update artifact. The existing signed updater snapshots and
installs the complete payload. A local commit is necessary before the normal
clean-tree release builder can include these changes.

Build using the existing build command for the target architecture. Do not
build an amd64 executable for an arm64 Raspberry Pi. The builder runs the
embedded `--prism-tls-check` and rejects missing embedded dependencies. It
reports libpcap availability separately: Linux live capture needs the target's
libpcap shared library (normally provided with tcpdump). A missing library
makes only the optional observer unavailable, not the backend.

## Explicit binary modes

```text
/opt/EasyPi/backend/bin/easypi-backend --prism-tls-check
/opt/EasyPi/backend/bin/easypi-backend --prism-tls-shadow --help
```

The check imports embedded decoders without starting capture, opening ports,
reading endpoint secrets or importing the backend application. It reports
`default_enabled: false`. `--prism-tls-shadow` is a bounded Linux capture
launcher for one explicitly opted-in endpoint/transport/tuple. The internal
`--prism-tls-child` mode is reserved for the supervisor's private stdio pipe.
With no Prism mode, the binary starts EasyPi as before. Source installations
can use `python -m prism_tls_bridge.entrypoint --prism-tls-check` from the root
with pinned runtime dependencies installed.

Frozen children re-execute the binary with `--prism-tls-child`, using a fresh
PyInstaller environment. A separate POSIX process group contains bootloader
and worker descendants; disabling shadow kills that group. This avoids leaving
an orphan decoder when only a one-file bootloader PID is terminated. The
startup grace is 20 seconds for extraction/import; running heartbeat timeout is
three seconds. Forced process-group kill may leave temporary extraction files
until the containing private systemd tmp directory is removed.

## Independent opt-in boundary

After updating, the feature is present but will not decrypt anything by itself.
The managed client must export the secrets for the exact observed TLS session.
ESET or another TLS inspection boundary can create a different TLS leg. Firefox
key export does not establish secret availability in Chrome, Edge, Telegram,
WhatsApp or Android applications.

The optional socket unit is **local Unix only**, owner-only to `easypi-prism-tls`,
with at most one active connection. It is not enabled at boot and listens only
if an administrator explicitly starts it. The socket activates one instance
with private stdin. No HTTP endpoint accepts TLS keys. The existing KeyReceiver
adds an exact-scope session capability, strict sequence/MAC checks and expiry
over the authenticated/owner-private collector channel. Do not connect its
stdin to an unauthenticated TCP listener. Same-account processes and the
explicitly managed collector are trusted; this is not device attestation.

Before a controlled session, an administrator must prepare a root-owned
`/etc/default/easypi-prism-endpoint-bridge` containing only capture metadata:
`PRISM_TLS_INTERFACE`, `PRISM_TLS_CLIENT_IP`, `PRISM_TLS_CLIENT_PORT`,
`PRISM_TLS_SERVER_IP`, `PRISM_TLS_SERVER_PORT`, `PRISM_TLS_TRANSPORT` and a fresh
32-hex-character `PRISM_TLS_SESSION`. Do not put secrets/capabilities in that
file or command arguments. Use one transport (`tcp` or `quic`) and an exact
client/server tuple, not a whole LAN. Never reuse a stale run ID or key grant.

The administrator must also create `/run/easypi-prism-tls/enabled` as a regular
owner-only file owned by the dedicated account, and provide a private key
collector using the exact grant scope from `shadow_agent.py`. A missing config,
missing enable file, missing libpcap, missing keys, failed limits or failed
capture leaves the observer unavailable; it does not stop networking/backend.
The socket does not remove the requirement for managed endpoint instrumentation.
No session config, enable file, collector or TLS material is generated by install.

## Stop, overload, loss and resource containment

- Remove `/run/easypi-prism-tls/enabled` to disable an active observer. File
  checks run every 50 ms plus scheduling. Restoring it does not restart a child.
- Stop `easypi-prism-endpoint-bridge.socket` to prevent new sessions; this does
  not replace stopping an existing instance. Stop active
  `easypi-prism-endpoint-bridge@*.service` instances to end existing sessions.
- Each instance has `CPUQuota=25%`, `MemoryHigh=192M`, `MemoryMax=512M`,
  `TasksMax=24`, `KillMode=control-group`, `Restart=no` and no core dumps. These
  cgroup bounds cover collector, bootloader and decoder, not only the child.
- The child additionally has a 512 MiB address-space ceiling, 300 CPU-second
  lifetime budget, a 192 MiB RSS trip and a sustained CPU watchdog. Linux
  capabilities are removed before decoder imports and NoNewPrivs is set.
- libpcap drop counters are checked before each bounded batch, not just at
  shutdown. Loss, a truncated capture, overload, queue overflow or process
  death reduces visibility to Unknown. A lost flow cannot regain Decrypted
  without a new capture/handshake and fresh authorization.
- No traffic-verdict, NFQUEUE, redirect, iptables or certificate modification
  is exposed by the new component. No keys must never mean block the flow.

Only opaque flow IDs, protocol, visibility/reason and resource counts appear
in shadow diagnostics. Keys, packet payloads, hostnames and request paths are
not emitted. Private runtime material must remain out of source/releases.
Historical diagnostic queues are bounded; monitor event-drop counters rather
than treating them as a guaranteed complete audit trail.

## Validation and current experimental scope

The source component previously passed Windows and local WSL/Linux tests,
including generated TLS/QUIC replay, actual memory/CPU-limit enforcement,
capability removal, packet loss, SIGKILL/restart and independent socket traffic.
A local real-libpcap loopback test recovered two generated HTTP2 headers, then
confirmed that the same TCP socket continued after a child kill. A 60-second
local replay recovered 1,401/1,401 generated headers. The earlier 6,480/6,480
Pi result is also a controlled replay, not arbitrary Internet HTTPS throughput.
These results must not be presented as a live browser validation of this newly
integrated frozen binary or target Raspberry Pi Shadow service.

The EasyPi integration adds tests of binary dispatch, frozen child lifecycle,
release completeness, default-off units and install/uninstall contracts. Local
build/integration evidence is recorded under ignored `.build`. Target arm64
binary startup, whole-service cgroups and real Firefox/Chrome/Edge HTTP2/HTTP3
sessions still require confirmation after the user builds and updates EasyPi.
No server was contacted or updated while preparing this integration.

## Local integration checks (2026-10-31)

- 60 selected EasyPi integration/release/install/uninstall regressions passed
  locally, including a real supplied Linux one-file smoke executable.
- 55 generated-input component/decoder/worker tests passed against the promoted
  server package. Test fixtures were used only under ignored .build, not copied
  into the release package.
- The pinned CI Ruff check passed with the new package included; installer,
  uninstaller and binary-builder shell syntax checks passed.
- A real local amd64 PyInstaller 6.16 one-file smoke build imported native QUIC
  decoders, applied OS limits, survived a forced bootloader crash by cleaning
  up its descendant, and started a fresh second generation. The smoke entrypoint
  uses the same dispatch as production and does not build or launch the web app.

This is not a full production backend/arm64 release build or a target-service
browser run. The normal builder now repeats the embedded dependency check on
its full binary. To repeat the real frozen process test against an explicit
local Linux binary, set EASYPI_PRISM_TLS_SMOKE_BINARY to that binary and run
`python -m pytest tests/security/test_prism_endpoint_bridge.py`.

## Target acceptance follow-up

Initial testing of the separate systemd service on the target Raspberry Pi
identified a cold-start heartbeat race under its CPU quota. The running
heartbeat budget now starts at the child's ready event, and the outer launcher
uses the same configured startup grace. A regression covers a child becoming
ready after the normal running heartbeat interval has already elapsed.

The observer also emits cached `capture_health` samples with received/drop
counters and submitted-packet counts. These samples never read/reset drop
statistics separately from the capture pump, so diagnostic sampling cannot
consume a loss notification. Whole-service CPU/memory must still be measured
from the systemd cgroup, separately from decoder-process heartbeat samples.
Target acceptance uses a separate temporary candidate and never replaces the
running EasyPi backend or changes existing Prism filtering rules.

Current target observations, candidate provenance and incomplete acceptance
items are recorded in [PRISM_TLS_TARGET_ACCEPTANCE.md](PRISM_TLS_TARGET_ACCEPTANCE.md).
