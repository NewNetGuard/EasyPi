# Withdrawn Chrome integration: historical validation record

**Superseded requirement:** ordinary EasyPi Mobile runs without root. The
ordinary-app root collector, boot receiver and UI have been removed; laboratory
results remain separate. The dedicated Pi Chrome observer is now stopped and
disabled. All deployment/status statements below describe earlier measurements,
not current ordinary-Mobile functionality or an accepted autonomous product.

Date: 2026-11-03. Status: **implemented and deployed candidate; autonomous
acceptance blocked by unavailable phone root; live/reboot tests pending**.

## Follow-up: remote initial setup and failure handling

After the owner authorized unattended setup, the ordinary Mobile foreground
observer was enabled through its own UI. Root then proved unavailable even to
the previously authorized ADB shell: the CLI reported connection refused, and
Android logged SIGTRAP in su. Magisk itself requested additional installation
and reboot. The cause of daemon unavailability is not established. No policy
database changes, boot image modifications, SELinux changes or lock bypass were
performed. The phone was not rebooted because its secure lock requires the
absent owner's manual unlock afterward.

Mobile fixes were built, signed and installed as an upgrade:
bounded exponential root/network retries, a specific root-unavailable message,
live Settings status updates, persistent failed-cleanup warning, and RAM expiry
during retry pauses. All 18 Android tests, release lint/build and signature
verification passed. The error and cleanup warning were exercised on-device;
the warning survived app force-stop/relaunch. Observer collection is disabled
on the phone; its Chrome command line matches baseline with no export flag.
Chrome-private directory cleanup cannot be asserted while root is unavailable.

Updated installed APK SHA-256:
`0816e951d330e334aba6fbd849ae4867915e1dbf559d55c3808d557872b71131`.
The earlier APK/hash below remain historical deployment evidence.

Separately, the Pi observer was given one generated ephemeral test key and
SIGKILLed. Systemd automatically restarted it, retained keys became zero, and
the old lease was rejected. No real Chrome key was used in that recovery test,
and no recovered request was claimed. The receipt is private ignored evidence
`.build/chrome-integration-crash-recovery.json`. This supersedes the initial
NRestarts=0 sample below; it is not a Pi reboot test. The backend, DNS, nginx
and existing Prism remain active.

The latest phone report is Mobile's `docs/CHROME_ROOT_FAILURE_VALIDATION.md`.
Restore functional Magisk root with manual unlock available before real
autonomous Chrome acceptance; the earlier offline results are not a substitute.

## Components implemented

- `prism_tls_bridge/chrome.py`: one-device/destination scope, automatic TCP and
  QUIC flow discovery, ClientHello-to-secret association, bounded in-memory key
  index, lease renewal/expiry, replay/conflict checks, existing Bridge decoding,
  loss handling and secret-free counters. No forwarding or blocking path.
- `prism_tls_bridge/chrome_agent.py`: existing libpcap capture and private Unix
  IPC adapter, strict resource and request budgets; no public listening port.
- `backend/app/services/chrome_bridge_service.py` and the existing Mobile router:
  paired-device authentication reused for lease/key/status/disable operations.
  Bounded raw-body parsing avoids secret reflection in validation responses.
- Existing binary entrypoint/packaging dispatch includes the Chrome observer.
  `pcap_live.py` adds an optional validated device/destination filter; the old
  exact-flow capture interface is preserved.
- `templates/systemd/easypi-prism-chrome.service`: dedicated capture-capable user,
  CAP_NET_RAW only, 25% CPU quota, 256 MiB memory, no core dumps, restart and boot
  lifecycle. Setup/disable script backs up existing configuration and unit.
  Normal installation installs the optional unit without enabling it by default.
- Ordinary Mobile: `ChromeRoot.kt`, `ChromeBridgeService.kt`, Settings UI and
  manifest. Explicit root opt-in, private native keylog setup/backup/restore,
  independent root janitor, bounded cursor/generation handling, pinned HTTPS
  upload using existing pairing, visible foreground service and boot receiver.
  No new project, Lab APK, browser hooks, CA or certificate replacement.

## Tests and builds

| Check | Actual result |
|---|---|
| Windows: existing pairing, Bridge integration, shadow runtime and new Chrome tests | 74 passed, 3 platform-dependent skips |
| Raspberry Pi: new automatic Chrome observer tests | 17 passed |
| Android existing unit tests | 16 passed, zero failures/errors/skips |
| Android release compile, lint and assembly | Passed |
| Release APK signature | Existing production v3 signing identity verified |
| Mobile upgrade | Installed with adb install -r, previous APK backed up, data retained |
| Pi candidate binary embedded Bridge check | Passed |
| Pi configuration preflight | Passed |
| New API with invalid Bearer token | 401, authentication boundary preserved |
| Isolated observer status over private IPC | Running; no lease, keys, flows or recovered headers yet |
| Observer systemd startup | Enabled and active; NRestarts=0 at check |
| Other services | Backend, NetProtection DNS, FlowGraph and nginx active |

The 17 tests include generated authenticated TLS 1.3/HTTP/2 and actual in-memory
aioquic HTTP/3 exchanges, keys arriving before/after packets, missing/wrong keys,
atomic batches/conflicts, ordered replay/idempotence, expiry, renewal, scope,
capacity and capture-loss revocation. These tests do not substitute for a real
autonomous Chrome-to-Pi run. Existing real Chrome PCAP results remain the separate
evidence recorded during earlier Mobile testing; they were not rerun here.

## Deployment evidence and failures preserved

Installed backend SHA-256 (identical to target-built candidate):
`da91aff6f7412817a2f690d8131f12bbba2d963f3c4a800db81bb8057d747b33`.

Installed signed APK SHA-256:
`491098a2170186e4b548fc6d791f5fd785315fad659a4a26d68a8d30b075f7cf`.

The backend/service backup and tested restoration script were stored under
`/var/lib/easypi/rollback/`. The observer installer recorded its
configuration backup in `/var/lib/easypi/rollback/chrome-20261103T102624Z/`.
The previous Mobile APK and install receipt are private ignored artifacts under
Mobile `.build/chrome-main-integration/`. Configuration/keys are not committed.

Preparation failures: a staged shell script initially had Windows CRLF line
endings, then the target build environment lacked pytest. Both failed before
service replacement; the script was corrected and pytest installed only in the
temporary build directory. No runtime environment was upgraded for that reason.

The first readiness probe expected 401 from a POST with no Authorization header;
existing CSRF middleware correctly returned 403. The backend was active, but the
deployment gate rejected it and the previous binary was restored. The probe was
corrected to use an explicitly invalid Bearer token; CSRF was not weakened.
One PyInstaller zlib archive error was observed during the replacement/rollback
window. Its exact mechanism was not independently reproduced; replacing an
archive while its readers are running is a plausible cause. Future restoration
now stops the observer/backend before atomic archive replacement. The subsequent
deployment passed and both candidate and installed hashes match.

Chameleon file hashes were identical before/after deployment. No route/firewall
commands were added to the feature. However, the normalized firewall fingerprint
changed across the backend restart. Logs show the existing startup path invoked
`setup_prism_shadow.sh enable`; the first check retained only the fingerprint,
not a complete before-rules snapshot, so the exact rule difference is not proven.
Two subsequent full normalized rule snapshots matched. Do not claim bitwise
firewall invariance or attribute the entire change to a proven cause. The new
observer has no CAP_NET_ADMIN. Its measured idle cgroup memory was about 180 MiB
(188,530,688 bytes); load/limit headroom is not yet validated.

## Not yet accepted

- Root consent and exporter/janitor behavior in the ordinary Mobile package on
  the actual phone, including cleanup and restart races.
- Actual paired Android upload, fresh key/packet correlation, AEAD and HTTP/2/H3
  header recovery in the deployed autonomous pipeline.
- Unplugged operation, network interruption, observer termination/OOM and fresh
  connection recovery; phone and Pi reboot acceptance.
- Long-lived connections beyond key/decoder budgets, QUIC tuple migration,
  IPv6 scope, ECH identifier mismatch and broad concurrent load.
- Exact cause of the initial firewall fingerprint change and full regression
  acceptance of all EasyPi services under live load.

Root was requested through the user-facing Mobile setup, not granted by editing
Magisk policy through ADB. At the final status sample the server retained zero
keys and no lease was active. No autonomous success is claimed from build/tests,
service enablement, or earlier offline replay alone. Setup, disable, retention
limits and rollback instructions are in CHROME_TLS_INTEGRATION.md.
