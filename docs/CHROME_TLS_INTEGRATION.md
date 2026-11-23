# Withdrawn ordinary-Mobile root integration — historical record

The product requirement is ordinary Android phones without root. The root
collector was mistakenly integrated into ordinary Mobile and has been removed.
The dedicated Chrome observer on the test Pi was stopped and disabled. Root
research is restricted to the isolated laboratory. The instructions below are
retained for historical review and must not be followed as ordinary Mobile setup.

## Historical implementation

This feature integrates the existing Prism TLS Bridge with the existing paired
Mobile HTTPS API. It is passive and separate from forwarding, DNS and Chameleon.
It is disabled until an administrator configures a single paired device and the
user enables it in Mobile. No extra network listener or firewall rule is needed.

## Initial setup

1. Build and install the updated EasyPi backend, including the existing embedded
   Bridge dependencies. Preserve the installed backend binary and service unit
   first. `--prism-tls-check` must pass before replacement. This change has no DB
   migration. The existing Mobile pairing/token and certificate pin are reused.
2. Write a root-owned JSON configuration with `device_id` (the existing paired
   MobileDevice ID), `phone_ip` (the phone's IPv4 address), `destinations` (1–16
   explicitly authorized test-server IPv4 addresses), and `interface` (the
   gateway interface receiving the original phone packets). Use a DHCP
   reservation for the phone. Never use arbitrary devices or broad subnets.
3. Run `sudo /opt/EasyPi/scripts/settings/setup_prism_chrome.sh install CONFIG`.
   It checks the binary mode and configuration, preserves existing configuration
   and unit under `/var/lib/easypi/rollback/`, installs a restricted observer and
   enables its systemd restart/boot lifecycle. It does not edit network rules.
4. Install the signed updated ordinary EasyPi Mobile APK as an upgrade; preserve
   the old APK first. Keep the existing paired connection. In Settings choose
   **Enable Chrome observation**, read the notice and grant Magisk root to
   **EasyPi Mobile**, not a Lab package. This is a one-time interactive step.
5. Fully close Chrome during initial configuration. Wait for the persistent
   Mobile notification to report connection, then open Chrome normally. No ADB
   is used by the feature, and Mobile never launches a Chrome URL. A browser
   already running before its startup switch was configured needs one restart.

## Boundaries

Chrome's native switch exports secrets for **all Chrome connections**, not only
the server allowlist. This unavoidable browser behavior is disclosed before
enabling. The temporary file is Chrome-private, mode 0600. A root janitor checks
every second and truncates at 30 seconds or 1 MiB (a polling bound, not an atomic
hard disk quota), including while the Mobile process is dead. Other applications
are not inspected. Root revocation, a killed janitor, or OS restrictions can
prevent cleanup: disabling must report failure rather than claim success.

Only four supported TLS 1.3 labels are transmitted. Native unsupported labels
are ignored. Existing certificate pinning and paired-device bearer authentication
protect the upload. There is no new shared password, CA, or alternate auth path.
Every request rechecks the active Mobile device; revoking its pairing prevents
renewal/upload. The isolated process accepts only the configured device ID over
a group-restricted Unix socket. It grants renewable 60-second in-memory leases,
uses strict ordered sequence numbers and idempotent exact retries, and discards
expired keys. Pending keys are bounded at 256 records for 60 seconds. Each flow
receives only keys with its captured ClientHello identifier. Wrong keys never
create authenticated HTTP headers. ECH or unavailable/missing handshakes may
prevent identifier matching; no guessed match or downgrade is performed.

There are at most 16 concurrent flows. Existing Bridge queue, reassembly,
header, event, idle, key and packet budgets still apply. Active flow key leases
are bounded at 300 seconds after their last supplied key; longer connections
can become Unknown until a fresh handshake. Loss clears the observation
generation. OOM/crash affects only the observer, and systemd restarts it.
Request bodies, unrelated application traffic, migration between QUIC tuples,
unbounded concurrent browsing and arbitrary apps are not supported claims.

The Mobile foreground service is opt-in and visible. BOOT_COMPLETED and package
replacement resume it after unlock, using Android's declared `specialUse`
foreground service type; this is not a Play Store approval claim. Reference:
https://developer.android.com/develop/background-work/services/fgs/service-types
Android force-stop, revoked root/notifications, OEM battery restrictions and
boot order must be tested on the target phone. Recovery after loss of capture
requires a new complete handshake; an existing encrypted connection cannot be
reconstructed without its missing initial capture.

The observer retains secret material only in memory and emits counters rather
than URLs or full headers. `POST /api/v1/mobile/prism/chrome/status`, authenticated
as the paired phone, returns state and counters. Headers are decoded by the
existing Bridge but are not used for blocking or written to ordinary telemetry.

## Disable and rollback

In Mobile choose **Disable and restore Chrome settings**. This stops Chrome
during the explicit disable operation, restores the backed-up command-line file
and deletes the diagnostic key file. Keep root available until cleanup succeeds.
The forwarding/VPN services are not stopped. Do not just uninstall or revoke
root while export is configured. File deletion is not forensic erasure.

On Pi run `sudo /opt/EasyPi/scripts/settings/setup_prism_chrome.sh disable`.
Restore configuration/unit from its recorded backup if needed, then
`systemctl daemon-reload`. To remove the integration, restore the previous
backend binary atomically after stopping both the observer and backend readers,
then start `easypi-backend`; preserve ownership and mode. Running PyInstaller
processes must not race replacement of their executable archive. Install the
backed-up Mobile APK as an upgrade if its signing lineage
and version permit it; retain app data. No firewall or routing rollback is needed.

## Verification status

Local automatic-observer tests cover generated authenticated HTTP/2 and real
in-memory QUIC/HTTP/3 endpoints, keys delivered before/after packets, wrong and
missing keys, scope, replay, expiry and budgets. Existing pairing/shadow tests
are also run. This is separate evidence from the earlier real Chrome offline
validation. Phone/Pi live, unplugged, crash and reboot results must be recorded
explicitly before declaring autonomous integration accepted.
