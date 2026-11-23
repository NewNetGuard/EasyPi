# EasyPi acceptance testing

This directory is the executable catalogue for product-wide testing. It keeps
long-running checks in scripts so repeated runs consume machine time instead of
manual review time.

## Profiles

- `quick` runs the security and agent regression suites.
- `full` adds linting, shell validation, frontend checks and Chameleon tests
  through `chameleon/test.sh` and the repository-pinned, checksum-verified Go
  toolchain.
- `live-readonly` checks public health/authentication behavior and service state
  without changing the appliance.
- `browser` opens the login flow and, when test credentials are supplied through
  the environment, every authenticated application page.
- `browser-data` creates and removes namespaced temporary users, PiCloud items,
  shares, and Files content. Run it only against a development appliance.
- `browser-agent` checks deterministic diagnostics, probe allowlisting,
  confirmation enforcement, and the locally configured chat runtime.
- `browser-network` performs bounded DNS, gateway, ARP and connection probes and
  compares Guard, PRISM and Chameleon live state without changing routing.
- `browser-operations` checks a real terminal PTY, job evidence, reversible
  notification preferences, and live admin/user authorization boundaries.
- `browser-marketplace-help` verifies that Marketplace makes no install API
  requests and that Help navigation, input limits, legacy-state cleanup, and
  external support links behave as documented.
- `browser-backup` creates, validates, downloads and deletes one encrypted
  config backup, exports a disposable protected recovery package, and rejects a
  malformed import. It never restores data.
- `browser-dns` creates and updates one temporary DNS rewrite, resolves it
  through the live NetProtection resolver, and deletes it with a cache check.
- `guard-functional` resolves one domain from the installed blocklist and one
  allowed domain, then verifies the resulting DNS answers and flow-log evidence.
- `prism-functional` creates a temporary LAN identity, performs one real HTTPS
  exchange, verifies a new PRISM TLS assessment, and removes the identity.
- `release-security` presents an invalid detached signature to the real updater
  and verifies rejection before code changes, snapshots or service restarts.
- `chameleon-recovery` restarts the Chameleon client and briefly blocks only its
  VPS carrier to verify route restoration, same-process recovery and dataplane
  traffic. Run it only against an authorized development appliance.
- `wireguard-functional` sends the current local WireGuard script to a Linux
  test host and exercises stopped-service rejection, failure rollback,
  concurrent peer allocation, and persistent peer revocation entirely under
  an isolated `/tmp` tree with command doubles.
- `camera-security` runs the camera transport and file-serving regressions,
  then starts an isolated go2rtc instance on the test host to verify that its
  loopback API rejects unauthenticated requests and accepts the reserved
  discovery-stream update with internal authentication.
- `operations-security` checks atomic terminal limits, bounded PTY input,
  secret-free job responses, safe email rendering, notification validation,
  push subscription persistence, and the frontend notification controls.
- `marketplace-help-security` checks that Marketplace remains a read-only
  preview with no backend route, Help does not retain diagnostics, and every
  Help link resolves to a real application route.

Every run writes `inventory.json`, `report.json`, and `report.md` under
`.build/acceptance/<UTC timestamp>/`.

```bash
python tests/acceptance/run_acceptance.py --profile quick
python tests/acceptance/run_acceptance.py --profile full
python tests/acceptance/run_acceptance.py --profile full --strict-tools
python tests/acceptance/run_acceptance.py --profile live-readonly \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile browser \
  --base-url https://easypi.test --browser-channel chrome --insecure
python tests/acceptance/run_acceptance.py --profile chameleon-recovery \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile guard-functional \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile prism-functional \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile wireguard-functional \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile camera-security \
  --base-url https://easypi.test --ssh-target easypi-test --insecure
python tests/acceptance/run_acceptance.py --profile operations-security
python tests/acceptance/run_acceptance.py --profile marketplace-help-security
```

SSH checks deliberately require key authentication. Passwords and tokens must
not be passed as command-line arguments because command lines and reports can be
visible to other processes or retained as test evidence.

Authenticated browser coverage reads `EASYPI_E2E_USERNAME`,
`EASYPI_E2E_PASSWORD`, and optionally `EASYPI_E2E_TOTP` from the process
environment. Without them, the public login and access-control checks still run.

The live profile is safe for an installed device. Fresh installation, restore,
firewall, routing, VPN, Chameleon deployment, and failure-injection scenarios
must run on a separate disposable Pi. Those scenarios are catalogued in
`acceptance_manifest.json` and will be automated as the isolated test target is
prepared.
