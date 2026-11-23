# Import, upload and restore boundaries

## OpenVPN profiles

`backend/app/core/openvpn_config.py` is the shared, standard-library-only parser.
Backend import validates before replacing the saved profile. The privileged
`outbound_vpn.sh` independently validates its private copy using isolated system
Python, verifies root ownership and non-writable permissions of the validator
and its ancestors, and launches only the canonical output. The signed release
must include the validator source even when the backend runs as a binary.

Unknown options, hooks, plugins, configuration includes, file references,
proxy authentication files and nested connection blocks are rejected. Supported
certificates and keys must use `<ca>`, `<cert>`, `<key>`, `<pkcs12>`, `<tls-auth>`,
`<tls-crypt>`, `<tls-crypt-v2>` or `<crl-verify>` blocks. Bare `auth-user-pass`
continues to use the existing protected credential broker; inline credentials
are also supported. User-supplied credential filenames are never accepted.

Quoted and `--`-prefixed safe option names are normalized before routing and
credential handling. Profiles with unsupported options must be re-exported or
reviewed; do not silently discard unknown directives or widen the allowlist.
The complete supported option/argument policy is in the parser. Lines are
limited to 254 UTF-8 bytes to avoid OpenVPN 2.6's 256-byte input-buffer splitting.

## Upload authentication

Both nginx listeners gate `/api/v1/mobile/upload` using a bodyless GET subrequest
to `/api/v1/mobile/auth-check`. That endpoint uses the same active-device token
lookup as the upload endpoint. Missing, invalid and revoked tokens return 401
before nginx forwards a body to the multipart handler. The internal auth
location cannot be requested directly. Authorized uploads retain the 5 GiB
nginx allowance and the backend's existing per-file limit. Other Mobile Link
requests have a 1 MiB default cap, matching the main listener.

CSRF middleware and the explicit CSRF dependency require `X-CSRF-Token` for
browser mutations. They never parse a form to find `_csrf_token`; external
clients using only that field must switch to the header. The shipped frontend
already sends the header. Mobile bearer-token authentication remains unchanged.

Install the matching backend before activating the nginx templates: older
backends do not have the auth-check endpoint. Direct backend access is outside
the nginx pre-upload gate; its listener must retain its loopback-only binding.

## Backup compatibility

New config/full/pre-restore snapshots exclude every host file that root
interprets: systemd units, SSH daemon configuration, `/etc/sysctl.conf` and the
EasyPi `sysctl.d` files, the nginx site configuration and the unbound
configuration. A kernel parameter can name a helper the kernel runs as root,
and an nginx configuration can make the root master process create files, so
these formats are as sensitive as a unit file. Restore and automatic rollback
leave the installed versions intact and never delete them; the installer, the
signed updater and the validating settings scripts own these host files.

After restoring onto a different host, gateway forwarding, the recursive
resolver and HTTPS certificates keep the new host's installed configuration.
Re-apply them from the EasyPi settings pages if the old host differed.

Legacy archives remain usable for data recovery. The exact formerly included
file names are validated as regular files, counted toward archive limits, read
for archive integrity, then skipped with a warning. They are never opened for
writing or assigned archive-provided ownership/modes. Unknown host paths,
links, duplicates and traversal remain rejected before writes. An archive
containing only skipped files cannot initiate a restore.

The remaining restore targets outside `/opt/EasyPi/config` and
`/opt/EasyPi/data` are `/etc/hostname`, `/etc/hosts`, `/opt/EasyPi/.env` and the
Stealth DNS policy. `.env` is application settings for unprivileged services:
no root service may load it as an environment file. The Taildrop importer,
which runs as root, reads only its upload-size limit from the file through
`--settings-file`. The contents of `.env`, `/etc/hosts` and the data tree are
not otherwise validated; the PostgreSQL connection settings in `.env` are
still used by the root backup helpers and were not part of this review.

## Reaching already installed systems

An ordinary signed update does not run the full installer. Its restart cycle
therefore re-renders two root-interpreted host files from the release
templates, next to the existing Mobile Link unit refresh:

- `/etc/nginx/sites-available/easypi`, so the upload gate replaces a site
  installed by an earlier release. The new site is kept only if `nginx -t`
  accepts it; otherwise the previous file is put back and the update rolls
  back. A missing or symlinked site is left untouched.
- `easypi-taildrop-import.service`, so the root importer stops loading `.env`.
  Its `--owner`/`--group` account is preserved; a removed unit is not recreated.

A rollback restores the previous tree and runs the same cycle, so both files
follow the restored templates and stay matched to the restored backend and
importer. `--skip-restart` refreshes the unit but not the nginx site, which is
only ever replaced together with the nginx restart.

## Verification

Run the security tests for `openvpn_allowlist`, `upload_preauth`,
`restore_host_files`, `mobile_pairing_security`, backup recovery and release
validation with `PYTHONPATH=backend:.` (use `;` on Windows).
The real extraction and root-owned launcher checks require Linux; the launcher
test redirects only test paths and does not start OpenVPN or change networking.
`test_nginx_mobile_upload.py` starts private localhost listeners from both actual
templates; set `EASYPI_TEST_NGINX` to an nginx executable with TLS/auth_request.
It checks rejection before 100 Continue with a >4 GiB declared length and chunked
framing, successful authorized uploads, revocation and internal-location access.
