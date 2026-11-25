# Mobile security migration

Deploy the matching backend, Chameleon server/client and Android release as one
reviewed change. Back up executables, server configuration, Stealth metadata,
client configuration, mobile database and service definitions before migration.
Keep an independent SSH administration path throughout.

The existing `psk_key` becomes only the shared cover/routing marker. Generate a
new independent `client_auth_key` and never return it to Mobile API callers.
The home client's `psk_key` is this independent credential; its `transport_key`
is the cover/routing value. Device PSKs are HMAC-SHA256 of the independent master
and the canonical device UUID with domain separation. A phone cannot derive the
master or another phone's credential. Captured legacy profiles cannot establish
new sessions after the server migration.

The VPS reads a root-owned `mobile_clients.json` registry containing version 1
and the allowed device UUID/IPv4 pairs. Publish it atomically, root:chameleon,
0640. Each device has exactly one /32 in 10.10.0.3--254. The home identity owns
10.10.0.2. Packet sources must match the authenticated assignment. Missing or
invalid registry data revokes mobile sessions and denies new mobile sessions.
Active streams are canceled on removal; registry reload is checked on new
requests and by a 200 ms watcher. Database/VPS mutations are serialized with
the existing cross-process deployment lease.

Enroll the Android client again through its existing authenticated Mobile API
connection to obtain the new device credential; re-pairing or data deletion is
not needed. Do not temporarily re-enable shared-key authentication. Deleting a
phone first disables its Mobile API token. A failed VPS synchronization keeps
the revoked database row and returns an error; retry deletion to finish VPN
revocation. Do not interpret an error as successful revocation of every path.

Legacy mobile Tailscale auth-key issuance is retired because it cannot bind
the resulting tailnet node to a revocable MobileDevice. The Android application
uses Chameleon. Existing unrelated Tailscale services are not part of this
change. Historical mobile nodes, if any were provisioned by an older client,
must be identified and removed from the tailnet separately; never delete nodes
based solely on an ambiguous display name. Reintroducing mobile Tailscale
requires verifiable node identity, scoped ACLs and node revocation first.

The mobile file API denies hidden/internal Cloud paths both before and after
path resolution. This includes downloads, previews and deletion. Do not move
internal metadata into a visible user folder to work around this boundary.

Native builds require Go 1.27.4. The pinned Linux archive checksums in
`chameleon/ensure-go.sh` are from the official Go download manifest. The updated
x/net module includes the HTTP/2 fixes; keep the existing isolated HTTP/2 flow
patch and verify its exact upstream match when building Linux release binaries.
