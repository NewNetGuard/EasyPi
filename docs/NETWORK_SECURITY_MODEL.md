# EasyPi network security model

## Unknown-device admission

EasyPi's standard LAN admission policy identifies a managed device by an
observed MAC address and IPv4 address/range pair. Both bindings must be enabled,
belong to the same profile, and identify the same named device. Missing,
ambiguous, corrupt, or legacy policy data fails closed.

When `block unknown devices` is enabled, the packet path does not wait for a
scanner or for the web interface: an identity without an active MAC+IPv4 pair is
rejected immediately by the admission chain. The backend separately consumes
passive DHCP observations and the kernel ARP neighbor table every few seconds.
It records a bounded, permission-restricted quarantine entry and raises the
"New device detected" banner and notification.

`Block` only acknowledges the alert; the deny rule remains in force. `Allow`
accepts a display name and one predefined access profile, while MAC and IP are
loaded exclusively from the server-side observation. The managed client,
profile, two bindings, and firewall chain are published transactionally. A
root-owned admission hold for that exact pair is installed before publication,
survives service/host restarts, and is released only after every policy stage
succeeds. A failed or partial publication restores the previous policy while
the independent hold keeps the device blocked. If the MAC already belongs to a
managed device, Allow updates its DHCP address and preserves the stable device
ID rather than creating a duplicate. That re-admission changes only the
observed identity, administrator-selected name, and shield profile; existing
per-device service blocks, domain rules, bypass response, and other individual
controls are retained.

PRISM Identity adds continuity above this packet-level admission boundary. For
each approved Device ID it keeps a bounded history of MAC aliases and a compact
metadata profile. DHCP Client-ID is accepted as an independent signal only when
it is not derived from the current MAC. DHCP hostname, vendor class, parameter
sequence, and fingerprint form one platform signal rather than several votes.
PRISM contributes TLS implementation fingerprints and a keyed digest of recent
destination names; raw destination names and traffic content are not written to
the identity store.

A new MAC remains quarantined while it is evaluated. A complete platform match
may be shown as a low-confidence suggestion for an explicit administrator
decision. Automatic migration requires at least three independent evidence
groups, a score of at least 85, and either a strong PRISM behavior match or a
stable non-MAC-derived DHCP identity. If the old and new MACs produce traffic at
the same time, stable identifiers conflict, or two managed devices score too
closely, automatic migration is forbidden. A successful migration preserves the
Device ID and every existing device policy, retires and blocks the previous MAC,
and publishes the change under durable firewall holds with rollback on failure.

The web banner always shows the complete pending queue. External Inbox, Web
Push, and Telegram alerts are limited to five individual device identities per
minute; additional identities are combined into one summary. All device-derived
Telegram text is HTML-escaped before it reaches Telegram's HTML parse mode.

This control is intended to quarantine new, accidental, and unapproved devices
on a trusted home or small-office LAN. It is not cryptographic device
authentication. A hostile peer with access to the same broadcast domain can
clone both the MAC address and IP address of an approved device, especially
while that device is offline. Passive DHCP observation, ARP inspection, and
duplicate-address detection cannot determine which of two identical L2/L3
identities is genuine.

Spoof-resistant admission therefore requires a trust anchor outside the current
DNS/router process:

- 802.1X or WPA-Enterprise enforced by the switch/access point, with a unique
  credential per device; or
- an enrolled per-device certificate/key and mandatory encrypted tunnel through
  EasyPi.

Until one of those deployment modes is implemented and enabled, hostile-LAN
MAC+IP impersonation is an explicitly documented residual risk. The API reports
`identity_assurance=observed_mac_ip_pair`, `spoof_resistant=false`, and
`requires_trusted_lan=true`; UI text must not describe this control as strong
device authentication.

## IPv6 forwarding boundary

The IPv6 policy guard is a required, continuously running system service for
EasyPi Backend and NetProtection. It establishes an unconditional emergency
IPv6 FORWARD rejection before either dependent service starts. It then checks
global addresses and default routes periodically and on NetworkManager events.

If inspection or selective policy publication fails, the emergency rejection
remains active. If netfilter cannot establish that rule, the guard disables
kernel IPv6 forwarding. If neither mechanism succeeds, the guard exits and
systemd `Requires`/`BindsTo` stops the dependent services.

No software running on EasyPi can filter packets that physically travel through
another router without traversing EasyPi. Deployments requiring enforced IPv6
policy must make EasyPi the IPv6 gateway or disable IPv6 at the upstream router.
