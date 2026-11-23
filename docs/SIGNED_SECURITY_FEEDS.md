# Signed security feeds

The Adult and NRD updaters pin both the upstream Git commit and the SHA-256 of
every downloaded source file. Maintainers must update the commit and hashes
together in a reviewed, signed EasyPi release; a byte mismatch keeps the active
policy unchanged.

EasyPi never replaces the active Tor IP policy from an unsigned Internet
response. The publisher extracts addresses from a Tor authority-signed
consensus, reviews the resulting change, and signs the validated snapshot with:

```bash
scripts/release/sign_tor_feed.sh \
  --input tor-ipv4-source.txt \
  --sequence 2026082901 \
  --signing-key /secure/offline/easypi-release.pem \
  --output-dir dist/tor-feed
```

Publish the three generated files over HTTPS. On each EasyPi host, create the
root-owned `/etc/easypi/tor-feed.json` (mode `0600` or `0644`):

```json
{
  "feed_url": "https://updates.example/tor_ipv4.txt",
  "manifest_url": "https://updates.example/tor_ipv4.manifest.json",
  "signature_url": "https://updates.example/tor_ipv4.manifest.json.sig"
}
```

The updater verifies the manifest with the root-owned EasyPi release key,
checks its sequence against the active root-owned bundle, validates the payload
hash and entry count, and rejects non-global or non-IPv4 values. Each accepted
version is stored below `/var/lib/easypi-security/tor/versions`; one atomic
rename of the protected `current` symlink activates its payload, signed manifest
and signature together. A download, signature, rollback, validation, or
activation failure preserves the last known-good bundle. When no signed feed is
configured, EasyPi keeps that bundle instead of trusting Onionoo directly.
