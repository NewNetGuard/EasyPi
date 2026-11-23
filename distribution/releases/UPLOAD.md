# Upload a signed binary release

Never publish an archive without its detached signature. `SHA256SUMS.txt` is
only a corruption check and is not a publisher-authentication mechanism.

1. Build the official Trixie/aarch64 archive on the supported build host.

```bash
./build_all.sh
```

2. Prepare a complete, validated public bundle with the offline release key:

```bash
./scripts/release/prepare_public_repo.sh \
  --asset .build/easypi-full-aarch64-trixie.tar.gz \
  --signing-key /secure/offline/easypi-release-key.pem
```

The output must contain the archive, the matching `.sig`, and
`checksums.txt`. Keep the private signing key outside the repository and release
channel.

3. Create the tag and upload the archive plus its detached signature:

```bash
gh release create vX.Y.Z \
  ".build/public_repo/easypi-full-aarch64-trixie.tar.gz" \
  ".build/public_repo/easypi-full-aarch64-trixie.tar.gz.sig" \
  ".build/public_repo/checksums.txt" \
  --repo NewNetGuard/EasyPi \
  --title "EasyPi vX.Y.Z" \
  --notes "Signed EasyPi binary release for Raspberry Pi OS Trixie (aarch64)."
```

4. Download both release assets into a clean directory and verify the detached
   signature with the independently provisioned public key. Then run the
   bootstrap against the final HTTPS asset URLs in a clean Raspberry Pi OS
   Trixie test installation.

Do not upload `easypi-install-release` or a replacement public key to the binary
release channel. They belong in the independently authenticated bootstrap
package/repository.
