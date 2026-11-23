# EasyPi Binary Releases

This repository is a **binary-only distribution** of EasyPi.

- Source code is not published here
- Installable archives are provided in GitHub Releases
- License terms: see `LICENSE` and `EULA.txt`

## Install

1. Open the latest Release page.
2. Copy the direct link to archive `__ASSET_NAME__`.
3. Install the `easypi-release-bootstrap` package through the independently
   authenticated EasyPi APT repository (or an equivalent authenticated channel).
   That package provides `/usr/bin/easypi-install-release` and
   `/usr/share/keyrings/easypi-release.pub`. This binary release repository
   intentionally contains neither the bootstrap nor a replacement trust key.
4. Run the independently installed bootstrap with the archive and detached
   `.sig` asset URLs:

```bash
easypi-install-release \
  --archive-url "__ASSET_URL_PLACEHOLDER__" \
  --signature-url "__ASSET_URL_PLACEHOLDER__.sig"
```

## Optional checksum verification

```bash
sha256sum -c checksums.txt
```

The checksum detects accidental corruption. The mandatory detached signature is
verified against the key installed outside this repository. Never execute a
bootstrap script or import a replacement key supplied by the release channel.

Release operators build the independent bootstrap package with
`scripts/release/prepare_bootstrap_deb.sh` in the source repository and publish
it only through a signed APT repository separate from this archive channel.

## Notes

- This repository is intended for end users.
- If you need access to source code, contact the project owner.
