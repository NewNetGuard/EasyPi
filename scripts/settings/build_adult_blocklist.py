#!/usr/bin/env python3
"""Validate a reviewed adult feed and generate runtime data plus provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path


SOURCE_NAME = "The Block List Project - Porn Block List"
SOURCE_REVISION = "ee3bdbaddf49c756cf3340bb2e6a9dee5282d1c6"
SOURCE_URL = (
    "https://raw.githubusercontent.com/blocklistproject/Lists/"
    f"{SOURCE_REVISION}/porn.txt"
)
SOURCE_HOMEPAGE = "https://github.com/blocklistproject/Lists"
LICENSE_URL = (
    "https://raw.githubusercontent.com/blocklistproject/Lists/"
    f"{SOURCE_REVISION}/LICENSE"
)
EXPECTED_SOURCE_HEADERS = frozenset(
    {
        "# Title: Porn Block List",
        "# Homepage: https://github.com/blocklistproject/Lists",
        "# License: MIT",
    }
)
MAX_SOURCE_BYTES = 64 * 1024 * 1024
DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
SKIP_VALUES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "ip6-localhost",
        "ip6-loopback",
    }
)
CRITICAL_APEX_DOMAINS = frozenset(
    {
        "apple.com",
        "cloudflare.com",
        "debian.org",
        "github.com",
        "google.com",
        "microsoft.com",
        "mozilla.org",
        "raspberrypi.com",
        "wikipedia.org",
    }
)


class FeedValidationError(ValueError):
    """Raised when mutable upstream content violates a reviewed boundary."""


def _read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise FeedValidationError(f"not a regular file: {path}")
        if file_stat.st_size <= 0 or file_stat.st_size > max_bytes:
            raise FeedValidationError(f"invalid file size for {path}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise FeedValidationError(f"file exceeds size limit: {path}")
        return payload
    finally:
        os.close(fd)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _parse_source(payload: bytes) -> tuple[set[str], list[str]]:
    text = payload.decode("utf-8", errors="ignore")
    headers: list[str] = []
    domains: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("#", "!")):
            if line.startswith("#") and len(headers) < 64:
                headers.append(line)
            continue
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        domain = line.split()[-1].strip().rstrip(".")
        if domain in SKIP_VALUES or len(domain) > 253:
            continue
        if DOMAIN_RE.fullmatch(domain):
            domains.add(domain)

    missing_headers = EXPECTED_SOURCE_HEADERS.difference(headers)
    if missing_headers:
        missing = ", ".join(sorted(missing_headers))
        raise FeedValidationError(f"reviewed source headers changed: {missing}")
    critical = sorted(domains.intersection(CRITICAL_APEX_DOMAINS))
    if critical:
        raise FeedValidationError(
            "source contains protected infrastructure domains: " + ", ".join(critical)
        )
    return domains, headers


def build_feed(
    *,
    source_path: Path,
    license_path: Path,
    output_path: Path,
    notice_output_path: Path,
    license_output_path: Path,
    manifest_output_path: Path,
    expected_license_sha256: str,
    min_domains: int,
    max_domains: int,
) -> dict[str, object]:
    source_payload = _read_regular_file(source_path, max_bytes=MAX_SOURCE_BYTES)
    license_payload = _read_regular_file(license_path, max_bytes=1024 * 1024)
    license_sha256 = _sha256(license_payload)
    if license_sha256 != expected_license_sha256.lower():
        raise FeedValidationError(
            "upstream license changed; manual legal review is required"
        )

    domains, source_headers = _parse_source(source_payload)
    if not min_domains <= len(domains) <= max_domains:
        raise FeedValidationError(
            f"domain count {len(domains)} is outside reviewed range "
            f"{min_domains}..{max_domains}"
        )

    generated_at = datetime.now(timezone.utc).isoformat()
    source_sha256 = _sha256(source_payload)
    header = [
        "# EasyPi runtime-derived adult domain feed",
        "# This third-party data file is not part of EasyPi proprietary code.",
        f"# Source: {SOURCE_NAME}",
        f"# Source URL: {SOURCE_URL}",
        f"# Source homepage: {SOURCE_HOMEPAGE}",
        "# Source list declaration: MIT",
        "# Repository LICENSE: Unlicense",
        f"# License URL: {LICENSE_URL}",
        f"# Source SHA256: {source_sha256}",
        f"# Generated at: {generated_at}",
        f"# Domain count: {len(domains)}",
        "# See adult_domains.NOTICE.txt, adult_domains.LICENSE.txt, and",
        "# adult_domains.sources.json in this directory.",
        "",
    ]
    generated_text = "\n".join(header) + "\n".join(sorted(domains)) + "\n"
    generated_sha256 = hashlib.sha256(generated_text.encode("utf-8")).hexdigest()
    output_path.write_text(generated_text, encoding="utf-8", newline="\n")

    notice_lines = [
        "EasyPi Adult Domain Feed - Third-Party Notice",
        "",
        "The domain data is downloaded and generated on the end user's device.",
        "It is not included in EasyPi source archives or release packages.",
        "EasyPi does not claim ownership of this third-party domain data.",
        "",
        f"Source: {SOURCE_NAME}",
        f"Homepage: {SOURCE_HOMEPAGE}",
        f"Downloaded from: {SOURCE_URL}",
        f"License file: {LICENSE_URL}",
        "",
        "The generated source file declares MIT in its header, while the",
        "repository LICENSE currently contains the Unlicense. EasyPi preserves",
        "both upstream notices and applies the more conservative notice handling.",
        "",
        "Preserved source header:",
        *source_headers,
        "",
    ]
    notice_output_path.write_text("\n".join(notice_lines), encoding="utf-8", newline="\n")
    license_output_path.write_bytes(license_payload)

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generated_at": generated_at,
        "distribution": "runtime-download-only",
        "source": {
            "name": SOURCE_NAME,
            "homepage": SOURCE_HOMEPAGE,
            "url": SOURCE_URL,
            "sha256": source_sha256,
            "declared_license": "MIT",
            "repository_license": "Unlicense",
            "license_url": LICENSE_URL,
            "license_sha256": license_sha256,
        },
        "domain_count": len(domains),
        "generated_sha256": generated_sha256,
    }
    manifest_output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--license", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--notice-output", type=Path, required=True)
    parser.add_argument("--license-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--expected-license-sha256", required=True)
    parser.add_argument("--min-domains", type=int, required=True)
    parser.add_argument("--max-domains", type=int, required=True)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    manifest = build_feed(
        source_path=args.source,
        license_path=args.license,
        output_path=args.output,
        notice_output_path=args.notice_output,
        license_output_path=args.license_output,
        manifest_output_path=args.manifest_output,
        expected_license_sha256=args.expected_license_sha256,
        min_domains=args.min_domains,
        max_domains=args.max_domains,
    )
    print(
        f"adult_domains.txt: {manifest['domain_count']} validated domains; "
        f"source_sha256={manifest['source']['sha256']}"
    )


if __name__ == "__main__":
    try:
        main()
    except (FeedValidationError, OSError) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
