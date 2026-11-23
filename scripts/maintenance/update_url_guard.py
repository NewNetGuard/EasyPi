#!/usr/bin/env python3
"""Validate and resolve one HTTPS update hop without trusting redirect targets."""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_URL_LENGTH = 8192
MAX_HEADER_BYTES = 128 * 1024


class UrlGuardError(ValueError):
    """The URL or redirect response violates the updater network policy."""


@dataclass(frozen=True)
class ResolvedHop:
    url: str
    host: str
    port: int
    address: str


Resolver = Callable[..., Iterable[tuple]]


def _normalized_host(raw_host: str) -> str:
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UrlGuardError("URL hostname is not valid IDNA") from exc
    if not host or host.endswith("."):
        raise UrlGuardError("URL hostname must be absolute without a trailing dot")
    return host


def resolve_public_https_url(
    url: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> ResolvedHop:
    """Normalize an HTTPS URL, require public DNS answers, and choose one pinned IP."""

    if not url or len(url) > MAX_URL_LENGTH:
        raise UrlGuardError("URL is empty or too long")
    if any(character.isspace() or ord(character) < 0x20 for character in url):
        raise UrlGuardError("URL contains whitespace or control characters")
    if "\\" in url:
        raise UrlGuardError("URL contains a backslash")

    try:
        parsed = urlsplit(url)
        raw_host = parsed.hostname
        port = parsed.port or 443
    except ValueError as exc:
        raise UrlGuardError(str(exc)) from exc

    if parsed.scheme.lower() != "https" or not raw_host:
        raise UrlGuardError("URL must use HTTPS and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise UrlGuardError("URL userinfo is not allowed")
    if parsed.fragment:
        raise UrlGuardError("URL fragments are not allowed")
    if not 1 <= port <= 65535:
        raise UrlGuardError("URL port is outside the valid range")

    host = _normalized_host(raw_host)
    try:
        results = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UrlGuardError(f"URL hostname resolution failed: {exc}") from exc

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for result in results:
        try:
            address = ipaddress.ip_address(result[4][0])
        except (IndexError, TypeError, ValueError) as exc:
            raise UrlGuardError("URL resolution returned an invalid address") from exc
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise UrlGuardError("URL hostname did not resolve")
    if any(not address.is_global for address in addresses):
        raise UrlGuardError("URL hostname resolves to a non-public address")

    addresses.sort(key=lambda address: (address.version != 4, str(address)))
    url_host = f"[{host}]" if ":" in host else host
    netloc = url_host if port == 443 else f"{url_host}:{port}"
    normalized = urlunsplit(
        ("https", netloc, parsed.path or "/", parsed.query, "")
    )
    return ResolvedHop(
        url=normalized,
        host=host,
        port=port,
        address=str(addresses[0]),
    )


def redirect_target(base_url: str, raw_headers: bytes) -> str:
    """Return the single Location target from the last HTTP response header block."""

    if not raw_headers or len(raw_headers) > MAX_HEADER_BYTES:
        raise UrlGuardError("Redirect response headers are empty or too large")
    text = raw_headers.decode("iso-8859-1")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks = [
        block
        for block in re.split(r"\n\n+", text)
        if block.startswith("HTTP/")
    ]
    if not blocks:
        raise UrlGuardError("Redirect response has no HTTP status block")

    locations: list[str] = []
    for line in blocks[-1].splitlines()[1:]:
        if line.startswith((" ", "\t")):
            raise UrlGuardError("Folded redirect headers are not accepted")
        name, separator, value = line.partition(":")
        if separator and name.lower() == "location":
            locations.append(value.strip())

    if len(locations) != 1 or not locations[0]:
        raise UrlGuardError("Redirect response must contain exactly one Location")

    location = locations[0]
    if (
        len(location) > MAX_URL_LENGTH
        or "\\" in location
        or any(character.isspace() or ord(character) < 0x20 for character in location)
    ):
        raise UrlGuardError("Redirect Location contains unsafe characters")

    target = urljoin(base_url, location)
    parsed_target = urlsplit(target)
    if parsed_target.scheme.lower() != "https":
        raise UrlGuardError("Redirect target must use HTTPS")
    return target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    resolve_parser = subparsers.add_parser("resolve")
    resolve_parser.add_argument("url")
    redirect_parser = subparsers.add_parser("redirect")
    redirect_parser.add_argument("base_url")
    redirect_parser.add_argument("header_file", type=Path)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        if args.command == "resolve":
            hop = resolve_public_https_url(args.url)
            print(hop.url)
            print(hop.host)
            print(hop.port)
            print(hop.address)
        else:
            header_file: Path = args.header_file
            if not header_file.is_file() or header_file.is_symlink():
                raise UrlGuardError("Redirect header path is not a regular file")
            print(redirect_target(args.base_url, header_file.read_bytes()))
    except (OSError, UrlGuardError) as exc:
        print(f"[ERROR] {exc}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
