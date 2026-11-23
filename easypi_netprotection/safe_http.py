"""Bounded HTTPS fetching for externally configured threat feeds."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import stat
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.request import url2pathname

import aiohttp
from aiohttp.abc import AbstractResolver


class _PinnedResolver(AbstractResolver):
    def __init__(self, addresses: list[tuple[str, int]]) -> None:
        self._addresses = addresses

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict]:
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": 0,
                "flags": 0,
            }
            for address, address_family in self._addresses
        ]

    async def close(self) -> None:
        return None


def validate_remote_url_syntax(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            "Feed URL must be HTTPS without credentials or a fragment"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Feed URL has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Feed URL has an invalid port")


async def _resolve_public(host: str, port: int) -> list[tuple[str, int]]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise ValueError("Feed hostname could not be resolved") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))

    if not addresses:
        raise ValueError("Feed hostname has no addresses")

    result: list[tuple[str, int]] = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Feed hostname resolves to a non-public address")
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        result.append((str(ip), family))
    return result


def _read_local_file(url: str, max_bytes: int, allowed_root: Path) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise ValueError("Invalid local feed URL")
    try:
        root = allowed_root.resolve(strict=True)
        source = Path(url2pathname(parsed.path))
        if source.is_symlink():
            raise ValueError("Local feed must not be a symbolic link")
        path = source.resolve(strict=True)
        if os.path.commonpath((str(root), str(path))) != str(root):
            raise ValueError(
                "Local feed must stay inside the custom feed directory"
            )
    except OSError as exc:
        raise ValueError("Local feed could not be opened") from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Local feed could not be opened") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("Local feed must be a regular file")
        if details.st_size > max_bytes:
            raise ValueError("Local feed exceeds the size limit")
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="ignore") as stream:
            descriptor = -1
            contents = stream.read(max_bytes + 1)
            if len(contents.encode("utf-8")) > max_bytes:
                raise ValueError("Local feed exceeds the size limit")
            return contents
    finally:
        if descriptor >= 0:
            os.close(descriptor)


async def fetch_text(
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    allowed_file_root: Path | None = None,
    max_redirects: int = 3,
) -> str:
    if max_bytes <= 0:
        raise ValueError("Download size limit must be positive")
    if url.startswith("file:"):
        if allowed_file_root is None:
            raise ValueError("Local feed URLs are not allowed")
        return _read_local_file(url, max_bytes, allowed_file_root)

    current_url = url
    for redirect_count in range(max_redirects + 1):
        try:
            validate_remote_url_syntax(current_url)
            parsed = urlsplit(current_url)
            port = parsed.port or 443
            addresses = await _resolve_public(parsed.hostname or "", port)
            resolver = _PinnedResolver(addresses)
            connector = aiohttp.TCPConnector(
                resolver=resolver,
                use_dns_cache=False,
                ssl=True,
            )
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=False,
                headers={"User-Agent": "EasyPi-NetProtection/1"},
            ) as session:
                async with session.get(
                    current_url, allow_redirects=False
                ) as response:
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location or redirect_count >= max_redirects:
                            raise ValueError("Feed redirect limit exceeded")
                        current_url = urljoin(current_url, location)
                        continue
                    if response.status != 200:
                        raise ValueError(f"Feed returned HTTP {response.status}")
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            declared_size = int(content_length)
                        except ValueError as exc:
                            raise ValueError(
                                "Feed returned an invalid Content-Length"
                            ) from exc
                        if declared_size < 0 or declared_size > max_bytes:
                            raise ValueError("Feed exceeds the size limit")

                    chunks: list[bytes] = []
                    received = 0
                    async for chunk in response.content.iter_chunked(64 * 1024):
                        received += len(chunk)
                        if received > max_bytes:
                            raise ValueError("Feed exceeds the size limit")
                        chunks.append(chunk)
                    return b"".join(chunks).decode(
                        "utf-8", errors="ignore"
                    )
        except ValueError:
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
            raise ValueError("Feed download failed") from exc

    raise ValueError("Feed redirect limit exceeded")
