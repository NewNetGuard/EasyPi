"""Loopback-only DNS forwarder whose process is routed through Chameleon.

Linux policy routing marks this service account independently from the main
NetProtection process.  The proxy has no direct fallback: an unavailable
tunnel produces DNS failure for protected devices.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import socket


LOGGER = logging.getLogger(__name__)
MAX_DNS_MESSAGE = 4096


def _upstreams() -> tuple[str, ...]:
    raw = os.getenv("EASYPI_STEALTH_DNS_UPSTREAMS", "1.1.1.1,9.9.9.9")
    result: list[str] = []
    for value in raw.split(","):
        candidate = value.strip()
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and address.is_global and candidate not in result:
            result.append(candidate)
    if not result:
        raise RuntimeError("no valid public IPv4 DNS upstream configured")
    return tuple(result[:4])


async def _query_tcp(data: bytes, host: str, timeout: float) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 53, family=socket.AF_INET), timeout=timeout
    )
    try:
        writer.write(len(data).to_bytes(2, "big") + data)
        await writer.drain()
        size = int.from_bytes(
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout), "big"
        )
        if not 12 <= size <= 65535:
            raise ValueError("invalid upstream DNS response size")
        response = await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
        if response[:2] != data[:2]:
            raise ValueError("upstream DNS transaction ID mismatch")
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _query(
    data: bytes, upstreams: tuple[str, ...], timeout: float
) -> bytes | None:
    loop = asyncio.get_running_loop()
    for host in upstreams:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, data, (host, 53))
            response, peer = await asyncio.wait_for(
                loop.sock_recvfrom(sock, MAX_DNS_MESSAGE), timeout=timeout
            )
            if peer[0] != host or len(response) < 12 or response[:2] != data[:2]:
                continue
            if int.from_bytes(response[2:4], "big") & 0x0200:
                return await _query_tcp(data, host, timeout)
            return response
        except (OSError, TimeoutError, asyncio.TimeoutError, ValueError):
            continue
        finally:
            sock.close()
    return None


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, upstreams: tuple[str, ...], timeout: float) -> None:
        self.upstreams = upstreams
        self.timeout = timeout
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if 12 <= len(data) <= MAX_DNS_MESSAGE:
            asyncio.create_task(self._reply(data, address))

    async def _reply(self, data: bytes, address: tuple[str, int]) -> None:
        response = await _query(data, self.upstreams, self.timeout)
        if response and self.transport:
            self.transport.sendto(response, address)


async def _handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstreams: tuple[str, ...],
    timeout: float,
) -> None:
    try:
        size = int.from_bytes(await reader.readexactly(2), "big")
        if not 12 <= size <= MAX_DNS_MESSAGE:
            return
        data = await reader.readexactly(size)
        response = await _query(data, upstreams, timeout)
        if response:
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError, TimeoutError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def run() -> None:
    host = os.getenv("EASYPI_STEALTH_DNS_HOST", "127.0.0.1")
    if host != "127.0.0.1":
        raise RuntimeError("stealth DNS proxy must remain loopback-only")
    port = int(os.getenv("EASYPI_STEALTH_DNS_PORT", "5455"))
    if not 1024 <= port <= 65535:
        raise RuntimeError("invalid stealth DNS proxy port")
    timeout = min(10.0, max(0.25, float(os.getenv("EASYPI_STEALTH_DNS_TIMEOUT", "3"))))
    upstreams = _upstreams()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPProtocol(upstreams, timeout), local_addr=(host, port)
    )
    tcp_server = await asyncio.start_server(
        lambda r, w: _handle_tcp(r, w, upstreams, timeout), host, port
    )
    LOGGER.info("Chameleon DNS proxy listening on loopback port %d", port)
    try:
        await stop.wait()
    finally:
        udp_transport.close()
        tcp_server.close()
        await tcp_server.wait_closed()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
