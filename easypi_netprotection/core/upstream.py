from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import dns.message
import dns.rdatatype
import httpx

from ..config import get_settings


logger = logging.getLogger(__name__)


class UpstreamProtocol(str, Enum):
    """Supported upstream DNS protocols."""
    
    UDP = "udp"
    TCP = "tcp"
    DOH = "doh"      # DNS over HTTPS
    DOT = "dot"      # DNS over TLS
    DOQ = "doq"      # DNS over QUIC


@dataclass
class UpstreamHealth:
    """Health status for an upstream server."""
    
    is_healthy: bool = True
    consecutive_failures: int = 0
    last_success: float | None = None
    last_failure: float | None = None
    last_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    total_queries: int = 0
    failed_queries: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.total_queries == 0:
            return 1.0
        return (self.total_queries - self.failed_queries) / self.total_queries


@dataclass 
class UpstreamServer:
    """Configuration for a single upstream DNS server."""
    
    url: str
    protocol: UpstreamProtocol = field(init=False)
    host: str = field(init=False)
    port: int = field(init=False)
    path: str = field(init=False, default="/dns-query")
    health: UpstreamHealth = field(default_factory=UpstreamHealth)
    
    def __post_init__(self):
        self._parse_url()
    
    def _parse_url(self) -> None:
        """Parse upstream URL and determine protocol."""
        url = self.url.lower()
        
        if url.startswith("https://"):
            self.protocol = UpstreamProtocol.DOH
            parsed = urlparse(self.url)
            self.host = parsed.hostname or ""
            self.port = parsed.port or 443
            self.path = parsed.path or "/dns-query"
        
        elif url.startswith("tls://"):
            self.protocol = UpstreamProtocol.DOT
            rest = self.url[6:]  # Remove "tls://"
            if ":" in rest:
                self.host, port_str = rest.split(":", 1)
                self.port = int(port_str)
            else:
                self.host = rest
                self.port = 853
        
        elif url.startswith("quic://"):
            self.protocol = UpstreamProtocol.DOQ
            rest = self.url[7:]  # Remove "quic://"
            if ":" in rest:
                self.host, port_str = rest.split(":", 1)
                self.port = int(port_str)
            else:
                self.host = rest
                self.port = 853
        
        elif url.startswith("tcp://"):
            self.protocol = UpstreamProtocol.TCP
            rest = self.url[6:]
            if ":" in rest:
                self.host, port_str = rest.split(":", 1)
                self.port = int(port_str)
            else:
                self.host = rest
                self.port = 53
        
        else:
            # Plain UDP (e.g., "8.8.8.8" or "udp://8.8.8.8")
            self.protocol = UpstreamProtocol.UDP
            clean = url.replace("udp://", "")
            if ":" in clean:
                self.host, port_str = clean.split(":", 1)
                self.port = int(port_str)
            else:
                self.host = clean
                self.port = 53
    
    def record_success(self, latency_ms: float) -> None:
        """Record a successful query."""
        self.health.is_healthy = True
        self.health.consecutive_failures = 0
        self.health.last_success = time.monotonic()
        self.health.last_latency_ms = latency_ms
        self.health.total_queries += 1
        
        # Update rolling average
        if self.health.avg_latency_ms == 0:
            self.health.avg_latency_ms = latency_ms
        else:
            self.health.avg_latency_ms = (
                self.health.avg_latency_ms * 0.9 + latency_ms * 0.1
            )
    
    def record_failure(self) -> None:
        """Record a failed query."""
        self.health.consecutive_failures += 1
        self.health.last_failure = time.monotonic()
        self.health.total_queries += 1
        self.health.failed_queries += 1
        
        # Mark unhealthy after threshold
        if self.health.consecutive_failures >= 3:
            self.health.is_healthy = False


class UpstreamPool:
    """Pool of upstream DNS servers with load balancing and failover."""
    
    def __init__(self, servers: list[str] | None = None):
        settings = get_settings()
        server_urls = servers or settings.upstream.servers
        
        self.servers = [UpstreamServer(url) for url in server_urls]
        self.timeout_sec = settings.upstream.timeout_ms / 1000.0
        self.retry_count = settings.upstream.retry_count
        self.health_check_interval = settings.upstream.health_check_interval_sec
        
        self._http_client: httpx.AsyncClient | None = None
        self._health_task: asyncio.Task | None = None
        self._current_index = 0
    
    async def start(self) -> None:
        """Initialize the upstream pool."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=self.timeout_sec,
                http2=True,
                verify=True,
            )
        if self._health_task is None:
            self._health_task = asyncio.create_task(self._health_check_loop())
    
    async def stop(self) -> None:
        """Shutdown the upstream pool."""
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
            self._health_task = None
        
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def close(self) -> None:
        """Compatibility alias for shutdown callers."""
        await self.stop()

    def rotate_servers(self) -> UpstreamServer | None:
        """Rotate the preferred server for guardian recovery."""
        if not self.servers:
            return None
        self._current_index = (self._current_index + 1) % len(self.servers)
        return self.servers[self._current_index]

    async def reset(self) -> None:
        """Reset upstream client state and health counters."""
        await self.stop()
        self._current_index = 0
        for server in self.servers:
            server.health.is_healthy = True
            server.health.consecutive_failures = 0
            server.health.last_failure = None
        await self.start()
    
    def get_healthy_server(self) -> UpstreamServer | None:
        """Get the next healthy server using round-robin."""
        healthy = [s for s in self.servers if s.health.is_healthy]
        if not healthy:
            # Fallback: return server with lowest consecutive failures
            return min(self.servers, key=lambda s: s.health.consecutive_failures)
        
        # Round-robin among healthy servers
        self._current_index = (self._current_index + 1) % len(healthy)
        return healthy[self._current_index]
    
    def get_fastest_server(self) -> UpstreamServer | None:
        """Get the server with lowest average latency."""
        healthy = [s for s in self.servers if s.health.is_healthy]
        if not healthy:
            return self.get_healthy_server()
        
        return min(healthy, key=lambda s: s.health.avg_latency_ms)
    
    async def query_raw(
        self,
        wire_query: bytes,
        use_fastest: bool = False,
    ) -> bytes | None:
        """
        Send raw DNS query and return raw response bytes.
        
        This is critical for preserving CNAME chains - no parsing/reconstruction!
        Supports DoH, DoT, and plain UDP.
        """
        if self._http_client is None:
            await self.start()
        last_error: Exception | None = None
        tried_servers: set[str] = set()
        
        for attempt in range(self.retry_count + 1):
            server = (
                self.get_fastest_server() if use_fastest
                else self.get_healthy_server()
            )
            
            if server is None:
                logger.error("No upstream servers available")
                return None
            
            # Avoid retrying same failed server immediately
            if server.url in tried_servers and len(self.servers) > 1:
                other = [s for s in self.servers if s.url not in tried_servers]
                if other:
                    server = other[0]
            
            tried_servers.add(server.url)
            
            try:
                start_time = time.monotonic()
                result = await self._query_server_raw(server, wire_query)
                latency_ms = (time.monotonic() - start_time) * 1000
                
                if result:
                    server.record_success(latency_ms)
                    return result
                else:
                    server.record_failure()
                    
            except Exception as e:
                server.record_failure()
                last_error = e
                logger.warning(f"Upstream raw query failed: {server.url} - {e}")
        
        logger.error(f"All upstream queries failed: {last_error}")
        return None
    
    async def _query_server_raw(
        self,
        server: UpstreamServer,
        wire_query: bytes,
    ) -> bytes | None:
        """Query upstream and return raw wire format bytes."""
        if server.protocol == UpstreamProtocol.DOH:
            return await self._query_doh_raw(server, wire_query)
        elif server.protocol == UpstreamProtocol.DOT:
            return await self._query_dot_raw(server, wire_query)
        elif server.protocol == UpstreamProtocol.TCP:
            return await self._query_tcp_raw(server, wire_query)
        else:
            return await self._query_udp_raw(server, wire_query)
    
    async def _query_doh_raw(
        self,
        server: UpstreamServer,
        wire_query: bytes,
    ) -> bytes | None:
        """Query DoH and return raw wire format."""
        if self._http_client is None:
            raise RuntimeError("HTTP client not initialized")
        
        encoded = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode()
        url = f"https://{server.host}:{server.port}{server.path}"
        
        response = await self._http_client.get(
            url,
            params={"dns": encoded},
            headers={"Accept": "application/dns-message"},
        )
        response.raise_for_status()
        return response.content  # Already wire format!
    
    async def _query_dot_raw(
        self,
        server: UpstreamServer,
        wire_query: bytes,
    ) -> bytes | None:
        """Query DoT and return raw wire format."""
        ssl_context = ssl.create_default_context()
        length_prefix = len(wire_query).to_bytes(2, "big")
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server.host, server.port, ssl=ssl_context),
            timeout=self.timeout_sec,
        )
        
        try:
            writer.write(length_prefix + wire_query)
            await writer.drain()
            
            length_data = await asyncio.wait_for(
                reader.readexactly(2), timeout=self.timeout_sec
            )
            response_length = int.from_bytes(length_data, "big")
            
            return await asyncio.wait_for(
                reader.readexactly(response_length), timeout=self.timeout_sec
            )
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _query_tcp_raw(
        self,
        server: UpstreamServer,
        wire_query: bytes,
    ) -> bytes | None:
        """Query TCP and return raw wire format."""
        length_prefix = len(wire_query).to_bytes(2, "big")
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server.host, server.port),
            timeout=self.timeout_sec,
        )
        
        try:
            writer.write(length_prefix + wire_query)
            await writer.drain()
            
            length_data = await asyncio.wait_for(
                reader.readexactly(2), timeout=self.timeout_sec
            )
            response_length = int.from_bytes(length_data, "big")
            
            return await asyncio.wait_for(
                reader.readexactly(response_length), timeout=self.timeout_sec
            )
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _query_udp_raw(
        self,
        server: UpstreamServer,
        wire_query: bytes,
    ) -> bytes | None:
        """Query UDP and return raw wire format."""
        loop = asyncio.get_event_loop()
        sock = None
        
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            await loop.sock_sendto(sock, wire_query, (server.host, server.port))
            response_data, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 4096),
                timeout=self.timeout_sec
            )
            return response_data
        finally:
            if sock:
                sock.close()

    async def query(
        self,
        domain: str,
        rdtype: str = "A",
        use_fastest: bool = False,
    ) -> dict:
        """Send DNS query to upstream with automatic failover."""
        if self._http_client is None:
            await self.start()
        last_error: Exception | None = None
        tried_servers: set[str] = set()
        
        for attempt in range(self.retry_count + 1):
            server = (
                self.get_fastest_server() if use_fastest
                else self.get_healthy_server()
            )
            
            if server is None:
                raise RuntimeError("No upstream servers available")
            
            # Avoid retrying same failed server immediately
            if server.url in tried_servers and len(self.servers) > 1:
                other = [s for s in self.servers if s.url not in tried_servers]
                if other:
                    server = other[0]
            
            tried_servers.add(server.url)
            
            try:
                start_time = time.monotonic()
                result = await self._query_server(server, domain, rdtype)
                latency_ms = (time.monotonic() - start_time) * 1000
                
                server.record_success(latency_ms)
                result["upstream"] = server.url
                result["latency_ms"] = latency_ms
                return result
                
            except Exception as e:
                server.record_failure()
                last_error = e
                logger.warning(
                    f"Upstream query failed: {server.url} - {e}"
                )
        
        raise RuntimeError(
            f"All upstream queries failed after {self.retry_count + 1} attempts: {last_error}"
        )
    
    async def _query_server(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query a specific upstream server."""
        if server.protocol == UpstreamProtocol.DOH:
            return await self._query_doh(server, domain, rdtype)
        elif server.protocol == UpstreamProtocol.DOT:
            return await self._query_dot(server, domain, rdtype)
        elif server.protocol == UpstreamProtocol.DOQ:
            return await self._query_doq(server, domain, rdtype)
        elif server.protocol == UpstreamProtocol.TCP:
            return await self._query_tcp(server, domain, rdtype)
        else:
            return await self._query_udp(server, domain, rdtype)
    
    async def _query_doh(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query using DNS over HTTPS (RFC 8484)."""
        if self._http_client is None:
            raise RuntimeError("HTTP client not initialized")
        
        # Build DNS wire format query
        query = dns.message.make_query(domain, rdtype)
        wire_query = query.to_wire()
        
        # Base64url encode for GET method
        encoded = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode()
        
        url = f"https://{server.host}:{server.port}{server.path}"
        
        response = await self._http_client.get(
            url,
            params={"dns": encoded},
            headers={
                "Accept": "application/dns-message",
            },
        )
        response.raise_for_status()
        
        # Parse DNS response
        dns_response = dns.message.from_wire(response.content)
        return self._parse_dns_response(dns_response, domain, rdtype)
    
    async def _query_dot(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query using DNS over TLS (RFC 7858)."""
        ssl_context = ssl.create_default_context()
        
        query = dns.message.make_query(domain, rdtype)
        wire_query = query.to_wire()
        
        # Prepend 2-byte length prefix (TCP DNS format)
        length_prefix = len(wire_query).to_bytes(2, "big")
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                server.host,
                server.port,
                ssl=ssl_context,
            ),
            timeout=self.timeout_sec,
        )
        
        try:
            writer.write(length_prefix + wire_query)
            await writer.drain()
            
            # Read response length
            length_data = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=self.timeout_sec,
            )
            response_length = int.from_bytes(length_data, "big")
            
            # Read response
            response_data = await asyncio.wait_for(
                reader.readexactly(response_length),
                timeout=self.timeout_sec,
            )
            
            dns_response = dns.message.from_wire(response_data)
            return self._parse_dns_response(dns_response, domain, rdtype)
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _query_doq(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query using DNS over QUIC (RFC 9250)."""
        # DoQ requires aioquic library - fallback to DoT for now
        logger.warning(f"DoQ not fully implemented, falling back to DoT for {server.host}")
        
        # Create a temporary DoT server config
        dot_server = UpstreamServer(f"tls://{server.host}:{server.port}")
        return await self._query_dot(dot_server, domain, rdtype)
    
    async def _query_tcp(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query using plain TCP DNS."""
        query = dns.message.make_query(domain, rdtype)
        wire_query = query.to_wire()
        length_prefix = len(wire_query).to_bytes(2, "big")
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server.host, server.port),
            timeout=self.timeout_sec,
        )
        
        try:
            writer.write(length_prefix + wire_query)
            await writer.drain()
            
            length_data = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=self.timeout_sec,
            )
            response_length = int.from_bytes(length_data, "big")
            
            response_data = await asyncio.wait_for(
                reader.readexactly(response_length),
                timeout=self.timeout_sec,
            )
            
            dns_response = dns.message.from_wire(response_data)
            return self._parse_dns_response(dns_response, domain, rdtype)
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _query_udp(
        self,
        server: UpstreamServer,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Query using plain UDP DNS."""
        query = dns.message.make_query(domain, rdtype)
        wire_query = query.to_wire()
        
        loop = asyncio.get_event_loop()
        
        # Create UDP socket
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(),
            remote_addr=(server.host, server.port),
        )
        
        try:
            transport.sendto(wire_query)
            
            # Wait for response
            response_data = await asyncio.wait_for(
                protocol.response_future,
                timeout=self.timeout_sec,
            )
            
            dns_response = dns.message.from_wire(response_data)
            return self._parse_dns_response(dns_response, domain, rdtype)
            
        finally:
            transport.close()
    
    def _parse_dns_response(
        self,
        response: dns.message.Message,
        domain: str,
        rdtype: str,
    ) -> dict:
        """Parse dnspython response into our format."""
        answers = []
        min_ttl = 300  # Default TTL
        
        for rrset in response.answer:
            ttl = rrset.ttl
            if ttl < min_ttl:
                min_ttl = ttl
            
            for rdata in rrset:
                answers.append({
                    "name": str(rrset.name),
                    "type": dns.rdatatype.to_text(rrset.rdtype),
                    "ttl": ttl,
                    "data": str(rdata),
                })
        
        # Extract CNAME chain if present
        cname_chain = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for rdata in rrset:
                    cname_chain.append(str(rdata.target))
        
        # Response code
        rcode = dns.rcode.to_text(response.rcode())
        
        return {
            "domain": domain,
            "query_type": rdtype,
            "response_code": rcode,
            "answers": answers,
            "cname_chain": cname_chain,
            "ttl": min_ttl,
            "is_negative": rcode == "NXDOMAIN" or len(answers) == 0,
            "dnssec_validated": response.flags & dns.flags.AD != 0,
        }
    
    async def _health_check_loop(self) -> None:
        """Periodically check health of upstream servers."""
        while True:
            await asyncio.sleep(self.health_check_interval)
            
            for server in self.servers:
                if not server.health.is_healthy:
                    # Try to recover unhealthy servers
                    try:
                        await self._query_server(server, ".", "NS")
                        server.health.is_healthy = True
                        server.health.consecutive_failures = 0
                        logger.info(f"Upstream recovered: {server.url}")
                    except Exception:
                        pass  # Still unhealthy
    
    @property
    def all_healthy(self) -> bool:
        """Check if all servers are healthy."""
        return all(s.health.is_healthy for s in self.servers)
    
    @property
    def any_healthy(self) -> bool:
        """Check if any server is healthy."""
        return any(s.health.is_healthy for s in self.servers)
    
    def get_stats(self) -> list[dict]:
        """Get statistics for all servers."""
        return [
            {
                "url": s.url,
                "protocol": s.protocol.value,
                "is_healthy": s.health.is_healthy,
                "avg_latency_ms": round(s.health.avg_latency_ms, 2),
                "success_rate": round(s.health.success_rate, 4),
                "total_queries": s.health.total_queries,
            }
            for s in self.servers
        ]


class _UDPProtocol(asyncio.DatagramProtocol):
    """Simple UDP protocol for DNS queries."""
    
    def __init__(self):
        self.response_future: asyncio.Future = asyncio.get_event_loop().create_future()
    
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if not self.response_future.done():
            self.response_future.set_result(data)
    
    def error_received(self, exc: Exception) -> None:
        if not self.response_future.done():
            self.response_future.set_exception(exc)


# Singleton instance
_upstream_pool: UpstreamPool | None = None


def get_upstream_pool() -> UpstreamPool:
    """Get cached upstream pool instance."""
    global _upstream_pool
    if _upstream_pool is None:
        _upstream_pool = UpstreamPool()
    return _upstream_pool


# Alias for backward compatibility
UpstreamManager = UpstreamPool
