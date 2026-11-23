"""
EasyPi NetProtection - Async DNS Resolver

High-performance DNS resolver with caching, DNSSEC validation,
and integration with the Verdict Pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Awaitable

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.flags

from ..config import get_settings
from .cache import DNSCache, get_dns_cache
from .upstream import UpstreamPool, get_upstream_pool


if TYPE_CHECKING:
    from ..vault.models import Verdict


logger = logging.getLogger(__name__)


@dataclass
class DNSQuestion:
    """Parsed DNS question from incoming request."""
    
    name: str
    rdtype: str
    rdclass: str = "IN"
    
    @classmethod
    def from_wire(cls, data: bytes) -> tuple["DNSQuestion", bytes]:
        """Parse DNS question from wire format."""
        msg = dns.message.from_wire(data)
        if not msg.question:
            raise ValueError("No question in DNS message")
        
        q = msg.question[0]
        return cls(
            name=str(q.name).rstrip("."),
            rdtype=dns.rdatatype.to_text(q.rdtype),
            rdclass=dns.rdataclass.to_text(q.rdclass),
        ), msg.id.to_bytes(2, "big")


@dataclass
class DNSResponse:
    """DNS response ready for wire format."""
    
    domain: str
    query_type: str
    response_code: str
    answers: list[dict]
    ttl: int
    is_blocked: bool = False
    block_reason: str | None = None
    redirect_ip: str | None = None
    upstream: str | None = None
    latency_ms: float = 0.0
    from_cache: bool = False
    dnssec_validated: bool = False
    cname_chain: list[str] = field(default_factory=list)
    
    def to_wire(self, query_id: bytes, query_data: bytes) -> bytes:
        """Convert response to DNS wire format."""
        # Parse original query to get proper structure
        query_msg = dns.message.from_wire(query_data)
        
        # Create response message
        response = dns.message.make_response(query_msg)
        
        if self.is_blocked:
            if self.redirect_ip:
                # Redirect to specified IP
                response.set_rcode(dns.rcode.NOERROR)
                rrset = response.find_rrset(
                    response.answer,
                    dns.name.from_text(self.domain + "."),
                    dns.rdataclass.IN,
                    dns.rdatatype.A,
                    create=True,
                )
                rrset.add(
                    dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.A,
                        self.redirect_ip,
                    ),
                    self.ttl,
                )
            else:
                # Block with NXDOMAIN
                response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            # Normal response
            rcode = dns.rcode.from_text(self.response_code)
            response.set_rcode(rcode)
            
            for answer in self.answers:
                try:
                    rdtype = dns.rdatatype.from_text(answer["type"])
                    rrset = response.find_rrset(
                        response.answer,
                        dns.name.from_text(answer["name"]),
                        dns.rdataclass.IN,
                        rdtype,
                        create=True,
                    )
                    rrset.add(
                        dns.rdata.from_text(
                            dns.rdataclass.IN,
                            rdtype,
                            answer["data"],
                        ),
                        answer.get("ttl", self.ttl),
                    )
                except Exception as e:
                    logger.warning(f"Failed to add answer record: {e}")
        
        # Set flags
        if self.dnssec_validated:
            response.flags |= dns.flags.AD
        
        return response.to_wire()


@dataclass
class FlowContext:
    """Context for a single DNS flow through the resolver."""
    
    flow_id: str
    client_ip: str
    client_port: int
    question: DNSQuestion
    client_mac: str | None = None
    timestamp: float = field(default_factory=time.time)
    protocol: str = "udp"
    verdict: "Verdict | None" = None
    response: DNSResponse | None = None
    processing_time_ms: float = 0.0


# Type alias for verdict callback
VerdictCallback = Callable[[FlowContext], Awaitable["Verdict"]]


class DNSResolver:
    """
    Asynchronous DNS resolver with Verdict Pipeline integration.
    
    Flow:
    1. Receive DNS query
    2. Check cache
    3. If not cached, invoke Verdict Pipeline
    4. Based on verdict: allow (forward), deny (block), redirect, observe
    5. Cache result
    6. Return response
    """
    
    def __init__(
        self,
        verdict_callback: VerdictCallback | None = None,
        cache: DNSCache | None = None,
        upstream: UpstreamPool | None = None,
    ):
        self.settings = get_settings()
        self.cache = cache or get_dns_cache()
        self.upstream = upstream or get_upstream_pool()
        self._verdict_callback = verdict_callback
        
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._running = False
        
        # Statistics
        self._total_queries = 0
        self._cache_hits = 0
        self._blocked_queries = 0
        self._failed_queries = 0
    
    async def start(self) -> None:
        """Start the DNS resolver server."""
        if self._running:
            return
        
        await self.upstream.start()
        
        loop = asyncio.get_event_loop()
        
        # Start UDP listener
        listen_addr = self.settings.listener.address
        listen_port = self.settings.listener.port
        
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPServerProtocol(self),
            local_addr=(listen_addr, listen_port),
        )
        
        # Start TCP listener
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_connection,
            listen_addr,
            listen_port,
        )
        
        self._running = True
        logger.info(f"DNS Resolver started on {listen_addr}:{listen_port}")
    
    async def stop(self) -> None:
        """Stop the DNS resolver server."""
        self._running = False
        
        if self._udp_transport:
            self._udp_transport.close()
        
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        
        await self.upstream.stop()
        logger.info("DNS Resolver stopped")
    
    def set_verdict_callback(self, callback: VerdictCallback) -> None:
        """Set the verdict pipeline callback."""
        self._verdict_callback = callback
    
    async def resolve(self, ctx: FlowContext) -> DNSResponse:
        """
        Resolve a DNS query through the Verdict Pipeline.
        
        This is the main entry point for processing DNS queries.
        """
        start_time = time.monotonic()
        self._total_queries += 1
        
        try:
            # Step 1: Check cache
            cache_key = f"{ctx.question.name}:{ctx.question.rdtype}"
            cached = await self.cache.get(cache_key)
            
            if cached is not None:
                self._cache_hits += 1
                response = DNSResponse(
                    domain=ctx.question.name,
                    query_type=ctx.question.rdtype,
                    response_code=cached.get("response_code", "NOERROR"),
                    answers=cached.get("answers", []),
                    ttl=cached.get("ttl", 300),
                    from_cache=True,
                    cname_chain=cached.get("cname_chain", []),
                    dnssec_validated=cached.get("dnssec_validated", False),
                )
                ctx.response = response
                return response
            
            # Step 2: Invoke Verdict Pipeline (if callback set)
            if self._verdict_callback:
                verdict = await self._verdict_callback(ctx)
                ctx.verdict = verdict
                
                # Handle verdict
                if verdict.action == "deny":
                    self._blocked_queries += 1
                    response = DNSResponse(
                        domain=ctx.question.name,
                        query_type=ctx.question.rdtype,
                        response_code="NXDOMAIN",
                        answers=[],
                        ttl=60,
                        is_blocked=True,
                        block_reason=self._format_block_reason(verdict),
                    )
                    ctx.response = response
                    return response
                
                elif verdict.action == "redirect":
                    self._blocked_queries += 1
                    redirect_ip = verdict.redirect_target or "0.0.0.0"
                    response = DNSResponse(
                        domain=ctx.question.name,
                        query_type=ctx.question.rdtype,
                        response_code="NOERROR",
                        answers=[{
                            "name": ctx.question.name + ".",
                            "type": "A",
                            "ttl": 60,
                            "data": redirect_ip,
                        }],
                        ttl=60,
                        is_blocked=True,
                        block_reason=self._format_block_reason(verdict),
                        redirect_ip=redirect_ip,
                    )
                    ctx.response = response
                    return response
            
            # Step 3: Forward to upstream
            upstream_result = await self.upstream.query(
                ctx.question.name,
                ctx.question.rdtype,
            )
            
            # Step 4: Build response
            response = DNSResponse(
                domain=ctx.question.name,
                query_type=ctx.question.rdtype,
                response_code=upstream_result.get("response_code", "NOERROR"),
                answers=upstream_result.get("answers", []),
                ttl=upstream_result.get("ttl", 300),
                upstream=upstream_result.get("upstream"),
                latency_ms=upstream_result.get("latency_ms", 0),
                cname_chain=upstream_result.get("cname_chain", []),
                dnssec_validated=upstream_result.get("dnssec_validated", False),
            )
            
            # Step 5: Cache the result
            if not upstream_result.get("is_negative"):
                await self.cache.set(cache_key, upstream_result)
            else:
                # Cache negative results with shorter TTL
                await self.cache.set_negative(cache_key)
            
            ctx.response = response
            return response
            
        except Exception as e:
            self._failed_queries += 1
            logger.error(f"Resolution failed for {ctx.question.name}: {e}")
            
            # Return SERVFAIL on error
            return DNSResponse(
                domain=ctx.question.name,
                query_type=ctx.question.rdtype,
                response_code="SERVFAIL",
                answers=[],
                ttl=0,
            )
        
        finally:
            ctx.processing_time_ms = (time.monotonic() - start_time) * 1000
    
    def _format_block_reason(self, verdict: "Verdict") -> str:
        """Format block reason from verdict evidence."""
        if verdict.evidence:
            reasons = [e.signal for e in verdict.evidence[:3]]
            return "; ".join(reasons)
        return "Blocked by policy"
    
    async def _handle_udp_query(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> bytes:
        """Handle incoming UDP DNS query."""
        try:
            # Validate packet size
            if len(data) < 12:  # Minimum DNS header size
                logger.warning(f"Packet too small from {addr}: {len(data)} bytes")
                return self._build_servfail(data)
            
            if len(data) > 4096:  # Max EDNS UDP size
                logger.warning(f"Packet too large from {addr}: {len(data)} bytes")
                return self._build_servfail(data)
            
            question, query_id = DNSQuestion.from_wire(data)
            
            # Validate domain name length
            if len(question.name) > 253:
                logger.warning(f"Domain too long from {addr}: {len(question.name)}")
                return self._build_servfail(data)
            
            ctx = FlowContext(
                flow_id=self._generate_flow_id(),
                client_ip=addr[0],
                client_port=addr[1],
                question=question,
                protocol="udp",
            )
            
            response = await self.resolve(ctx)
            return response.to_wire(query_id, data)
            
        except Exception as e:
            logger.error(f"UDP query handling failed: {e}")
            return self._build_servfail(data)
    
    async def _handle_tcp_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming TCP DNS connection."""
        addr = writer.get_extra_info("peername")
        
        # Limit queries per connection to prevent abuse
        max_queries = 100
        query_count = 0
        
        try:
            while query_count < max_queries:
                # Read 2-byte length prefix
                length_data = await asyncio.wait_for(
                    reader.readexactly(2),
                    timeout=30.0,
                )
                query_length = struct.unpack("!H", length_data)[0]
                
                # Validate query length
                if query_length < 12 or query_length > 65535:
                    logger.warning(f"Invalid query length from {addr}: {query_length}")
                    break
                
                # Read query
                query_data = await asyncio.wait_for(
                    reader.readexactly(query_length),
                    timeout=30.0,
                )
                
                question, query_id = DNSQuestion.from_wire(query_data)
                
                # Validate domain name
                if len(question.name) > 253:
                    logger.warning(f"Domain too long from {addr}: {len(question.name)}")
                    continue
                
                query_count += 1
                
                ctx = FlowContext(
                    flow_id=self._generate_flow_id(),
                    client_ip=addr[0],
                    client_port=addr[1],
                    question=question,
                    protocol="tcp",
                )
                
                response = await self.resolve(ctx)
                response_wire = response.to_wire(query_id, query_data)
                
                # Write response with length prefix
                writer.write(struct.pack("!H", len(response_wire)))
                writer.write(response_wire)
                await writer.drain()
                
        except asyncio.TimeoutError:
            pass  # Connection timeout, normal
        except asyncio.IncompleteReadError:
            pass  # Client disconnected
        except Exception as e:
            logger.error(f"TCP connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _generate_flow_id(self) -> str:
        """Generate unique flow ID."""
        import secrets
        return f"fl_{secrets.token_hex(4)}"
    
    def _build_servfail(self, query_data: bytes) -> bytes:
        """Build SERVFAIL response for error cases."""
        try:
            query = dns.message.from_wire(query_data)
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            return response.to_wire()
        except Exception:
            # Return minimal SERVFAIL if parsing fails
            return b"\x00\x00\x80\x02\x00\x00\x00\x00\x00\x00\x00\x00"
    
    def get_stats(self) -> dict:
        """Get resolver statistics."""
        cache_stats = self.cache.get_stats()
        upstream_stats = self.upstream.get_stats()
        
        return {
            "total_queries": self._total_queries,
            "cache_hits": self._cache_hits,
            "cache_hit_ratio": (
                self._cache_hits / self._total_queries
                if self._total_queries > 0 else 0.0
            ),
            "blocked_queries": self._blocked_queries,
            "failed_queries": self._failed_queries,
            "cache": cache_stats.__dict__,
            "upstreams": upstream_stats,
        }


class _UDPServerProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS server."""
    
    def __init__(self, resolver: DNSResolver):
        self.resolver = resolver
        self.transport: asyncio.DatagramTransport | None = None
    
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._handle_query(data, addr))
    
    async def _handle_query(self, data: bytes, addr: tuple[str, int]) -> None:
        response = await self.resolver._handle_udp_query(data, addr)
        if self.transport:
            self.transport.sendto(response, addr)


# Singleton instance
_resolver: DNSResolver | None = None


def get_resolver() -> DNSResolver:
    """Get cached resolver instance."""
    global _resolver
    if _resolver is None:
        _resolver = DNSResolver()
    return _resolver
