"""
EasyPi NetProtection — Main DNS Server.

Главный модуль, объединяющий все компоненты в единый DNS-сервер.
Поддерживает UDP, TCP, DoH, DoT, DoQ протоколы.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import signal
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from aiohttp import web

from .config import NetProtectionConfig, load_config
from .system.bootstrap import BootstrapContext, bootstrap_netprotection
from .system.guardian import Guardian, GuardianMode
from .core.resolver import DNSResolver
from .core.cache import DNSCache
from .core.upstream import UpstreamManager
from .verdict.engine import VerdictEngine
from .verdict.outcome import VerdictType, VerdictAction
from .chronicle.flow_log import (
    FLOW_REASON_PREFIX,
    FlowEntry,
    FlowLogger,
    FlowStatus,
    QueryType,
)
from .chronicle.metrics import NetProtectionMetrics
from .healthcheck import is_internal_resolver_healthcheck
from .stealth_dns_policy import NEED_MAC, ORDINARY, PROTECTED, StealthDNSPolicy

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

DNS_HEADER_SIZE = 12
MAX_UDP_SIZE = 512
MAX_EDNS_SIZE = 4096
TCP_LENGTH_PREFIX_SIZE = 2

DEFAULT_TTL_BLOCKED = 10  # TTL для заблокированных ответов (10 сек для быстрого разблокирования)
DEFAULT_NETPROTECTION_TLS_CERT = "/opt/EasyPi/certs/cert.pem"
DEFAULT_NETPROTECTION_TLS_KEY = "/opt/EasyPi/certs/key.pem"
DEFAULT_EASYPI_TLS_CERT = "/etc/ssl/certs/easypi-selfsigned.crt"
DEFAULT_EASYPI_TLS_KEY = "/etc/ssl/private/easypi-selfsigned.key"

# DoH client identification: the peer IP is the authoritative identity for
# per-device filtering. X-Forwarded-For / X-Real-IP are honored ONLY when the
# request arrives from one of these trusted proxy peers, so a direct LAN client
# cannot spoof another device's profile (and its parental filter) via a header.
DOH_TRUSTED_PROXIES = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
_doh_tp_env = os.environ.get("NETPROTECTION_TRUSTED_PROXIES", "").strip()
if _doh_tp_env:
    DOH_TRUSTED_PROXIES = DOH_TRUSTED_PROXIES | {
        p.strip() for p in _doh_tp_env.split(",") if p.strip()
    }


# ════════════════════════════════════════════════════════════════════════════════
# SERVER STATE
# ════════════════════════════════════════════════════════════════════════════════

class ServerState(Enum):
    """Состояние сервера."""
    
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"


@dataclass
class ServerStats:
    """Статистика сервера."""
    
    started_at: datetime | None = None
    total_queries: int = 0
    udp_queries: int = 0
    tcp_queries: int = 0
    doh_queries: int = 0
    dot_queries: int = 0
    doq_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    cache_hits: int = 0
    upstream_queries: int = 0
    errors: int = 0
    overload_drops: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": (datetime.now() - self.started_at).total_seconds() if self.started_at else 0,
            "total_queries": self.total_queries,
            "udp_queries": self.udp_queries,
            "tcp_queries": self.tcp_queries,
            "doh_queries": self.doh_queries,
            "dot_queries": self.dot_queries,
            "doq_queries": self.doq_queries,
            "blocked_queries": self.blocked_queries,
            "allowed_queries": self.allowed_queries,
            "cache_hits": self.cache_hits,
            "upstream_queries": self.upstream_queries,
            "errors": self.errors,
            "overload_drops": self.overload_drops,
        }


# ════════════════════════════════════════════════════════════════════════════════
# DNS PROTOCOL HANDLERS
# ════════════════════════════════════════════════════════════════════════════════

class UDPProtocol(asyncio.DatagramProtocol):
    """UDP протокол для DNS."""
    
    def __init__(self, server: "NetProtectionServer"):
        self._server = server
        self._transport: asyncio.DatagramTransport | None = None
        self._queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
            maxsize=server._listener_limit("udp_queue_size", 2048)
        )
        self._workers: list[asyncio.Task[None]] = []
        self._pending_by_source: dict[str, int] = {}
    
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        self._workers = [
            asyncio.create_task(self._worker())
            for _ in range(self._server._listener_limit("udp_workers", 64))
        ]
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < DNS_HEADER_SIZE or len(data) > MAX_EDNS_SIZE:
            self._server._record_overload_drop("udp-invalid")
            return
        source = addr[0]
        pending = self._pending_by_source.get(source, 0)
        if pending >= self._server._listener_limit("max_client_queries", 64):
            self._server._record_overload_drop("udp-client")
            return
        try:
            self._queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            self._server._record_overload_drop("udp-queue")
            return
        self._pending_by_source[source] = pending + 1

    async def _worker(self) -> None:
        while True:
            data, addr = await self._queue.get()
            try:
                await self._handle_query(data, addr)
            finally:
                source = addr[0]
                remaining = self._pending_by_source.get(source, 1) - 1
                if remaining > 0:
                    self._pending_by_source[source] = remaining
                else:
                    self._pending_by_source.pop(source, None)
                self._queue.task_done()
    
    async def _handle_query(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            response = await self._server.handle_dns_query(data, addr, "udp")
            if response and self._transport:
                self._transport.sendto(response, addr)
        except Exception as e:
            logger.error(f"UDP handler error: {e}")
    
    def error_received(self, exc: Exception) -> None:
        logger.error(f"UDP error: {exc}")

    def connection_lost(self, exc: Exception | None) -> None:
        for worker in self._workers:
            worker.cancel()
        self._workers.clear()
        self._pending_by_source.clear()


class TCPClientHandler:
    """Обработчик TCP-соединения."""
    
    def __init__(
        self,
        server: "NetProtectionServer",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: str = "tcp",
        timeout_sec: float = 10.0,
    ):
        self._server = server
        self._reader = reader
        self._writer = writer
        self._protocol = protocol
        self._timeout_sec = timeout_sec
    
    async def handle(self) -> None:
        addr = self._writer.get_extra_info("peername")
        
        try:
            while True:
                # Читаем длину сообщения (2 байта) с таймаутом
                try:
                    length_data = await asyncio.wait_for(
                        self._reader.readexactly(TCP_LENGTH_PREFIX_SIZE),
                        timeout=self._timeout_sec
                    )
                except asyncio.TimeoutError:
                    break
                    
                length = struct.unpack("!H", length_data)[0]
                
                if length == 0 or length > MAX_EDNS_SIZE:
                    break
                
                # Читаем DNS-сообщение
                data = await asyncio.wait_for(
                    self._reader.readexactly(length),
                    timeout=self._timeout_sec
                )
                
                # Обрабатываем с таймаутом
                try:
                    response = await asyncio.wait_for(
                        self._server.handle_dns_query(data, addr, self._protocol),
                        timeout=self._timeout_sec
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"TCP query timeout for {addr}")
                    continue
                
                if response:
                    # Отправляем с префиксом длины
                    self._writer.write(struct.pack("!H", len(response)))
                    self._writer.write(response)
                    await self._writer.drain()
        
        except asyncio.IncompleteReadError:
            pass  # Клиент закрыл соединение
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass  # Клиент закрыл соединение  
        except Exception as e:
            logger.error(f"TCP handler error for {addr}: {e}")
        finally:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════════════════════
# MAIN SERVER
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class NetProtectionServer:
    """
    Главный DNS-сервер NetProtection.
    
    Объединяет все компоненты:
    - DNS Resolver (UDP/TCP/DoH/DoT/DoQ)
    - Verdict Engine (фильтрация)
    - Cache (кеширование)
    - Chronicle (логирование)
    - Guardian (мониторинг)
    """
    
    config: NetProtectionConfig
    context: BootstrapContext | None = None
    
    # Компоненты
    resolver: DNSResolver | None = None
    cache: DNSCache | None = None
    upstream: UpstreamManager | None = None
    verdict_engine: VerdictEngine | None = None
    flow_logger: FlowLogger | None = None
    metrics: NetProtectionMetrics | None = None
    guardian: Guardian | None = None
    
    # Состояние
    state: ServerState = ServerState.STOPPED
    stats: ServerStats = field(default_factory=ServerStats)
    
    # Транспорты
    _udp_transport: asyncio.DatagramTransport | None = None
    _tcp_server: asyncio.Server | None = None
    _dot_server: asyncio.Server | None = None
    _doh_runner: web.AppRunner | None = None
    _doh_site: web.TCPSite | None = None
    _shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    _stats_task: asyncio.Task | None = None
    _client_mac_cache: dict[str, tuple[str, float]] = field(default_factory=dict)
    _stealth_dns_policy: StealthDNSPolicy = field(default_factory=StealthDNSPolicy)
    _mac_cache_ttl_sec: float = 120.0
    _mac_negative_cache_ttl_sec: float = 2.0
    _active_queries: int = 0
    _active_connections: int = 0
    _active_queries_by_source: dict[str, int] = field(default_factory=dict)
    
    async def start(self) -> None:
        """Запуск сервера."""
        if self.state != ServerState.STOPPED:
            raise RuntimeError(f"Cannot start server in state {self.state}")
        
        self.state = ServerState.STARTING
        logger.info("Starting NetProtection server...")
        
        try:
            # Bootstrap всех компонентов
            await self._bootstrap()
            
            # Запуск слушателей
            await self._start_listeners()
            await self._start_encrypted_listeners()
            
            # Запуск Guardian
            if self.guardian:
                await self.guardian.start()
            
            # Запуск периодического логирования статистики
            self._stats_task = asyncio.create_task(self._periodic_stats_log())
            
            self.state = ServerState.RUNNING
            self.stats.started_at = datetime.now()
            
            logger.info(
                f"NetProtection server started on "
                f"{self.config.listen_address}:{self.config.listen_port}"
            )
        
        except Exception as e:
            self.state = ServerState.FAILED
            logger.error(f"Failed to start server: {e}")
            raise
    
    async def stop(self) -> None:
        """Остановка сервера."""
        if self.state not in (ServerState.RUNNING, ServerState.STARTING):
            return
        
        self.state = ServerState.STOPPING
        logger.info("Stopping NetProtection server...")
        
        try:
            # Останавливаем периодическое логирование
            if self._stats_task:
                self._stats_task.cancel()
                try:
                    await self._stats_task
                except asyncio.CancelledError:
                    pass
                self._stats_task = None
            
            # Останавливаем Guardian
            if self.guardian:
                await self.guardian.stop()
            
            # Закрываем слушателей
            await self._stop_encrypted_listeners()
            await self._stop_listeners()
            
            # Закрываем компоненты
            await self._shutdown_components()
            
            self.state = ServerState.STOPPED
            logger.info("NetProtection server stopped")
        
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            self.state = ServerState.FAILED
    
    async def wait_for_shutdown(self) -> None:
        """Ожидание сигнала завершения."""
        await self._shutdown_event.wait()
    
    def request_shutdown(self) -> None:
        """Запрос на завершение работы."""
        self._shutdown_event.set()
    
    # ─────────────────────────────────────────────────────────────────────────
    # DNS Query Handling
    # ─────────────────────────────────────────────────────────────────────────
    
    def _listener_limit(self, name: str, default: int) -> int:
        return int(getattr(self.config.listener, name, default))

    def _record_overload_drop(self, reason: str) -> None:
        self.stats.overload_drops += 1
        if self.stats.overload_drops == 1 or self.stats.overload_drops % 1000 == 0:
            logger.warning(
                "DNS overload drop (%s), total=%d",
                reason,
                self.stats.overload_drops,
            )

    def _try_admit_connection(self) -> bool:
        if self._active_connections >= self._listener_limit("max_connections", 256):
            self._record_overload_drop("connection")
            return False
        self._active_connections += 1
        return True

    def _release_connection(self) -> None:
        self._active_connections = max(0, self._active_connections - 1)

    async def handle_dns_query(
        self,
        data: bytes,
        client_addr: tuple[str, int],
        protocol: str,
    ) -> bytes | None:
        client_ip = client_addr[0]
        source_active = self._active_queries_by_source.get(client_ip, 0)
        if (
            self._active_queries >= self._listener_limit("max_concurrent_queries", 256)
            or source_active >= self._listener_limit("max_client_queries", 64)
        ):
            self._record_overload_drop(f"{protocol}-query")
            return self._make_error_response(data, dns.rcode.SERVFAIL)
        self._active_queries += 1
        self._active_queries_by_source[client_ip] = source_active + 1
        try:
            return await self._process_dns_query(data, client_addr, protocol)
        finally:
            self._active_queries = max(0, self._active_queries - 1)
            remaining = self._active_queries_by_source.get(client_ip, 1) - 1
            if remaining > 0:
                self._active_queries_by_source[client_ip] = remaining
            else:
                self._active_queries_by_source.pop(client_ip, None)

    async def _process_dns_query(
        self,
        data: bytes,
        client_addr: tuple[str, int],
        protocol: str,
    ) -> bytes | None:
        """
        Обработка DNS-запроса.
        
        Архитектура: Forward-First с Verdict Check
        1. Парсим запрос для получения домена
        2. Проверяем verdict (блоклист, профили и т.д.)
        3. Если DENY - возвращаем блокирующий ответ
        4. Если ALLOW - пробрасываем СЫРОЙ ответ от upstream (без пересборки!)
        """
        client_ip = client_addr[0]
        flow_id = self._generate_flow_id()
        start_time = datetime.now()
        
        try:
            # 1. Парсим запрос
            try:
                query = dns.message.from_wire(data)
            except Exception as e:
                self.stats.total_queries += 1
                self._update_protocol_stats(protocol)
                logger.warning(f"[{flow_id}] Invalid DNS query from {client_ip}: {e}")
                self.stats.errors += 1
                return self._make_error_response(data, dns.rcode.FORMERR)
            
            if not query.question:
                self.stats.total_queries += 1
                self._update_protocol_stats(protocol)
                return self._make_error_response(data, dns.rcode.FORMERR)
            
            question = query.question[0]
            domain = str(question.name).rstrip(".")
            qtype = question.rdtype
            qtype_str = dns.rdatatype.to_text(qtype)

            # The backend watchdog uses a reserved marker from loopback. Keep it
            # out of verdicts, first-seen/AI learning, the Query Log and all
            # user-facing/internal query counters while still exercising the
            # real upstream resolver path. The helper is strict about loopback,
            # so a LAN client cannot use this bypass.
            if is_internal_resolver_healthcheck(client_ip, domain):
                response_data = await self._direct_upstream_query(data, client_ip)
                if response_data:
                    return response_data
                return self._make_error_response(data, dns.rcode.SERVFAIL)

            self.stats.total_queries += 1
            self._update_protocol_stats(protocol)

            if self._is_safe_mode():
                self.stats.upstream_queries += 1
                response_data = await self._direct_upstream_query(data, client_ip)
                if response_data:
                    self.stats.allowed_queries += 1
                    return response_data
                self.stats.errors += 1
                return self._make_error_response(data, dns.rcode.SERVFAIL)
            
            # 2. Получаем verdict
            verdict = await self._get_verdict(domain, client_ip, qtype_str, flow_id)
            action = verdict.action if hasattr(verdict, 'action') else verdict.verdict_type
            
            # 3. Если DENY - блокируем
            if action == VerdictAction.DENY or action == VerdictType.DENY:
                self.stats.blocked_queries += 1
                logger.info(f"[{flow_id}] BLOCKED: {domain} ({verdict.reason.value if hasattr(verdict, 'reason') else 'blocklist'})")
                await self._log_flow(
                    flow_id, domain, qtype_str, client_ip, protocol,
                    FlowStatus.BLOCKED, verdict, start_time,
                )
                return self._make_blocked_response(query, verdict)
            
            # 3.5 Если REDIRECT - возвращаем rewrite ответ
            if action == VerdictAction.REDIRECT or action == VerdictType.REDIRECT:
                logger.info(f"[{flow_id}] REDIRECT: {domain} -> {verdict.redirect_target}")
                await self._log_flow(
                    flow_id, domain, qtype_str, client_ip, protocol,
                    FlowStatus.REDIRECTED, verdict, start_time,
                )
                return await self._make_redirect_response(query, verdict, client_ip)
            
            # 4. ALLOW - пробрасываем сырой ответ от upstream
            self.stats.allowed_queries += 1
            self.stats.upstream_queries += 1
            
            # Используем прямой проброс - без парсинга и пересборки!
            response_data = await self._direct_upstream_query(data, client_ip)
            
            if response_data:
                # 5. Post-resolution checks: CNAME uncloaking + IP/ASN matchers
                #    + DNS rebinding. Runs for EVERY answer, not only CNAMEs.
                post_verdict, resolved_ips = await self._check_post_resolution(
                    response_data, domain, flow_id, query
                )
                if post_verdict and post_verdict.action == VerdictAction.DENY:
                    self.stats.blocked_queries += 1
                    self.stats.allowed_queries -= 1
                    logger.info(f"[{flow_id}] POST-RESOLUTION BLOCKED: {domain}")
                    await self._log_flow(
                        flow_id, domain, qtype_str, client_ip, protocol,
                        FlowStatus.BLOCKED, post_verdict, start_time,
                    )
                    return self._make_blocked_response(query, post_verdict)

                await self._log_flow(
                    flow_id, domain, qtype_str, client_ip, protocol,
                    FlowStatus.UPSTREAM, verdict, start_time, response_ips=resolved_ips,
                )
                return response_data
            else:
                await self._log_flow(
                    flow_id, domain, qtype_str, client_ip, protocol,
                    FlowStatus.FAILED, verdict, start_time,
                )
                return self._make_error_response(data, dns.rcode.SERVFAIL)
        
        except Exception as e:
            logger.error(f"[{flow_id}] Error handling query: {e}", exc_info=True)
            self.stats.errors += 1
            return self._make_error_response(data, dns.rcode.SERVFAIL)
    
    async def _direct_upstream_query(
        self, data: bytes, client_ip: str = "127.0.0.1"
    ) -> bytes | None:
        """
        Прямой проброс DNS запроса к upstream.
        
        Использует upstream pool (DoH/DoT/UDP) и возвращает СЫРЫЕ байты!
        Это критично для корректной работы CNAME цепочек.
        """
        decision = self._stealth_dns_policy.classify(client_ip)
        if decision == NEED_MAC:
            # A cached MAC belongs to an earlier IP/MAC observation and cannot
            # authorize direct WAN DNS. Re-read the current neighbor tables for
            # every security decision; unresolved identity fails closed below.
            client_mac = await self._resolve_client_mac(client_ip, fresh=True)
            decision = self._stealth_dns_policy.classify(
                client_ip,
                client_mac,
                mac_lookup_complete=True,
            )
        if decision == PROTECTED:
            return await self._query_stealth_dns_proxy(data)
        if decision != ORDINARY:
            logger.warning(
                "Refusing direct DNS for client %s because its Stealth identity "
                "could not be determined",
                client_ip,
            )
            return None

        # Ordinary devices retain the existing resolver behavior. Protected
        # devices returned above and can never reach this direct fallback.
        if self.upstream:
            try:
                return await self.upstream.query_raw(data)
            except Exception as e:
                logger.warning(f"Upstream pool error: {e}, falling back to direct UDP")
        return await self._query_ordinary_udp_fallback(data)

    async def _query_ordinary_udp_fallback(self, data: bytes) -> bytes | None:
        """Preserve the legacy fallback for devices outside strict Stealth."""
        host = "8.8.8.8"
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, data, (host, 53))
            response_data, peer = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 4096), timeout=5.0
            )
            if peer != (host, 53) or len(response_data) < DNS_HEADER_SIZE:
                return None
            if response_data[:2] != data[:2]:
                return None
            return response_data
        except asyncio.TimeoutError:
            logger.warning("Fallback upstream timeout")
            return None
        except Exception as e:
            logger.error(f"Fallback upstream error: {e}")
            return None
        finally:
            sock.close()

    async def _query_stealth_dns_proxy(self, data: bytes) -> bytes | None:
        """Use the loopback-only resolver whose egress is pinned to cham0."""
        host = "127.0.0.1"
        try:
            port = int(os.getenv("EASYPI_STEALTH_DNS_PORT", "5455"))
        except ValueError:
            logger.error("Invalid Chameleon DNS resolver port")
            return None
        if not 1024 <= port <= 65535:
            logger.error("Chameleon DNS resolver port is outside the allowed range")
            return None
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, data, (host, port))
            response_data, peer = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 4096), timeout=5.0
            )
            if peer != (host, port) or len(response_data) < DNS_HEADER_SIZE:
                return None
            if response_data[:2] != data[:2]:
                return None
            return response_data
        except asyncio.TimeoutError:
            logger.warning("Chameleon DNS resolver timeout")
            return None
        except Exception as e:
            logger.error(f"Chameleon DNS resolver error: {e}")
            return None
        finally:
            sock.close()
    
    async def _check_post_resolution(
        self,
        response_data: bytes,
        domain: str,
        flow_id: str,
        original_query: dns.message.Message,
    ):
        """
        Post-resolution checks on the upstream answer.

        Parses the answer once to extract the CNAME chain and resolved IPs,
        then runs them through the verdict engine for:
          - CNAME uncloaking (when enabled)
          - IP / ASN matchers
          - DNS rebinding protection (public domain -> private IP)

        Runs for ALL answers that carry a CNAME chain or resolved IPs,
        not only those containing a CNAME.
        """
        try:
            response = dns.message.from_wire(response_data)

            # Извлекаем CNAME цепочку и IP адреса
            cname_chain = []
            resolved_ips = []

            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for rdata in rrset:
                        cname_chain.append(str(rdata.target).rstrip('.'))
                elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    for rdata in rrset:
                        resolved_ips.append(str(rdata))

            # Respect the CNAME-uncloak toggle: when disabled, skip CNAME-based
            # verdicts but still run IP matchers + rebinding protection.
            if not self.config.verdict.enable_cname_uncloak:
                cname_chain = []

            # Nothing to evaluate
            if not cname_chain and not resolved_ips:
                return None, resolved_ips

            if self.verdict_engine and hasattr(self.verdict_engine, 'evaluate_post_resolution'):
                post_verdict = await self.verdict_engine.evaluate_post_resolution(
                    flow_id=flow_id,
                    domain=domain,
                    resolved_ips=resolved_ips,
                    cname_chain=cname_chain,
                )
                return post_verdict, resolved_ips

            return None, resolved_ips

        except Exception as e:
            logger.debug(f"[{flow_id}] Post-resolution parse error: {e}")
            return None, []
    
    # ─────────────────────────────────────────────────────────────────────────
    # Private Methods
    # ─────────────────────────────────────────────────────────────────────────
    
    async def _bootstrap(self) -> None:
        """Инициализация компонентов."""
        # Native EasyPi keeps its established layout.  The hardened VPS
        # container supplies a dedicated persistent root so no runtime state is
        # written into the read-only application tree under /app.
        base_path = Path(__file__).parent.parent
        runtime_root_value = os.environ.get("NETPROTECTION_RUNTIME_ROOT", "").strip()
        runtime_root = Path(runtime_root_value) if runtime_root_value else None
        if runtime_root is not None and not runtime_root.is_absolute():
            raise RuntimeError("NETPROTECTION_RUNTIME_ROOT must be an absolute path")
        self.context = await bootstrap_netprotection(
            base_path,
            self.config,
            runtime_root=runtime_root,
        )
        
        # Связываем компоненты
        self.resolver = self.context.resolver
        self.cache = self.context.dns_cache
        self.upstream = self.context.upstream_manager
        self.verdict_engine = self.context.verdict_engine
        self.flow_logger = self.context.flow_logger
        self.metrics = self.context.metrics
        self.guardian = self.context.guardian
    
    async def _start_listeners(self) -> None:
        """Запуск сетевых слушателей."""
        loop = asyncio.get_event_loop()
        # Read from nested listener config
        addr = self.config.listener.address
        port = self.config.listener.port
        
        # UDP
        if self.config.listener.enable_udp:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UDPProtocol(self),
                local_addr=(addr, port),
            )
            self._udp_transport = transport
            logger.info(f"UDP listener started on {addr}:{port}")
        
        # TCP
        if self.config.listener.enable_tcp:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_connection,
                addr,
                port,
            )
            logger.info(f"TCP listener started on {addr}:{port}")
    
    async def _stop_listeners(self) -> None:
        """Остановка сетевых слушателей."""
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
        
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
        
        if self._dot_server:
            self._dot_server.close()
            await self._dot_server.wait_closed()
            self._dot_server = None
        
        if self._doh_runner:
            await self._doh_runner.cleanup()
            self._doh_runner = None
            self._doh_site = None
    
    async def _shutdown_components(self) -> None:
        """Завершение работы компонентов."""
        if self.flow_logger:
            await self._close_component(self.flow_logger)
        
        if self.cache:
            await self._close_component(self.cache)
        
        if self.upstream:
            await self._close_component(self.upstream)

    async def _close_component(self, component: Any) -> None:
        """Close or stop a component depending on its runtime contract."""
        close_method = getattr(component, "close", None)
        if callable(close_method):
            await close_method()
            return

        stop_method = getattr(component, "stop", None)
        if callable(stop_method):
            await stop_method()
    
    async def _handle_tcp_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Обработка TCP-соединения."""
        if not self._try_admit_connection():
            writer.close()
            await writer.wait_closed()
            return
        handler = TCPClientHandler(
            self,
            reader,
            writer,
            protocol="tcp",
            timeout_sec=self.config.listener.tcp_timeout_sec,
        )
        try:
            await handler.handle()
        finally:
            self._release_connection()

    async def _handle_dot_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Обработка DoT-соединения."""
        if not self._try_admit_connection():
            writer.close()
            await writer.wait_closed()
            return
        handler = TCPClientHandler(
            self,
            reader,
            writer,
            protocol="dot",
            timeout_sec=self.config.listener.tcp_timeout_sec,
        )
        try:
            await handler.handle()
        finally:
            self._release_connection()

    def _build_tls_context(self) -> ssl.SSLContext | None:
        """Create TLS context for DoH/DoT listeners."""
        cert_path = self.config.encrypted_dns.tls_cert_path
        key_path = self.config.encrypted_dns.tls_key_path
        candidates = [
            (cert_path, key_path),
            (DEFAULT_NETPROTECTION_TLS_CERT, DEFAULT_NETPROTECTION_TLS_KEY),
            (DEFAULT_EASYPI_TLS_CERT, DEFAULT_EASYPI_TLS_KEY),
        ]

        selected_paths: tuple[str, str] | None = None
        for candidate_cert, candidate_key in candidates:
            if not candidate_cert or not candidate_key:
                continue
            cert_candidate = Path(candidate_cert)
            key_candidate = Path(candidate_key)
            if (
                cert_candidate.exists()
                and key_candidate.exists()
                and os.access(cert_candidate, os.R_OK)
                and os.access(key_candidate, os.R_OK)
            ):
                selected_paths = (str(cert_candidate), str(key_candidate))
                break

        if selected_paths is None:
            if not cert_path or not key_path:
                logger.warning("TLS cert/key not configured for encrypted DNS listeners")
            else:
                logger.warning("TLS cert/key not found or not readable for encrypted DNS listeners")
            return None

        cert_path, key_path = selected_paths
        try:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            return ctx
        except Exception as e:
            logger.warning(f"Failed to load TLS cert/key: {e}")
            return None

    def _get_request_ip(self, request: web.Request) -> str:
        """Best-effort client IP for DoH requests.

        DoH on :8053 is reached directly by LAN clients, so the peer IP is the
        authoritative identity used for per-device filtering. Client-supplied
        X-Forwarded-For / X-Real-IP headers are trusted ONLY when the request
        arrives from a trusted proxy (e.g. a local reverse proxy); otherwise a
        device could spoof another client's profile and bypass parental controls.
        """
        peer = request.transport.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        if peer_ip in DOH_TRUSTED_PROXIES:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
            real_ip = request.headers.get("x-real-ip")
            if real_ip:
                return real_ip.strip()
        return peer_ip

    def _decode_doh_query(self, value: str) -> bytes:
        """Decode base64url DNS query parameter."""
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    @web.middleware
    async def _doh_admission_middleware(
        self,
        request: web.Request,
        handler: Any,
    ) -> web.StreamResponse:
        """Bound active direct-DoH requests before allocating query work."""
        if not self._try_admit_connection():
            return web.Response(
                status=503,
                text="DNS service temporarily at capacity",
                headers={"Retry-After": "1"},
            )
        try:
            return await handler(request)
        finally:
            self._release_connection()

    async def _handle_doh_request(self, request: web.Request) -> web.Response:
        """Handle DNS over HTTPS requests."""
        try:
            if request.method == "GET":
                dns_param = request.query.get("dns", "")
                if not dns_param:
                    return web.Response(status=400, text="Missing dns parameter")
                if len(dns_param) > (MAX_EDNS_SIZE * 4 // 3) + 8:
                    return web.Response(status=413, text="DNS query is too large")
                query_data = self._decode_doh_query(dns_param)
            elif request.method == "POST":
                query_data = await request.read()
                if not query_data:
                    return web.Response(status=400, text="Empty request body")
            else:
                return web.Response(status=405)
        except Exception:
            return web.Response(status=400, text="Invalid DNS query")

        client_ip = self._get_request_ip(request)
        response_data = await self.handle_dns_query(query_data, (client_ip, 0), "doh")
        if not response_data:
            return web.Response(status=502, text="Upstream failure")

        return web.Response(
            body=response_data,
            content_type="application/dns-message",
            headers={"Cache-Control": "no-store"},
        )

    async def _start_encrypted_listeners(self) -> None:
        """Start DoH/DoT listeners if enabled."""
        if not (
            self.config.encrypted_dns.dot_enabled
            or self.config.encrypted_dns.doh_enabled
        ):
            return

        tls_ctx = self._build_tls_context()
        if tls_ctx is None:
            return

        if self.config.encrypted_dns.dot_enabled:
            try:
                self._dot_server = await asyncio.start_server(
                    self._handle_dot_connection,
                    self.config.encrypted_dns.dot_address,
                    self.config.encrypted_dns.dot_port,
                    ssl=tls_ctx,
                )
                logger.info(
                    "DoT listener started on %s:%s",
                    self.config.encrypted_dns.dot_address,
                    self.config.encrypted_dns.dot_port,
                )
            except Exception as e:
                logger.warning(f"Failed to start DoT listener: {e}")

        if self.config.encrypted_dns.doh_enabled:
            try:
                app = web.Application(
                    middlewares=[self._doh_admission_middleware],
                    client_max_size=MAX_EDNS_SIZE,
                )
                app.router.add_route(
                    "*",
                    self.config.encrypted_dns.doh_path,
                    self._handle_doh_request,
                )
                self._doh_runner = web.AppRunner(app)
                await self._doh_runner.setup()
                self._doh_site = web.TCPSite(
                    self._doh_runner,
                    self.config.encrypted_dns.doh_address,
                    self.config.encrypted_dns.doh_port,
                    ssl_context=tls_ctx,
                )
                await self._doh_site.start()
                logger.info(
                    "DoH listener started on https://%s:%s%s",
                    self.config.encrypted_dns.doh_address,
                    self.config.encrypted_dns.doh_port,
                    self.config.encrypted_dns.doh_path,
                )
            except Exception as e:
                logger.warning(f"Failed to start DoH listener: {e}")

    async def _stop_encrypted_listeners(self) -> None:
        """Stop DoH/DoT listeners."""
        if self._dot_server:
            self._dot_server.close()
            await self._dot_server.wait_closed()
            self._dot_server = None

        if self._doh_runner:
            await self._doh_runner.cleanup()
            self._doh_runner = None
            self._doh_site = None
    
    def _generate_flow_id(self) -> str:
        """Генерация уникального ID потока."""
        import secrets
        return secrets.token_hex(4)
    
    def _update_protocol_stats(self, protocol: str) -> None:
        """Обновление статистики по протоколу."""
        if protocol == "udp":
            self.stats.udp_queries += 1
        elif protocol == "tcp":
            self.stats.tcp_queries += 1
        elif protocol == "doh":
            self.stats.doh_queries += 1
        elif protocol == "dot":
            self.stats.dot_queries += 1
        elif protocol == "doq":
            self.stats.doq_queries += 1
    
    async def _periodic_stats_log(self, interval: int = 300) -> None:
        """
        Периодическое логирование статистики.
        
        Args:
            interval: Интервал в секундах (по умолчанию 5 минут)
        """
        try:
            while True:
                await asyncio.sleep(interval)
                
                if self.state != ServerState.RUNNING:
                    break
                
                # Собираем статистику
                uptime = ""
                if self.stats.started_at:
                    delta = datetime.now() - self.stats.started_at
                    hours, remainder = divmod(int(delta.total_seconds()), 3600)
                    minutes, _ = divmod(remainder, 60)
                    uptime = f"{hours}h{minutes}m"
                
                # CNAME cache stats
                cname_info = ""
                if self.verdict_engine:
                    try:
                        health = self.verdict_engine.get_cache_health()
                        cname = health.get('cname_cache', {})
                        if cname and 'size' in cname:
                            cname_info = f", CNAME cache: {cname['size']}/{cname['max_size']} ({cname['hit_rate']:.0f}% hit)"
                    except Exception:
                        pass
                
                logger.info(
                    f"[STATS] uptime={uptime}, queries={self.stats.total_queries}, "
                    f"blocked={self.stats.blocked_queries}, allowed={self.stats.allowed_queries}"
                    f"{cname_info}"
                )
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Stats logging error: {e}")
    
    def _is_safe_mode(self) -> bool:
        """Проверка, включён ли Safe Mode."""
        if self.guardian:
            return self.guardian.mode == GuardianMode.SAFE
        return False
    
    async def _check_cache(
        self,
        domain: str,
        qtype: int,
    ) -> dns.message.Message | None:
        """Проверка кеша."""
        if not self.cache:
            return None
        
        return await self.cache.get(domain, qtype)
    
    async def _cache_response(
        self,
        domain: str,
        qtype: int,
        response: dns.message.Message,
    ) -> None:
        """Кеширование ответа."""
        if not self.cache:
            return
        
        await self.cache.put(domain, qtype, response)
    
    async def _get_verdict(
        self,
        domain: str,
        client_ip: str,
        qtype: str,
        flow_id: str = "",
    ) -> Any:
        """Получение вердикта от Verdict Engine."""
        if not self.verdict_engine:
            # Без engine — разрешаем всё
            from .verdict.outcome import Verdict
            return Verdict(verdict_type=VerdictType.ALLOW, confidence=100)
        
        # Create FlowContext for verdict engine
        from .core.resolver import FlowContext, DNSQuestion
        import uuid

        client_mac = await self._resolve_client_mac(client_ip)
        
        ctx = FlowContext(
            flow_id=flow_id or str(uuid.uuid4())[:8],
            client_ip=client_ip,
            client_port=0,
            client_mac=client_mac,
            question=DNSQuestion(name=domain, rdtype=qtype),
            timestamp=time.time(),
            protocol="udp",
        )
        
        return await self.verdict_engine.evaluate(ctx)

    def _normalize_mac(self, mac: str | None) -> str | None:
        """Normalize MAC to lowercase aa:bb:cc:dd:ee:ff (or return None)."""
        if not mac:
            return None
        clean = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
        if len(clean) != 12:
            return None
        if not re.fullmatch(r"[0-9A-Fa-f]{12}", clean):
            return None
        return ":".join(clean[i:i+2].lower() for i in range(0, 12, 2))

    def _lookup_mac_from_arp(self, client_ip: str) -> str | None:
        """Best-effort MAC lookup from /proc/net/arp."""
        try:
            arp_path = Path("/proc/net/arp")
            if not arp_path.exists():
                return None
            lines = arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                arp_ip, _hwtype, flags, mac = parts[:4]
                if arp_ip != client_ip:
                    continue
                if flags.lower() in {"0x0", "0x00"}:
                    continue
                normalized = self._normalize_mac(mac)
                if normalized:
                    return normalized
        except Exception:
            return None
        return None

    async def _lookup_mac_from_neigh(self, client_ip: str) -> str | None:
        """Fallback MAC lookup from `ip neigh`."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip",
                "neigh",
                "show",
                "to",
                client_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=0.75)
            if proc.returncode != 0:
                return None
            text = (stdout or b"").decode(errors="ignore")
            match = re.search(r"lladdr\s+([0-9A-Fa-f:.\-]{11,})", text)
            if not match:
                return None
            return self._normalize_mac(match.group(1))
        except Exception:
            return None

    async def _resolve_client_mac(
        self, client_ip: str, *, fresh: bool = False
    ) -> str | None:
        """
        Resolve client MAC from local neighbor tables with a short TTL cache.

        This enables profile matching by MAC even when clients rotate IPs.
        """
        if ":" in client_ip:
            return None
        if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", client_ip):
            return None

        now_ts = time.monotonic()
        cached = self._client_mac_cache.get(client_ip)
        cache_ttl = (
            self._mac_cache_ttl_sec
            if cached and cached[0]
            else self._mac_negative_cache_ttl_sec
        )
        if not fresh and cached and (now_ts - cached[1]) <= cache_ttl:
            return cached[0] or None

        mac = self._lookup_mac_from_arp(client_ip)
        if not mac:
            mac = await self._lookup_mac_from_neigh(client_ip)

        self._client_mac_cache[client_ip] = (mac or "", now_ts)

        # Keep cache bounded in long-running installations.
        if len(self._client_mac_cache) > 4096:
            cutoff = now_ts - self._mac_cache_ttl_sec
            stale_keys = [ip for ip, (_m, ts) in self._client_mac_cache.items() if ts < cutoff]
            for ip in stale_keys:
                self._client_mac_cache.pop(ip, None)
            if len(self._client_mac_cache) > 4096:
                for ip in list(self._client_mac_cache.keys())[:512]:
                    self._client_mac_cache.pop(ip, None)

        return mac

    async def _log_flow(
        self,
        flow_id: str,
        domain: str,
        qtype: str,
        client_ip: str,
        protocol: str,
        status: FlowStatus,
        verdict: Any | None,
        start_time: datetime,
        response_ips: list[str] | None = None,
    ) -> None:
        """Логирование DNS-потока."""
        if is_internal_resolver_healthcheck(client_ip, domain):
            return
        if not self.flow_logger:
            return
        
        latency_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        # Hash client IP for privacy
        import hashlib
        client_id = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        
        # Get verdict string
        verdict_str = "allow"
        if verdict:
            if hasattr(verdict, 'action'):
                verdict_str = verdict.action.value
            elif hasattr(verdict, 'verdict_type'):
                verdict_str = verdict.verdict_type.value
        
        # Build evidence summary
        evidence_list = self._extract_evidence(verdict) if verdict else []
        evidence_summary = "; ".join(e.get("signal", str(e))[:50] for e in evidence_list[:3])

        # The engine's decisive reason. The evidence summary keeps only the
        # first signals, which need not include the one that decided the block,
        # so the reason is recorded on its own for "who blocked this" views.
        reason = getattr(verdict, "reason", None)
        reason = getattr(reason, "value", reason)
        categories = [f"{FLOW_REASON_PREFIX}{reason}"] if isinstance(reason, str) and reason else []

        response_code = "NOERROR"
        if status == FlowStatus.FAILED:
            response_code = "SERVFAIL"
        elif status == FlowStatus.BLOCKED:
            if reason == "rewrite_nxdomain" or self.config.block_mode == "nxdomain":
                response_code = "NXDOMAIN"

        entry = FlowEntry(
            flow_id=flow_id,
            timestamp=start_time,
            domain=domain,
            query_type=QueryType[qtype] if qtype in QueryType.__members__ else QueryType.A,
            client_id=client_id,
            status=status,
            verdict=verdict_str,
            confidence=verdict.confidence if verdict else 100,
            evidence_summary=evidence_summary,
            latency_ms=latency_ms,
            response_ips=response_ips or [],
            response_code=response_code,
            categories=categories,
        )

        self.flow_logger.log(entry)
        
        # Обновляем метрики
        if self.metrics:
            self.metrics.record_query(
                domain=domain,
                client_id=client_id,
                query_type=qtype,
                verdict=verdict_str,
                latency_ms=latency_ms,
                cached=status == FlowStatus.CACHED,
            )
    
    def _extract_evidence(self, verdict: Any) -> list[dict]:
        """Extract evidence list from verdict (handles both Verdict and VerdictResult)."""
        if not verdict or not hasattr(verdict, 'evidence'):
            return []
        
        evidence = verdict.evidence
        
        # EvidenceChain has .items attribute
        if hasattr(evidence, 'items'):
            items = evidence.items
        # List of Evidence
        elif isinstance(evidence, list):
            items = evidence
        else:
            return []
        
        result = []
        for e in items:
            if hasattr(e, 'to_dict'):
                result.append(e.to_dict())
            elif isinstance(e, dict):
                result.append(e)
            else:
                result.append({"signal": str(e)})
        return result
    
    def _make_response(
        self,
        query: dns.message.Message,
        response: dns.message.Message,
    ) -> bytes:
        """Формирование ответа с правильным ID."""
        response.id = query.id
        return response.to_wire()
    
    def _make_error_response(self, query_data: bytes, rcode: int) -> bytes:
        """Формирование ответа об ошибке."""
        try:
            query = dns.message.from_wire(query_data)
            response = dns.message.make_response(query)
            response.set_rcode(rcode)
            return response.to_wire()
        except Exception:
            # Минимальный ответ если не можем распарсить запрос
            # ID (2) + Flags (2) + Counts (8)
            if len(query_data) >= 2:
                query_id = query_data[:2]
            else:
                query_id = b"\x00\x00"
            
            flags = 0x8000 | (rcode & 0x0F)  # QR=1, RCODE
            return query_id + struct.pack("!HHHHH", flags, 0, 0, 0, 0)
    
    def _make_blocked_response(
        self,
        query: dns.message.Message,
        verdict: Any,
    ) -> bytes:
        """Формирование ответа для заблокированного домена."""
        response = dns.message.make_response(query)
        
        # Check if verdict reason requests specific response type
        reason = None
        if hasattr(verdict, 'reason'):
            reason = verdict.reason.value if hasattr(verdict.reason, 'value') else verdict.reason
        
        # NXDOMAIN for rewrite rules that request it
        if reason == "rewrite_nxdomain":
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()
        
        # NXDOMAIN или 0.0.0.0 в зависимости от настроек
        if self.config.block_mode == "nxdomain":
            response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            # Отвечаем 0.0.0.0 для A-запросов
            response.set_rcode(dns.rcode.NOERROR)
            if query.question:
                question = query.question[0]
                if question.rdtype == dns.rdatatype.A:
                    # Добавляем 0.0.0.0
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.A)
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0")
                    rrset.add(rdata, DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
                elif question.rdtype == dns.rdatatype.AAAA:
                    # Добавляем ::
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.AAAA)
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, "::")
                    rrset.add(rdata, DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
        
        return response.to_wire()
    
    async def _make_redirect_response(
        self,
        query: dns.message.Message,
        verdict: Any,
        client_ip: str = "127.0.0.1",
    ) -> bytes:
        """Формирование ответа для редиректа (DNS Rewrite / Safe Search).

        For a CNAME target (e.g. Safe Search -> forcesafesearch.google.com) we return
        the CNAME **and** resolve the target's A/AAAA into the same answer, so clients
        that don't chase CNAMEs themselves still get an address (bulletproof)."""
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)

        # Get redirect target from verdict (handles both redirect_ip and redirect_target)
        redirect_target = None
        if hasattr(verdict, "redirect_target") and verdict.redirect_target:
            redirect_target = verdict.redirect_target
        elif hasattr(verdict, "redirect_ip") and verdict.redirect_ip:
            redirect_target = verdict.redirect_ip

        if query.question and redirect_target:
            question = query.question[0]

            # Determine if target is IPv4, IPv6, or CNAME
            is_ipv6 = ":" in redirect_target
            is_ipv4 = not is_ipv6 and self._is_valid_ipv4(redirect_target)

            if question.rdtype == dns.rdatatype.A:
                if is_ipv4:
                    # Direct A record response
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.A)
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, redirect_target)
                    rrset.add(rdata, DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
                elif not is_ipv6:
                    # CNAME rewrite: emit the CNAME, then resolve + attach its A records.
                    target_name = redirect_target if redirect_target.endswith('.') else redirect_target + '.'
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.CNAME)
                    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target_name), DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
                    await self._append_resolved(
                        response,
                        target_name,
                        "A",
                        dns.rdatatype.A,
                        client_ip,
                    )

            elif question.rdtype == dns.rdatatype.AAAA:
                if is_ipv6:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.AAAA)
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, redirect_target)
                    rrset.add(rdata, DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
                elif not is_ipv4:
                    # CNAME for AAAA query: emit CNAME + resolve target's AAAA.
                    target_name = redirect_target if redirect_target.endswith('.') else redirect_target + '.'
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, dns.rdatatype.CNAME)
                    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target_name), DEFAULT_TTL_BLOCKED)
                    response.answer.append(rrset)
                    await self._append_resolved(
                        response,
                        target_name,
                        "AAAA",
                        dns.rdatatype.AAAA,
                        client_ip,
                    )

        return response.to_wire()

    async def _append_resolved(
        self,
        response,
        owner_name: str,
        rdtype_text: str,
        rdtype,
        client_ip: str,
    ) -> None:
        """Resolve owner_name via upstream and append its A/AAAA records (owner=target)
        to the response. Best-effort — on any failure we keep the CNAME-only answer,
        which still works for clients that chase CNAMEs."""
        try:
            query = dns.message.make_query(owner_name, rdtype_text)
            raw_response = await self._direct_upstream_query(query.to_wire(), client_ip)
            if not raw_response:
                return
            resolved = dns.message.from_wire(raw_response)
        except Exception as e:
            logger.debug(f"safe-search chain resolve failed for {owner_name}: {e}")
            return
        try:
            name = dns.name.from_text(owner_name if owner_name.endswith('.') else owner_name + '.')
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
            added = 0
            for answer in resolved.answer:
                if answer.rdtype != rdtype:
                    continue
                ttl = min(int(answer.ttl), DEFAULT_TTL_BLOCKED)
                for rdata in answer:
                    rrset.add(rdata, ttl)
                    added += 1
            if added:
                response.answer.append(rrset)
        except Exception as e:
            logger.debug(f"safe-search append failed for {owner_name}: {e}")
    
    def _is_valid_ipv4(self, s: str) -> bool:
        """Check if string is valid IPv4 address."""
        try:
            parts = s.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, AttributeError):
            return False


# ════════════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLING
# ════════════════════════════════════════════════════════════════════════════════

def setup_signal_handlers(server: NetProtectionServer) -> None:
    """Настройка обработчиков сигналов."""
    loop = asyncio.get_event_loop()
    
    def signal_handler(sig: signal.Signals) -> None:
        logger.info(f"Received signal {sig.name}, initiating shutdown...")
        server.request_shutdown()
    
    if sys.platform != "win32":
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
    else:
        # Windows не поддерживает add_signal_handler
        signal.signal(signal.SIGINT, lambda s, f: server.request_shutdown())
        signal.signal(signal.SIGTERM, lambda s, f: server.request_shutdown())


# ════════════════════════════════════════════════════════════════════════════════
# ENTRY POINTS
# ════════════════════════════════════════════════════════════════════════════════

async def run_server(config: NetProtectionConfig | None = None) -> None:
    """
    Запуск DNS-сервера.
    
    Args:
        config: Конфигурация. Если None, загружается из файла.
    """
    if config is None:
        config = load_config()
    
    server = NetProtectionServer(config=config)
    
    setup_signal_handlers(server)
    
    try:
        await server.start()
        await server.wait_for_shutdown()
    finally:
        await server.stop()


def main() -> None:
    """Точка входа для CLI."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass


async def create_server(config: NetProtectionConfig) -> NetProtectionServer:
    """
    Создание сервера для интеграции с EasyPi.
    
    Возвращает сервер без запуска — для ручного управления.
    """
    return NetProtectionServer(config=config)


if __name__ == "__main__":
    main()
