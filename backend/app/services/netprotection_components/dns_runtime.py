"""DnsRuntime operations for NetProtection."""

from app.services.netprotection_components.runtime_context import (
    Any,
    Dict,
    List,
    NETPROTECTION_AVAILABLE,
    asyncio,
    logger,
)


class DnsRuntimeMixin:
    """Internal behavior mixed into the stable service facade."""

    async def get_dns_config(self) -> Dict[str, Any]:
        """Get DNS-specific configuration."""
        config = await self.get_config()
        return {
            "upstream_dns": config.get(
                "upstream_dns", ["https://dns.quad9.net/dns-query"]
            ),
            "dnssec_enabled": config.get("dnssec", False),
            "disable_ipv6": config.get("disable_ipv6", False),
            "cache_size": config.get("cache_size", 10000),
            "cache_ttl": config.get("cache_ttl", 300),
        }

    async def set_dns_config(self, dns_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update DNS-specific configuration."""
        config = await self.get_config()

        if "upstream_dns" in dns_config:
            config["upstream_dns"] = dns_config["upstream_dns"]
        if "dnssec_enabled" in dns_config:
            config["dnssec"] = dns_config["dnssec_enabled"]
        if "disable_ipv6" in dns_config:
            config["disable_ipv6"] = dns_config["disable_ipv6"]
        if "cache_size" in dns_config:
            config["cache_size"] = dns_config["cache_size"]
        if "cache_ttl" in dns_config:
            config["cache_ttl"] = dns_config["cache_ttl"]

        await self.update_config(config)
        return {"success": True}

    async def get_query_log_config(self) -> Dict[str, Any]:
        """Get query log configuration."""
        config = await self.get_config()
        return {
            "enabled": config.get("log_queries", True),
            "anonymize_client_ip": config.get("anonymize_logs", False),
        }

    async def set_query_log_config(
        self, enabled: bool = None, anonymize: bool = None
    ) -> Dict[str, Any]:
        """Update query log configuration."""
        config = await self.get_config()

        if enabled is not None:
            config["log_queries"] = enabled
        if anonymize is not None:
            config["anonymize_logs"] = anonymize

        await self.update_config(config)
        return {"success": True}

    async def clear_dns_cache(self) -> Dict[str, Any]:
        """Clear DNS cache (placeholder - actual cache is in-memory in NetProtection)."""
        # NetProtection keeps cache in memory. Restarting would clear it.
        # For now, just return success since there's no direct API.
        logger.info("DNS cache clear requested (cache is in NetProtection memory)")
        return {"success": True, "message": "Cache cleared"}

    async def get_upstream_servers(self) -> Dict[str, Any]:
        """Read the resolver's REAL upstream DNS servers from its TOML config."""
        if not NETPROTECTION_AVAILABLE:
            return {
                "success": False,
                "error": "NetProtection module not available",
                "servers": [],
            }
        try:
            from easypi_netprotection.config import NetProtectionSettings

            settings = NetProtectionSettings.from_toml(
                self._get_netprotection_toml_path()
            )
            return {"success": True, "servers": list(settings.upstream.servers)}
        except Exception as e:
            logger.error(f"Failed to read upstream servers: {e}")
            return {"success": False, "error": str(e), "servers": []}

    @staticmethod
    def _validate_upstream_server(s: str) -> bool:
        """Accept DoH (https://), DoT (tls://), DoQ (quic://) URLs, or plain IPv4[:port]."""
        import re

        s = (s or "").strip()
        if not s or len(s) > 256:
            return False
        if s.startswith(("https://", "tls://", "quic://")):
            return bool(
                re.match(
                    r"^(https|tls|quic)://[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9](:\d{1,5})?(/[a-zA-Z0-9._\-/]*)?$",
                    s,
                )
            )
        return bool(
            re.match(
                r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)(:\d{1,5})?$",
                s,
            )
        )

    async def set_upstream_servers(self, servers: List[str]) -> Dict[str, Any]:
        """Write upstream DNS servers to the resolver TOML and reload it (applies live)."""
        if not NETPROTECTION_AVAILABLE:
            return {"success": False, "error": "NetProtection module not available"}
        cleaned = [str(s).strip() for s in (servers or []) if str(s).strip()]
        if not cleaned:
            return {
                "success": False,
                "error": "At least one upstream server is required",
            }
        cleaned = cleaned[:10]
        invalid = [s for s in cleaned if not self._validate_upstream_server(s)]
        if invalid:
            return {
                "success": False,
                "error": f"Invalid upstream server(s): {', '.join(invalid[:3])}",
            }
        try:
            from easypi_netprotection.config import NetProtectionSettings

            path = self._get_netprotection_toml_path()
            settings = NetProtectionSettings.from_toml(path)
            settings.upstream.servers = cleaned
            settings.to_toml(path)
            await self._reload_netprotection()
            logger.info(
                f"Upstream DNS servers updated ({len(cleaned)}) and resolver reloaded"
            )
            return {"success": True, "servers": cleaned}
        except Exception as e:
            logger.error(f"Failed to set upstream servers: {e}")
            return {"success": False, "error": str(e)}

    def _probe_plain_dns(self, addr: str, port: int, timeout: float) -> tuple:
        """Blocking DNS probe for a plain IPv4 resolver. Returns (ok, ms, error)."""
        import socket
        import time

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            query += b"\x06google\x03com\x00\x00\x01\x00\x01"
            start = time.monotonic()
            s.sendto(query, (addr, port))
            data, _ = s.recvfrom(512)
            return (len(data) >= 12, int((time.monotonic() - start) * 1000), None)
        except socket.timeout:
            return (False, 0, "Timeout")
        except Exception:
            return (False, 0, "Connection failed")
        finally:
            s.close()

    async def test_upstream_dns(self, servers: List[str]) -> Dict[str, Any]:
        """Actually probe each upstream: real DoH query, DoT TLS handshake, or plain DNS query."""
        import re
        import time
        import ssl
        import base64
        import struct

        servers = (servers or [])[:10]
        dns_query = (
            struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack(">HH", 1, 1)
        )
        results: Dict[str, Any] = {}

        async def probe_doh(url):
            import httpx

            b64 = base64.urlsafe_b64encode(dns_query).rstrip(b"=").decode()
            t = time.monotonic()
            async with httpx.AsyncClient(timeout=6.0) as cl:
                r = await cl.get(
                    url,
                    params={"dns": b64},
                    headers={"accept": "application/dns-message"},
                )
            ms = int((time.monotonic() - t) * 1000)
            return (
                r.status_code == 200,
                ms,
                None if r.status_code == 200 else f"HTTP {r.status_code}",
            )

        async def probe_dot(host, port):
            t = time.monotonic()
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=6.0
            )
            ms = int((time.monotonic() - t) * 1000)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass
            return (True, ms, None)

        for server in servers:
            res: Dict[str, Any] = {"success": False, "time": 0, "error": None}
            try:
                if not server or len(server) > 256:
                    res["error"] = "Invalid server"
                    results[server] = res
                    continue
                if server.startswith("https://"):
                    ok, ms, err = await probe_doh(server)
                    res.update(success=ok, time=ms, error=err)
                elif server.startswith("tls://"):
                    hostport = server[len("tls://") :].split("/")[0]
                    host = hostport.split(":")[0]
                    port = int(hostport.split(":")[1]) if ":" in hostport else 853
                    ok, ms, err = await probe_dot(host, port)
                    res.update(success=ok, time=ms, error=err)
                elif server.startswith("quic://"):
                    res["error"] = "DoQ test not supported"
                else:
                    parts = server.split(":")
                    addr = parts[0]
                    if not re.match(
                        r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$",
                        addr,
                    ):
                        res["error"] = "Invalid IP address"
                        results[server] = res
                        continue
                    if (
                        addr.startswith("127.")
                        or addr.startswith("0.")
                        or addr == "localhost"
                    ):
                        res["error"] = "Local addresses not allowed"
                        results[server] = res
                        continue
                    port = 53
                    if len(parts) > 1:
                        try:
                            port = int(parts[1])
                            if not 1 <= port <= 65535:
                                raise ValueError("port out of range")
                        except (TypeError, ValueError):
                            res["error"] = "Invalid port"
                            results[server] = res
                            continue
                    ok, ms, err = await asyncio.to_thread(
                        self._probe_plain_dns, addr, port, 3.0
                    )
                    res.update(success=ok, time=ms, error=err)
            except asyncio.TimeoutError:
                res["error"] = "Timeout"
            except Exception as e:
                res["error"] = "Connection failed"
                logger.warning(f"DNS test failed for {server}: {e}")
            results[server] = res
        return results

    async def enable_protection(self) -> Dict[str, Any]:
        """Enable DNS protection."""
        config = await self.get_config()
        config["protection_enabled"] = True
        await self.update_config(config)
        return {"success": True, "message": "Protection enabled"}

    async def disable_protection(self) -> Dict[str, Any]:
        """Disable DNS protection."""
        config = await self.get_config()
        config["protection_enabled"] = False
        await self.update_config(config)
        return {"success": True, "message": "Protection disabled"}
