"""Detection operations for NetProtection."""

from app.services.netprotection_components.runtime_context import (
    Any,
    Dict,
    EASYPI_ROOT,
    List,
    Path,
    _short_err,
    asyncio,
    json,
    logger,
    re,
    sanitize_mac,
    uuid,
)


class DetectionFailClosedMixin:
    def _new_client_id(self) -> str:
        """Generate a stable random client ID for parental clients."""
        return f"dev_{uuid.uuid4().hex[:12]}"

    def _normalize_client_id(self, value: Any) -> str:
        """Normalize client ID to a safe identifier (or generate one)."""
        if isinstance(value, str):
            cleaned = re.sub(r"[^a-z0-9_-]", "", value.strip().lower())
            if cleaned:
                return cleaned[:64]
        return self._new_client_id()

    def _first_client_ip(self, client: Dict[str, Any]) -> str:
        """Get first IP from modern ('ids') or legacy ('ip') client payload."""
        ip = str(client.get("ip") or "").strip()
        if ip:
            return ip
        ids = client.get("ids") or []
        if isinstance(ids, list):
            for value in ids:
                candidate = str(value or "").strip()
                if candidate:
                    return candidate
        return ""

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Validate dotted-quad IPv4 address."""
        if not isinstance(ip, str):
            return False
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    async def _run_vpn_blocking_action(
        self,
        action: str,
        client_ip: str | None = None,
        client_mac: str | None = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Execute setup_vpn_blocking.sh via secure runner."""
        runner_path = EASYPI_ROOT / "scripts" / "runner"
        command = [
            "sudo",
            "-n",
            str(runner_path),
            "settings/setup_vpn_blocking.sh",
            action,
        ]
        if client_ip:
            command.append(client_ip)
            command.append("")
            command.append(client_mac or "")

        if not runner_path.exists():
            return {
                "success": False,
                "error": f"Runner not found: {runner_path}",
                "stdout": "",
                "stderr": "",
            }

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out_text = (stdout or b"").decode(errors="ignore").strip()
            err_text = (stderr or b"").decode(errors="ignore").strip()
            ok = proc.returncode == 0
            return {
                "success": ok,
                "stdout": out_text,
                "stderr": err_text,
                "exit_code": proc.returncode,
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Timeout running VPN action '{action}'",
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
            }

    async def list_fail_closed_clients(self) -> List[str]:
        """
        Get list of IPs currently quarantined by fail-closed mode.

        Read directly from fail_closed_devices.json (fast path). We avoid spawning
        sudo/runner processes here because the UI polls this endpoint frequently.
        """
        state_path = self.data_dir / "fail_closed_devices.json"
        try:
            if not state_path.exists():
                return []
            payload = json.loads(
                state_path.read_text(encoding="utf-8", errors="ignore")
            )
        except Exception:
            return []

        raw_ips = payload.get("ips", [])
        if not isinstance(raw_ips, list):
            raw_ips = []

        ips: List[str] = []
        seen: set[str] = set()
        for raw in raw_ips:
            candidate = str(raw or "").strip()
            if not self._is_valid_ipv4(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            ips.append(candidate)
        raw_devices = payload.get("devices", [])
        if isinstance(raw_devices, list):
            for raw in raw_devices:
                if not isinstance(raw, dict):
                    continue
                current_ip = self._resolve_ipv4_from_mac(
                    sanitize_mac(raw.get("mac")) or ""
                )
                if current_ip and current_ip not in seen:
                    seen.add(current_ip)
                    ips.append(current_ip)
        return ips

    async def quarantine_client(self, client_ip: str) -> Dict[str, Any]:
        """Enable fail-closed quarantine (full internet block) for one client IP."""
        if not self._is_valid_ipv4(client_ip):
            return {"success": False, "error": "Invalid IP address"}
        result = await self._run_vpn_blocking_action(
            "quarantine", client_ip, self._resolve_mac_from_arp(client_ip) or None
        )
        if not result.get("success"):
            return {
                "success": False,
                "error": _short_err(
                    result.get("stderr") or result.get("stdout") or "Unknown error"
                ),
            }
        return {
            "success": True,
            "ip": client_ip,
            "message": "Fail-closed quarantine enabled",
        }

    async def unquarantine_client(self, client_ip: str) -> Dict[str, Any]:
        """Disable fail-closed quarantine for one client IP."""
        if not self._is_valid_ipv4(client_ip):
            return {"success": False, "error": "Invalid IP address"}
        result = await self._run_vpn_blocking_action(
            "unquarantine", client_ip, self._resolve_mac_from_arp(client_ip) or None
        )
        if not result.get("success"):
            return {
                "success": False,
                "error": _short_err(
                    result.get("stderr") or result.get("stdout") or "Unknown error"
                ),
            }
        # Forget the previous alert + counter baseline so that if the same device
        # bypasses again (e.g. VPN switched back on) it is detected and blocked
        # again, instead of being silenced by the earlier acknowledgement.
        self._reset_bypass_state(client_ip)
        return {
            "success": True,
            "ip": client_ip,
            "message": "Fail-closed quarantine removed",
        }

    async def process_fail_closed_requests(self) -> Dict[str, Any]:
        """
        Drain fail-closed queue from netprotection engine and apply quarantine.

        Queue format: JSON-lines with at least {"ip": "..."}.
        """
        async with self._fail_closed_lock:
            queue_path = self._fail_closed_queue_path
            processing_path = self._fail_closed_queue_processing_path

            if not queue_path.exists() and not processing_path.exists():
                return {"processed": 0, "applied": [], "failed": []}

            # Atomically swap queue file so engine can continue writing new events.
            if queue_path.exists():
                try:
                    queue_path.replace(processing_path)
                except FileNotFoundError:
                    pass
                except Exception as e:
                    logger.warning(f"Failed to rotate fail-closed queue: {e}")
                    return {"processed": 0, "applied": [], "failed": [str(e)]}

            if not processing_path.exists():
                return {"processed": 0, "applied": [], "failed": []}

            try:
                lines = processing_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except Exception as e:
                logger.warning(f"Failed to read fail-closed queue: {e}")
                lines = []
            finally:
                try:
                    processing_path.unlink(missing_ok=True)
                except Exception as exc:
                    logger.warning(
                        "Could not remove processed fail-closed queue %s: %s",
                        processing_path,
                        exc,
                    )

            # Keep the last trigger per IP (for UI diagnostics).
            triggers: dict[str, dict[str, Any]] = {}
            failed: List[str] = []

            for raw in lines:
                line = (raw or "").strip()
                if not line:
                    continue
                ip = ""
                domain = None
                flow_id = None
                ts = None
                try:
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        ip = str(payload.get("ip") or "").strip()
                        domain = payload.get("domain")
                        flow_id = payload.get("flow_id")
                        ts = payload.get("ts")
                    else:
                        ip = str(payload).strip()
                except Exception:
                    # Backward compatibility: allow plain-ip line.
                    ip = line

                if not self._is_valid_ipv4(ip):
                    failed.append(f"Invalid IP in queue: {line[:80]}")
                    continue
                triggers[ip] = {
                    "ip": ip,
                    "domain": str(domain or "").strip() if domain is not None else None,
                    "flow_id": str(flow_id or "").strip()
                    if flow_id is not None
                    else None,
                    "ts": ts,
                }

            applied: List[str] = []
            for ip, event in triggers.items():
                result = await self.quarantine_client(ip)
                if result.get("success"):
                    applied.append(ip)
                    try:
                        self.record_fail_closed_trigger(
                            client_ip=ip,
                            domain=event.get("domain"),
                            flow_id=event.get("flow_id"),
                            ts=event.get("ts"),
                            applied=True,
                        )
                    except Exception as e:
                        logger.warning(
                            f"Failed to persist fail-closed meta for {ip}: {e}"
                        )
                else:
                    err = result.get("error", "quarantine failed")
                    failed.append(f"{ip}: {err}")
                    try:
                        self.record_fail_closed_trigger(
                            client_ip=ip,
                            domain=event.get("domain"),
                            flow_id=event.get("flow_id"),
                            ts=event.get("ts"),
                            applied=False,
                            error=str(err),
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to persist failed fail-closed trigger for %s: %s",
                            ip,
                            exc,
                        )

        if applied:
            logger.warning(
                f"Fail-closed applied for {len(applied)} device(s): {', '.join(applied)}"
            )
            try:
                asyncio.create_task(
                    self._notify_fail_closed(list(applied), dict(triggers))
                )
            except Exception as exc:
                logger.warning("Could not schedule fail-closed notification: %s", exc)
        if failed:
            logger.warning(f"Fail-closed processing issues: {failed}")

        return {"processed": len(lines), "applied": applied, "failed": failed}

    async def _notify_fail_closed(self, applied: List[str], triggers: dict) -> None:
        """Best-effort notification when devices are quarantined (fail-closed).

        Fire-and-forget: respects each user's notification preferences and never
        affects the fail-closed worker (fully guarded; email send is offloaded).
        """
        try:
            from app.services.email_service import (
                broadcast_security_alert,
                AlertType,
                EmailPriority,
            )

            domains = sorted(
                {
                    (triggers.get(ip, {}) or {}).get("domain")
                    for ip in applied
                    if (triggers.get(ip, {}) or {}).get("domain")
                }
            )
            names = ", ".join(applied[:10])
            desc = (
                f"NetProtection quarantined {len(applied)} device(s) after a DNS leak"
            )
            if domains:
                desc += f" (domains: {', '.join(domains[:5])})"
            desc += f": {names}"
            await broadcast_security_alert(
                AlertType.SECURITY_BREACH,
                title="DNS leak blocked (fail-closed)",
                description=desc,
                details={"devices": applied[:20], "domains": domains[:20]},
                priority=EmailPriority.HIGH,
            )
        except Exception as e:
            logger.debug(f"fail-closed notification skipped: {e}")

    async def _fail_closed_worker_loop(self) -> None:
        """Background worker that continuously applies fail-closed requests."""
        while True:
            try:
                await self.process_fail_closed_requests()
                await self.process_bypass_events()
                await self.detect_network_bypass()
                await self.detect_dns_shadow_bypass()
                await self.process_bypass_leak_timeouts()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Fail-closed worker error: {e}")
            await asyncio.sleep(2)

    def _resolve_mac_from_arp(self, ip: str) -> str:
        """
        Best-effort MAC lookup for LAN IPv4 clients using ARP/neigh tables.
        Returns normalized MAC or empty string.
        """
        ip = (ip or "").strip()
        if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
            return ""

        # Fast path: kernel ARP cache
        try:
            arp_path = Path("/proc/net/arp")
            if arp_path.exists():
                lines = arp_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    arp_ip, _hwtype, flags, mac = parts[:4]
                    if arp_ip != ip:
                        continue
                    if flags.lower() in {"0x0", "0x00"}:
                        continue
                    normalized = sanitize_mac(mac)
                    if normalized:
                        return normalized
        except Exception:
            # Best-effort only.
            pass

        # Fallback: ip neigh (may include fresh ARP entries)
        try:
            import subprocess

            result = subprocess.run(
                ["ip", "neigh", "show", "to", ip],
                capture_output=True,
                text=True,
                timeout=1.5,
            )
            if result.returncode == 0:
                match = re.search(
                    r"lladdr\s+([0-9a-fA-F:.-]{11,})", result.stdout or ""
                )
                if match:
                    normalized = sanitize_mac(match.group(1))
                    if normalized:
                        return normalized
        except Exception:
            pass

        return ""

    def _resolve_ipv4_from_mac(self, mac: str) -> str:
        """
        Best-effort IPv4 lookup for a MAC from neighbor tables.

        This is used to keep per-device firewall chains (source IP based)
        aligned with DHCP changes.
        """
        normalized_mac = sanitize_mac(mac)
        if not normalized_mac:
            return ""

        try:
            import subprocess

            def _collect(candidates_cmd: list[str]) -> list[tuple[int, str]]:
                result = subprocess.run(
                    candidates_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                )
                if result.returncode != 0:
                    return []

                rows: list[tuple[int, str]] = []
                state_score = {
                    "REACHABLE": 100,
                    "DELAY": 90,
                    "PROBE": 80,
                }

                for raw in (result.stdout or "").splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    # Example:
                    # 192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                    m = re.search(
                        r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+dev\s+(?P<dev>\S+)\s+lladdr\s+(?P<mac>[0-9a-fA-F:.\-]{11,})\s+(?P<state>\S+)$",
                        line,
                    )
                    if not m:
                        continue

                    row_mac = sanitize_mac(m.group("mac"))
                    if row_mac != normalized_mac:
                        continue

                    ip = m.group("ip")
                    state = m.group("state").upper()
                    score = state_score.get(state, 0)
                    if score <= 0:
                        continue

                    dev = (m.group("dev") or "").lower()
                    # Prefer wired path when available.
                    if dev.startswith("eth"):
                        score += 10
                    elif dev.startswith("wlan"):
                        score += 5

                    rows.append((score, ip))
                return rows

            # Trust only active neighbors. A STALE entry can belong to the
            # device's previous DHCP address and must never overwrite a newer,
            # server-observed admission binding.
            candidates = _collect(
                [
                    "ip",
                    "-4",
                    "neigh",
                    "show",
                    "nud",
                    "reachable",
                    "nud",
                    "delay",
                    "nud",
                    "probe",
                ]
            )

            if candidates:
                candidates.sort(key=lambda x: x[0], reverse=True)
                return candidates[0][1]
        except Exception:
            pass

        return ""
