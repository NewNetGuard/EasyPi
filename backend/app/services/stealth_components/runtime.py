"""StealthRuntimeMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.stealth_components.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    detect_routing_conflict,
    get_easypi_root,
    get_netprotection_data_dir,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    posixpath,
    re,
    require_public_ipv4,
    routing_claim,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)


class StealthRuntimeMixin:
    @staticmethod
    def _arp_ip_by_mac() -> Dict[str, str]:
        out: Dict[str, str] = {}
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    p = line.split()
                    if len(p) >= 4:
                        ip, flags, mac = p[0], p[2], p[3].lower()
                        if flags not in {"0x0", "0x00"} and mac != "00:00:00:00:00:00":
                            out[mac] = ip
        except Exception:
            pass
        return out

    def _resolve_ips(self, meta: Dict[str, Any]) -> List[str]:
        by_mac = self._arp_ip_by_mac()
        ips: List[str] = []
        for dev in meta.get("devices", []):
            mac = str(dev.get("mac", "")).lower()
            resolved = by_mac.get(mac)
            if resolved and resolved not in ips:
                ips.append(resolved)
        return ips

    def _devices_with_live_ips(self, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        by_mac = self._arp_ip_by_mac()
        devices: List[Dict[str, Any]] = []
        for dev in meta.get("devices", []):
            mac = str(dev.get("mac", "")).lower().strip()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                continue
            devices.append(
                {
                    "mac": mac,
                    "name": str(dev.get("name", ""))[:48],
                    "ip": by_mac.get(mac),
                }
            )
        return devices

    @staticmethod
    def _resolve_macs(meta: Dict[str, Any]) -> List[str]:
        macs: List[str] = []
        for dev in meta.get("devices", []):
            mac = str(dev.get("mac", "")).lower().strip()
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac not in macs:
                macs.append(mac)
        return macs

    def _online_ips(self, meta: Dict[str, Any]) -> List[str]:
        by_mac = self._arp_ip_by_mac()
        return [by_mac[mac] for mac in self._resolve_macs(meta) if mac in by_mac]

    async def set_targets(
        self,
        scope: str,
        devices: List[Dict[str, Any]],
        confirm_routing_conflict: bool = False,
    ) -> Dict[str, Any]:
        async with self._runtime_lock:
            return await self._set_targets_locked(
                scope, devices, confirm_routing_conflict
            )

    async def _set_targets_locked(
        self,
        scope: str,
        devices: List[Dict[str, Any]],
        confirm_routing_conflict: bool,
    ) -> Dict[str, Any]:
        if scope not in ("all", "selected"):
            raise ValueError("scope must be 'all' or 'selected'")
        clean: List[Dict[str, Any]] = []
        for d in devices or []:
            mac = str(d.get("mac", "")).lower().strip()
            if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                continue
            clean.append({"mac": mac, "name": str(d.get("name", ""))[:48]})
        meta = self._meta()
        if meta.get("enabled") and not confirm_routing_conflict:
            conflict = self._routing_conflict(scope, clean)
            if conflict:
                return {
                    "success": False,
                    "error": conflict["message"],
                    "conflict": conflict,
                }
        meta["scope"] = scope
        meta["devices"] = clean
        self._save_meta(meta)
        if meta.get("enabled"):
            return await self._enable_locked(confirm_routing_conflict=True)
        return {"success": True, **self.client_state()}

    # ── client lifecycle ──────────────────────────────────────────────────────
    async def enable(self, confirm_routing_conflict: bool = False) -> Dict[str, Any]:
        async with self._runtime_lock:
            return await self._enable_locked(confirm_routing_conflict)

    async def _enable_locked(
        self, confirm_routing_conflict: bool = False
    ) -> Dict[str, Any]:
        meta = self._meta()
        if not (meta.get("server_address") and meta.get("psk_key")):
            return {
                "success": False,
                "error": "Set the server address + generate keys first",
            }
        if not meta.get("ssh", {}).get("ip_shield_deployed"):
            return {
                "success": False,
                "error": "Deploy IP Shield to the VPS before enabling Stealth",
            }
        self._write_client_conf(meta)
        scope = meta["scope"]
        ips = self._resolve_ips(meta) if scope == "selected" else []
        macs = self._resolve_macs(meta) if scope == "selected" else []
        if scope == "selected" and not macs:
            return {
                "success": False,
                "error": "Selected devices must have valid MAC addresses",
            }
        if not confirm_routing_conflict:
            conflict = self._routing_conflict(scope, meta.get("devices") or [])
            if conflict:
                return {
                    "success": False,
                    "error": conflict["message"],
                    "conflict": conflict,
                }
        # Persist the requested protection before entering the privileged
        # startup path. If the tunnel cannot start, boot/reconcile still know
        # that these devices must remain fail-closed.
        meta["enabled"] = True
        self._save_meta(meta)
        block_quic = "true" if meta.get("block_quic", True) else "false"
        res = await self._run(
            "up",
            str(self._conf_path),
            scope,
            ",".join(ips),
            block_quic,
            ",".join(macs),
            timeout=45,
        )
        if res.get("running") or res.get("killswitch"):
            self._applied_ips = set(ips)
        elif res.get("error"):
            return res
        return await self.status()

    async def disable(self) -> Dict[str, Any]:
        async with self._runtime_lock:
            return await self._disable_locked()

    async def _disable_locked(self) -> Dict[str, Any]:
        res = await self._run("down", timeout=30)
        if res.get("success") is True:
            meta = self._meta()
            meta["enabled"] = False
            self._save_meta(meta)
            self._applied_ips = set()
            # Return the same complete, authoritative state shape as enable().
            # The UI can then update without a racy follow-up GET.
            return await self.status()
        return res

    async def reconcile_if_needed(self) -> None:
        # Re-read both intent and runtime only after any manual transition has
        # completed. This prevents the watchdog from observing the intentional
        # startup gap and launching a second privileged `up` in parallel.
        async with self._runtime_lock:
            meta = self._meta()
            if not meta.get("enabled"):
                return
            runtime = await self._run("status", timeout=15)
            if not runtime.get("running"):
                # Persisted strict intent survives backend restarts and full boots.
                # Startup failure leaves the privileged kill-switch in place.
                await self._enable_locked(confirm_routing_conflict=True)
                return
            if meta.get("scope") != "selected":
                return
            ips = set(self._resolve_ips(meta))
            macs = self._resolve_macs(meta)
            if ips != self._applied_ips:
                await self._run(
                    "reconcile", ",".join(sorted(ips)), ",".join(macs), timeout=30
                )
                self._applied_ips = ips

    def covered_ips(self) -> tuple[bool, set[str]]:
        """LAN IPs currently routed through OUR Stealth tunnel — exempt from anti-bypass.

        Anti-bypass exists to catch a device sneaking out through an UNsanctioned tunnel
        (VPN/proxy/Tor/DoH). A device we deliberately route through Stealth is doing the
        opposite: using EasyPi's OWN anti-DPI path. Its heavy WAN to IPs EasyPi never
        resolved IS the tunnel itself — so the bypass detectors must stand down for it,
        or EasyPi bans its own stealth traffic the moment it comes up.

        Returns (covers_all, ips):
          * (False, set())      — Stealth off: nothing exempt.
          * (True,  set())      — scope 'all': the whole network is tunneled.
          * (False, {ip, ...})  — scope 'selected': these device IPs (resolved live by MAC,
                                  so it follows DHCP just like the routing does).
        """
        try:
            meta = self._meta()
            if not meta.get("enabled"):
                return (False, set())
            if meta.get("scope") == "all":
                return (True, set())
            return (False, {ip for ip in self._resolve_ips(meta) if ip})
        except Exception:
            return (False, set())

    @staticmethod
    def _log_tail(n: int = 40) -> str:
        try:
            data = (
                Path(CLIENT_LOG)
                .read_text(encoding="utf-8", errors="ignore")
                .splitlines()
            )
            return "\n".join(data[-n:])
        except Exception:
            return ""

    async def status(self) -> Dict[str, Any]:
        st = await self._run("status", timeout=15)
        st.update(self.client_state())
        st.update(self.server_state())
        if st.get("health_error") and not st.get("connected"):
            code = st.get("failure_code") or "server_connection_failed"
            st["health_title"] = "Stealth server unavailable"
            if code == "server_unavailable":
                st["health_hint"] = (
                    "The VPS refused the connection. Chameleon Server is probably stopped or removed. "
                    "Open Server, check SSH, then run Deploy & Start."
                )
            elif code == "server_timeout":
                st["health_hint"] = (
                    "The VPS did not answer. Check its network, firewall and SSH, then deploy the server again."
                )
            elif code == "server_tls_failed":
                st["health_hint"] = (
                    "The server identity or TLS certificate is invalid. Do not bypass verification; deploy again."
                )
            elif code == "server_auth_failed":
                st["health_hint"] = (
                    "The client and server credentials do not match. Deploy the server again to synchronize them."
                )
            elif code == "server_route_failed":
                st["health_hint"] = (
                    "The authenticated Chameleon HTTPS route is missing on the VPS. Deploy the server again."
                )
            elif code == "server_protocol_failed":
                st["health_hint"] = (
                    "The installed Chameleon client and server are incompatible. Update EasyPi and deploy the server again."
                )
            else:
                st["health_hint"] = (
                    "The tunnel could not reach a working Chameleon Server. Check SSH and deploy the server again."
                )
        st["online_targets"] = (
            len(self._online_ips(self._meta()))
            if self._meta().get("scope") == "selected"
            else None
        )
        st["device_list"] = self._devices_with_live_ips(self._meta())
        st["runtime_log"] = self._log_tail()
        return st

    async def reset_profile(self) -> Dict[str, Any]:
        try:
            (self._data_dir / "stealth_profile.json").unlink(missing_ok=True)
        except Exception:
            pass
        return {"success": True}

    @_deployment_locked("config-delete")
    async def delete_config(self) -> Dict[str, Any]:
        async with self._runtime_lock:
            disabled = await self._disable_locked()
            if disabled.get("success") is not True:
                return disabled
            try:
                for credential_name in (
                    "ssh-private-key",
                    "ssh-password",
                    "duckdns-token",
                ):
                    self._secret_delete(credential_name)
                self._conf_path.unlink(missing_ok=True)
                self._meta_path.unlink(missing_ok=True)
            except Exception as e:  # noqa: BLE001
                return {"success": False, "error": str(e)}
            return {"success": True, "configured": False}
