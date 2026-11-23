"""
Outbound VPN client service (Privacy -> Internet Encryption).

Lets EasyPi act as a VPN CLIENT (WireGuard, OpenVPN, or Outline) to a provider
and route either the whole network or selected devices out through the tunnel.
Privileged networking lives in the root-owned ``scripts/settings/outbound_vpn.sh``
(via the secure runner). This service validates + stores the config, tracks the
routing scope + target devices, and resolves device MACs -> current IPs from ARP
so per-device targeting survives DHCP (same approach as the schedule enforcer).

Distinct from the anti-bypass VPN *blocking* (setup_vpn_blocking.sh): that DETECTS
LAN clients evading the filter; this is the box's own private uplink.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import signal
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

from app.core.paths import get_easypi_root, get_netprotection_data_dir
from app.core.openvpn_config import openvpn_option_text, validate_openvpn_config
from app.services.routing_conflict_service import detect_routing_conflict, routing_claim

logger = logging.getLogger(__name__)

CONFIG_NAME = "outbound_vpn.conf"
META_NAME = "outbound_vpn_meta.json"
SCRIPT_REL = "settings/outbound_vpn.sh"
SECRET_SCRIPT_REL = "settings/outbound_vpn_secrets.sh"


class VpnClientService:
    def __init__(self) -> None:
        self._data_dir = Path(get_netprotection_data_dir())
        # Config lives under /opt/EasyPi/... so the root script's allow-list
        # (only .conf under /opt/EasyPi) accepts it.
        self._conf_path = self._data_dir / CONFIG_NAME
        self._meta_path = self._data_dir / META_NAME
        self._applied_macs: set[str] = set()

    # ── runner ────────────────────────────────────────────────────────────────
    async def _run(self, action: str, *args: str, timeout: int = 90) -> Dict[str, Any]:
        runner = get_easypi_root() / "scripts" / "runner"
        if not runner.exists():
            return {"success": False, "error": f"runner not found: {runner}"}
        cmd = ["sudo", "-n", str(runner), SCRIPT_REL, action, *[str(a) for a in args]]
        proc: Optional[asyncio.subprocess.Process] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            # sudo/runner and every non-daemon child share this dedicated process
            # group. Terminating the group triggers the root script's rollback
            # trap, preventing a timed-out request from changing routes later.
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    await proc.wait()
            return {"success": False, "error": f"timeout running '{action}'"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}
        out = (stdout or b"").decode(errors="ignore").strip()
        parsed = self._last_json(out)
        if parsed is None:
            err = (stderr or b"").decode(errors="ignore").strip() or out
            return {"success": proc.returncode == 0, "error": err[:300]}
        return parsed

    @staticmethod
    def _last_json(text: str) -> Optional[Dict[str, Any]]:
        found: Optional[Dict[str, Any]] = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    found = json.loads(line)
                except Exception:
                    continue
        return found

    def _credential_command(self, action: str, payload: Optional[Dict[str, str]] = None) -> str:
        """Use the root credential broker; secret material is passed only on stdin."""
        runner = get_easypi_root() / "scripts" / "runner"
        cmd = ["sudo", "-n", str(runner), SECRET_SCRIPT_REL, action]
        try:
            completed = subprocess.run(
                cmd,
                input=None if payload is None else json.dumps(payload).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        except Exception as exc:
            raise RuntimeError("Secure OpenVPN credential storage is unavailable") from exc
        if completed.returncode != 0:
            # Broker stderr may contain validation detail but must never be
            # reflected to a browser in case an underlying tool includes data.
            raise RuntimeError("Secure OpenVPN credential storage rejected the operation")
        return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")

    def _credentials_configured(self) -> bool:
        try:
            return self._credential_command("exists") == "true"
        except RuntimeError:
            return False

    @staticmethod
    def _requires_credentials(text: str) -> bool:
        return bool(re.search(r"(?im)^\s*auth-user-pass(?:\s*(?:[#;].*)?)?$", openvpn_option_text(text)))

    def save_credentials(self, username: str, password: str) -> Dict[str, Any]:
        if not self._conf_path.exists():
            raise ValueError("Import an OpenVPN config first")
        text = self._conf_path.read_text(encoding="utf-8", errors="ignore")
        if self._detect_engine(text) != "openvpn" or not self._requires_credentials(text):
            raise ValueError("The imported VPN config does not require OpenVPN credentials")
        if not username or not password:
            raise ValueError("OpenVPN username and password are required")
        if any(ch in username or ch in password for ch in ("\n", "\r", "\x00")):
            raise ValueError("OpenVPN credentials contain forbidden control characters")
        if len(username) > 256 or len(password) > 4096:
            raise ValueError("OpenVPN credentials are too long")
        mode = self._credential_command("store", {"username": username, "password": password})
        if mode not in ("", "host", "host+tpm2"):
            mode = "host"
        return {
            "success": True,
            "credentials_configured": True,
            "credential_protection": "TPM + host-bound encryption" if "tpm2" in mode else "host-bound encryption",
        }

    def delete_credentials(self) -> Dict[str, Any]:
        meta = self._meta()
        if meta.get("enabled") and self._runtime_active(meta):
            raise ValueError("Disable Internet Encryption before removing OpenVPN credentials")
        self._credential_command("delete")
        return {"success": True, "credentials_configured": False}

    # ── meta (engine + scope + devices + enabled) ─────────────────────────────
    def _meta(self) -> Dict[str, Any]:
        default = {"engine": "wireguard", "scope": "all", "devices": [], "enabled": False}
        try:
            if self._meta_path.exists():
                d = json.loads(self._meta_path.read_text(encoding="utf-8"))
                if isinstance(d, dict):
                    default.update({k: d.get(k, default[k]) for k in default})
        except Exception:
            pass
        normalized_devices: List[Dict[str, str]] = []
        seen_macs: set[str] = set()
        for raw in default.get("devices", []):
            if not isinstance(raw, dict):
                continue
            mac = str(raw.get("mac", "")).lower().strip()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or mac in seen_macs:
                continue
            seen_macs.add(mac)
            normalized_devices.append({"mac": mac, "name": str(raw.get("name", ""))[:48]})
        default["devices"] = normalized_devices
        return default

    def _save_meta(self, meta: Dict[str, Any]) -> None:
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            self._meta_path.write_text(json.dumps(meta), encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"vpn meta save failed: {e}")

    def routing_claim(self) -> Dict[str, Any]:
        """Non-secret routing ownership advertised to other EasyPi features."""
        meta = self._meta()
        return routing_claim(
            enabled=bool(meta.get("enabled") and self._runtime_active(meta)),
            scope=str(meta.get("scope", "all")),
            devices=meta.get("devices") or [],
        )

    @staticmethod
    def _runtime_active(meta: Dict[str, Any]) -> bool:
        engine = meta.get("engine")
        if engine == "outline":
            # Root owns this marker. A stale marker is fail-safe (it may block a
            # conflicting router feature) and is reconciled by the status call.
            marker = Path("/run/easypi-outbound-vpn.active")
            try:
                return marker.read_text(encoding="ascii").strip() == "outline"
            except (OSError, UnicodeError):
                return False
        interface = "easypi-ovpn" if engine == "openvpn" else "wg-out"
        return (Path("/sys/class/net") / interface).exists()

    @staticmethod
    def _routing_conflict(scope: str, devices: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        # Lazy import avoids coupling service initialization. No secrets or
        # privileged runtime state cross this boundary.
        from app.services.stealth_service import get_stealth_service

        return detect_routing_conflict(
            feature="internet_encryption",
            scope=scope,
            devices=devices,
            other_feature="stealth",
            other_claim=get_stealth_service().routing_claim(),
        )

    # ── ARP resolution (DHCP-proof device targeting) ──────────────────────────
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
                        if flags != "0x0" and mac and mac != "00:00:00:00:00:00":
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
            devices.append({
                "mac": mac,
                "name": str(dev.get("name", ""))[:48],
                "ip": by_mac.get(mac),
            })
        return devices

    def _online_ips(self, meta: Dict[str, Any]) -> List[str]:
        by_mac = self._arp_ip_by_mac()
        return [by_mac[mac] for mac in self._resolve_macs(meta) if mac in by_mac]

    @staticmethod
    def _resolve_macs(meta: Dict[str, Any]) -> List[str]:
        macs: List[str] = []
        for dev in meta.get("devices", []):
            mac = str(dev.get("mac", "")).lower().strip()
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac not in macs:
                macs.append(mac)
        return macs

    # ── config ────────────────────────────────────────────────────────────────
    @staticmethod
    def _detect_engine(text: str) -> Optional[str]:
        if text.strip().lower().startswith("ss://"):
            return "outline"
        if "[Interface]" in text and re.search(r"(?im)^\s*PrivateKey\s*=", text):
            return "wireguard"
        if re.search(r"(?im)^\s*remote\s+\S+", text):
            return "openvpn"
        # Safe quoted/--prefixed option names are canonicalized by the shared
        # parser. Recognize these profiles too, without accepting unknown data.
        try:
            validate_openvpn_config(text)
        except ValueError:
            return None
        return "openvpn"

    @staticmethod
    def _parse_outline_key(text: str) -> Dict[str, Any]:
        key = text.strip()
        if len(key) > 8192 or not key.lower().startswith("ss://"):
            raise ValueError("Expected a static Outline access key starting with ss://")

        parsed = urlsplit(key)
        userinfo = unquote(parsed.username or "")
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Outline access key has an invalid port") from exc

        def decode_urlsafe(value: str) -> str:
            try:
                padded = value + "=" * (-len(value) % 4)
                return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("Outline access key contains invalid base64 data") from exc

        if host and port:
            credentials = userinfo if ":" in userinfo else decode_urlsafe(userinfo)
        else:
            # Legacy keys encode method:password@host:port as one base64 value.
            payload = key[5:].split("#", 1)[0].split("?", 1)[0].rstrip("/")
            decoded = decode_urlsafe(payload)
            legacy = urlsplit(f"ss://{decoded}")
            if legacy.username is None or legacy.password is None:
                raise ValueError("Outline access key is missing its cipher or secret")
            credentials = f"{unquote(legacy.username)}:{unquote(legacy.password)}"
            host = legacy.hostname or ""
            try:
                port = legacy.port
            except ValueError as exc:
                raise ValueError("Outline access key has an invalid port") from exc

        if ":" not in credentials:
            raise ValueError("Outline access key is missing its cipher or secret")
        method, password = credentials.split(":", 1)
        method = method.lower().strip()
        allowed_methods = {
            "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
            "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        }
        if method not in allowed_methods:
            raise ValueError("Outline access key uses an unsupported cipher")
        if not host or not port or not 1 <= port <= 65535:
            raise ValueError("Outline access key is missing a valid server and port")
        if not password or len(password) > 512 or any(ord(char) < 32 for char in password):
            raise ValueError("Outline access key contains an invalid secret")
        # Initial support is deliberately IPv4/hostname-only. Bracketed IPv6
        # endpoints need separate loop-prevention and firewall handling.
        if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("Outline access key contains an invalid server name")
        return {"server": host, "port": port, "method": method, "password": password}

    @staticmethod
    def _parse_meta(text: str, engine: str) -> Dict[str, Any]:
        endpoint = ""
        address = ""
        transport_protocol = "udp" if engine == "wireguard" else ""
        transport_port: Optional[int] = None
        if engine == "outline":
            outline = VpnClientService._parse_outline_key(text)
            endpoint = f"{outline['server']}:{outline['port']}"
            transport_protocol = "tcp+udp"
            transport_port = int(outline["port"])
        elif engine == "wireguard":
            for raw in text.splitlines():
                line = raw.strip()
                m = re.match(r"(?i)^Endpoint\s*=\s*(.+)$", line)
                if m:
                    endpoint = m.group(1).strip()
                m = re.match(r"(?i)^Address\s*=\s*(.+)$", line)
                if m:
                    address = m.group(1).strip()
        else:  # openvpn
            text = openvpn_option_text(text)
            proto_match = re.search(r"(?im)^\s*proto\s+(\S+)", text)
            if proto_match:
                raw_proto = proto_match.group(1).lower()
                if raw_proto.startswith("udp"):
                    transport_protocol = "udp"
                elif raw_proto.startswith("tcp"):
                    transport_protocol = "tcp"
            m = re.search(r"(?im)^\s*remote\s+(\S+)\s*(\d+)?", text)
            if m:
                endpoint = f"{m.group(1)}:{m.group(2)}" if m.group(2) else m.group(1)
                if m.group(2):
                    transport_port = int(m.group(2))
        if engine == "wireguard" and endpoint:
            port_match = re.search(r":(\d+)$", endpoint)
            if port_match:
                transport_port = int(port_match.group(1))
        host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
        transport_warning = ""
        if transport_port == 53:
            transport_warning = (
                "Port 53 is reserved for DNS and may be intercepted or filtered by EasyPi, "
                "the router, or the ISP. Use the provider's UDP profile on another port or "
                "OpenVPN TCP 443 when available."
            )
        return {
            "endpoint": endpoint,
            "endpoint_host": host,
            "address": address,
            "transport_protocol": transport_protocol,
            "transport_port": transport_port,
            "transport_warning": transport_warning,
        }

    def import_config(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            raise ValueError("Empty config")
        engine = self._detect_engine(text)
        if engine is None:
            if text.strip().lower().startswith("ssconf://"):
                raise ValueError("Dynamic Outline keys are not supported yet; use a static ss:// access key")
            raise ValueError("Unrecognised config — expected WireGuard, OpenVPN, or a static Outline ss:// key")
        normalised = text.replace("\r\n", "\n").replace("\r", "\n")
        if engine == "openvpn":
            normalised = validate_openvpn_config(normalised)
        if engine == "outline":
            self._parse_outline_key(normalised)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._conf_path.write_text(normalised, encoding="utf-8")
        try:
            self._conf_path.chmod(0o600)
        except Exception:
            pass
        meta = self._meta()
        meta["engine"] = engine
        # A fresh import keeps existing scope/devices but is not auto-enabled.
        meta["enabled"] = False
        self._save_meta(meta)
        requires_credentials = engine == "openvpn" and self._requires_credentials(normalised)
        return {
            "success": True,
            "engine": engine,
            "requires_credentials": requires_credentials,
            "credentials_configured": self._credentials_configured() if requires_credentials else False,
            **self._parse_meta(normalised, engine),
        }

    def config_meta(self) -> Dict[str, Any]:
        meta = self._meta()
        base = {
            "configured": self._conf_path.exists(),
            "engine": meta["engine"], "scope": meta["scope"],
            "devices": meta["devices"], "enabled": meta["enabled"],
            "endpoint": "", "endpoint_host": "", "address": "",
            "transport_protocol": "", "transport_port": None, "transport_warning": "",
        }
        if self._conf_path.exists():
            try:
                text = self._conf_path.read_text(encoding="utf-8", errors="ignore")
                base.update(self._parse_meta(text, meta["engine"]))
                requires_credentials = meta["engine"] == "openvpn" and self._requires_credentials(text)
                base["requires_credentials"] = requires_credentials
                base["credentials_configured"] = (
                    self._credentials_configured() if requires_credentials else False
                )
            except Exception:
                pass
        base.setdefault("requires_credentials", False)
        base.setdefault("credentials_configured", False)
        return base

    # ── targeting ─────────────────────────────────────────────────────────────
    async def set_targets(
        self,
        scope: str,
        devices: List[Dict[str, Any]],
        confirm_routing_conflict: bool = False,
    ) -> Dict[str, Any]:
        if scope not in ("all", "selected"):
            raise ValueError("scope must be 'all' or 'selected'")
        clean: List[Dict[str, Any]] = []
        seen_macs: set[str] = set()
        for d in devices or []:
            mac = str(d.get("mac", "")).lower().strip()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or mac in seen_macs:
                continue
            seen_macs.add(mac)
            clean.append({"mac": mac, "name": str(d.get("name", ""))[:48]})
        meta = self._meta()
        if meta.get("enabled") and not confirm_routing_conflict:
            conflict = self._routing_conflict(scope, clean)
            if conflict:
                return {"success": False, "error": conflict["message"], "conflict": conflict}
        meta["scope"] = scope
        meta["devices"] = clean
        self._save_meta(meta)
        # If already running, re-apply so the new scope/devices take effect live.
        if meta.get("enabled"):
            return await self.enable(confirm_routing_conflict=True)
        return {"success": True, **self.config_meta()}

    # ── lifecycle ─────────────────────────────────────────────────────────────
    async def enable(self, confirm_routing_conflict: bool = False) -> Dict[str, Any]:
        if not self._conf_path.exists():
            return {"success": False, "error": "Import a VPN config first"}
        meta = self._meta()
        if meta.get("engine") == "openvpn":
            text = self._conf_path.read_text(encoding="utf-8", errors="ignore")
            if self._requires_credentials(text) and not self._credentials_configured():
                return {
                    "success": False,
                    "error": "OpenVPN username and password are required; save them first",
                }
        scope = meta["scope"]
        ips = self._resolve_ips(meta) if scope == "selected" else []
        macs = self._resolve_macs(meta) if scope == "selected" else []
        if scope == "selected" and not macs:
            return {"success": False, "error": "Selected scope requires at least one device MAC address"}
        if not confirm_routing_conflict:
            conflict = self._routing_conflict(scope, meta.get("devices") or [])
            if conflict:
                return {"success": False, "error": conflict["message"], "conflict": conflict}
        res = await self._run(
            "up", str(self._conf_path), meta["engine"], scope, ",".join(ips), ",".join(macs),
            timeout=185,
        )
        if res.get("running"):
            meta["enabled"] = True
            self._save_meta(meta)
            self._applied_macs = set(macs)
        elif res.get("error"):
            return res
        return await self.status()

    async def disable(self) -> Dict[str, Any]:
        res = await self._run("down", timeout=45)
        if not res.get("success"):
            return res
        if res.get("running") or res.get("killswitch"):
            return {
                "success": False,
                "error": "Internet Encryption runtime is still active after Disable",
            }
        meta = self._meta()
        meta["enabled"] = False
        self._save_meta(meta)
        self._applied_macs = set()
        return await self.status()

    async def reconcile_if_needed(self) -> None:
        """Re-apply selected-device rules after a restart or target change."""
        meta = self._meta()
        if not meta.get("enabled") or meta.get("scope") != "selected":
            return
        macs = set(self._resolve_macs(meta))
        if macs and macs != self._applied_macs:
            ips = self._resolve_ips(meta)
            await self._run("reconcile", ",".join(ips), ",".join(sorted(macs)), timeout=30)
            self._applied_macs = macs

    async def status(self) -> Dict[str, Any]:
        st = await self._run("status", timeout=20)
        persisted = self._meta()
        if persisted.get("enabled") and not st.get("running") and not st.get("killswitch"):
            # Runtime state is intentionally ephemeral. After a reboot the
            # tunnel stays off; reconcile the persisted flag so conflict guards
            # do not claim a non-existent VPN is active.
            persisted["enabled"] = False
            self._save_meta(persisted)
        meta = self.config_meta()
        if not st.get("endpoint"):
            st["endpoint"] = meta.get("endpoint", "")
        st["configured"] = meta.get("configured", bool(st.get("configured")))
        st["engine"] = st.get("engine") or meta.get("engine", "")
        st["scope"] = meta.get("scope", st.get("scope", "all"))
        st["endpoint_host"] = meta.get("endpoint_host", "")
        st["address"] = meta.get("address", "")
        st["requires_credentials"] = bool(meta.get("requires_credentials"))
        st["credentials_configured"] = bool(meta.get("credentials_configured"))
        st["device_list"] = self._devices_with_live_ips(self._meta())
        st["online_targets"] = len(self._online_ips(self._meta())) if meta.get("scope") == "selected" else None
        return st

    async def delete_config(self) -> Dict[str, Any]:
        await self.disable()
        try:
            self._credential_command("delete")
            self._conf_path.unlink(missing_ok=True)
            self._meta_path.unlink(missing_ok=True)
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}
        return {"success": True, "configured": False}


_service: Optional[VpnClientService] = None


def get_vpn_client_service() -> VpnClientService:
    global _service
    if _service is None:
        _service = VpnClientService()
    return _service
