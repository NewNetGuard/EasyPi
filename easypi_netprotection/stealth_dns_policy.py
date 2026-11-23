"""Read the root-owned Chameleon DNS routing policy.

The policy contains no secrets.  It tells NetProtection which client queries
must use the dedicated fail-closed resolver instead of the ordinary upstream
pool.  A malformed existing policy fails closed for non-loopback clients.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


DEFAULT_POLICY_PATH = Path("/var/lib/easypi/stealth-policy/dns-policy.json")
ORDINARY = "ordinary"
PROTECTED = "protected"
NEED_MAC = "need_mac"
INDETERMINATE = "indeterminate"


class StealthDNSPolicy:
    def __init__(self, path: Path | None = None) -> None:
        configured = os.getenv("EASYPI_STEALTH_DNS_POLICY", "").strip()
        self.path = path or (Path(configured) if configured else DEFAULT_POLICY_PATH)

    def _load(self) -> dict[str, Any] | None:
        try:
            parent = os.stat(self.path.parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            return {"enabled": True, "invalid": True}
        if (
            not stat.S_ISDIR(parent.st_mode)
            or (os.name != "nt" and parent.st_uid != 0)
            or parent.st_mode & 0o022
        ):
            return {"enabled": True, "invalid": True}
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            return None
        except OSError:
            return {"enabled": True, "invalid": True}
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size > 64 * 1024
                or (os.name != "nt" and info.st_uid != 0)
                or info.st_mode & 0o022
            ):
                return {"enabled": True, "invalid": True}
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                value = json.load(handle)
            if not isinstance(value, dict):
                raise ValueError("policy is not an object")
            if value.get("version") != 1 or not isinstance(value.get("enabled"), bool):
                raise ValueError("invalid policy header")
            scope = value.get("scope")
            if scope not in {"all", "selected"}:
                raise ValueError("invalid scope")
            raw_ips = value.get("ips")
            raw_macs = value.get("macs")
            if (
                not isinstance(raw_ips, list)
                or not isinstance(raw_macs, list)
                or len(raw_ips) > 256
                or len(raw_macs) > 256
            ):
                raise ValueError("invalid device list")
            ips: list[str] = []
            for raw_ip in raw_ips:
                address = ipaddress.ip_address(str(raw_ip))
                if (
                    address.version != 4
                    or address.is_unspecified
                    or address.is_multicast
                ):
                    raise ValueError("invalid device IP")
                ips.append(str(address))
            mac_pattern = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
            macs = [str(raw_mac).strip().lower() for raw_mac in raw_macs]
            if any(not mac_pattern.fullmatch(mac) for mac in macs):
                raise ValueError("invalid device MAC")
            if scope == "selected" and not macs:
                raise ValueError("empty selected policy")
            return {
                "version": 1,
                "enabled": value["enabled"],
                "scope": scope,
                "ips": ips,
                "macs": macs,
                "block_quic": value.get("block_quic", True) is not False,
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return {"enabled": True, "invalid": True}
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _is_loopback(client_ip: str) -> bool:
        try:
            return ipaddress.ip_address(client_ip).is_loopback
        except ValueError:
            return False

    def classify(
        self,
        client_ip: str,
        client_mac: str | None = None,
        *,
        mac_lookup_complete: bool = False,
    ) -> str:
        """Classify a client without treating missing identity as permission.

        A selected-device policy needs a MAC lookup when the current IP is not
        already recorded.  If that lookup cannot identify the client, callers
        must fail the query closed instead of using the ordinary DNS path.
        """
        policy = self._load()
        if not policy or not policy.get("enabled") or self._is_loopback(client_ip):
            return ORDINARY
        if policy.get("invalid"):
            return PROTECTED
        if policy.get("scope") == "all":
            return PROTECTED
        if policy.get("scope") != "selected":
            return PROTECTED
        normalized_ip = str(client_ip).strip()
        normalized_mac = str(client_mac or "").strip().lower()
        ips = {str(value).strip() for value in policy.get("ips", [])}
        macs = {str(value).strip().lower() for value in policy.get("macs", [])}
        if normalized_ip in ips:
            return PROTECTED
        if not mac_lookup_complete:
            return NEED_MAC
        if not normalized_mac:
            return INDETERMINATE
        return PROTECTED if normalized_mac in macs else ORDINARY

    def active_for(self, client_ip: str, client_mac: str | None = None) -> bool:
        return (
            self.classify(
                client_ip,
                client_mac,
                mac_lookup_complete=client_mac is not None,
            )
            == PROTECTED
        )

    def may_need_mac(self, client_ip: str) -> bool:
        return self.classify(client_ip) == NEED_MAC
