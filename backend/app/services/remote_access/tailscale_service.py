"""
TailscaleRemoteAccessService

Single-action Tailscale gateway service for EasyPi.
Handles all complexity internally - user only sees ON/OFF.

Features:
- Auto-detects LAN CIDR from network interface
- Always runs as Subnet Router + Exit Node
- Auth key from config/environment only
- Manages IP forwarding and firewall rules
"""

import asyncio
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core.encryption import decrypt_password, encrypt_password, is_encrypted
from app.core.installer import create_install_job, start_install_job, read_installer_log
from app.core.paths import get_backend_data_dir, get_data_dir, get_easypi_root
from app.schemas.tailscale import (
    NetworkInfo,
    TailscaleInfo,
    TailscalePeer,
    TailscaleStatus as TailscaleConnectionStatus,
)

from ..remote_access.tailscale_config import TailscaleConfig, get_tailscale_config

logger = logging.getLogger(__name__)

# The Taildrop importer runs as root; its status file is trusted only when
# owned by this uid.
TRUSTED_OWNER_UID = 0

@dataclass
class TailscaleStatus:
    """Current status of Tailscale remote access."""
    enabled: bool
    tailscale_running: bool
    lan_cidr: Optional[str]
    tailscale_ips: list[str]
    advertised_routes: list[str]
    exit_node_advertised: bool
    hostname: Optional[str]
    tailnet: Optional[str]
    backend_state: Optional[str]
    last_error: Optional[str]
    last_enabled_at: Optional[str]
    taildrop_importer_active: bool
    taildrop_device_eligible: bool
    taildrop_error: Optional[str]
    taildrop_free_bytes: Optional[int]
    taildrop_reserve_bytes: Optional[int]
    
    def to_dict(self) -> dict:
        return asdict(self)


class TailscaleRemoteAccessService:
    """
    Service for managing Tailscale as a simple ON/OFF VPN gateway.
    
    All configuration is internal - no user input required except ON/OFF.
    """
    
    def __init__(self, config: Optional[TailscaleConfig] = None):
        self.config = config or get_tailscale_config()
        # Tailscale state is project-level runtime data in every deployment mode.
        # Older venv installations wrote it below backend/data; migrate that file
        # once so switching between venv and native-binary mode keeps all settings.
        data_dir = Path(os.environ["EASYPI_DATA_DIR"]) if os.environ.get("EASYPI_DATA_DIR") else get_data_dir()
        backend_data_dir = (
            Path(os.environ["EASYPI_BACKEND_DATA_DIR"])
            if os.environ.get("EASYPI_BACKEND_DATA_DIR")
            else get_backend_data_dir()
        )
        self.state_file = data_dir / "tailscale_state.json"
        self.legacy_state_file = backend_data_dir / "tailscale_state.json"
        self._state_lock = threading.RLock()
        self._ensure_state_dir()
        self._migrate_legacy_state()
    
    def _ensure_state_dir(self) -> None:
        """Ensure state directory exists."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            if not os.access(self.state_file.parent, os.W_OK):
                raise PermissionError("State dir not writable")
        except PermissionError:
            raise RuntimeError("EasyPi data directory is not writable")

    def _install_lock_path(self) -> Path:
        return self.state_file.parent / "tailscale_installing.lock"

    def _load_taildrop_status(self) -> dict[str, object]:
        status_path = Path(
            os.getenv(
                "EASYPI_TAILDROP_STATUS_FILE",
                "/var/lib/easypi/taildrop/status.json",
            )
        )
        try:
            details = status_path.lstat()
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                return {}
            if details.st_size > 4096 or (
                os.name == "posix"
                and (details.st_uid != TRUSTED_OWNER_UID or details.st_mode & 0o022)
            ):
                return {}
            payload = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _migrate_legacy_state(self) -> None:
        """Move the old backend-data state to the canonical data directory."""
        if self.state_file.exists() or not self.legacy_state_file.exists():
            return
        try:
            try:
                self.legacy_state_file.replace(self.state_file)
            except OSError:
                shutil.copy2(self.legacy_state_file, self.state_file)
                self.legacy_state_file.unlink()
            self.state_file.chmod(0o600)
            logger.info("Migrated Tailscale state to %s", self.state_file)
        except OSError as exc:
            logger.error(
                "Could not migrate Tailscale state from %s to %s: %s",
                self.legacy_state_file,
                self.state_file,
                exc,
            )
            raise RuntimeError("Could not migrate legacy Tailscale state") from exc
    
    def _load_state(self) -> dict:
        """Load persisted state."""
        with self._state_lock:
            if self.state_file.exists():
                try:
                    state = json.loads(self.state_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    logger.error("Could not read Tailscale state from %s: %s", self.state_file, exc)
                    raise RuntimeError("Tailscale state is unavailable or corrupted") from exc
                if not isinstance(state, dict):
                    logger.error("Invalid Tailscale state format in %s", self.state_file)
                    raise RuntimeError("Tailscale state has an invalid format")
                return state
        return {"enabled": False, "last_lan_cidr": None, "last_error": None, "last_enabled_at": None}
    
    def _save_state(self, state: dict, *, update_authkey: bool = False) -> None:
        """Persist state to disk."""
        with self._state_lock:
            state_to_save = dict(state)
            if self.state_file.exists():
                existing_state = self._load_state()
                if "authkey" in existing_state and not update_authkey:
                    state_to_save["authkey"] = existing_state["authkey"]
            temporary_file = self.state_file.with_suffix(f"{self.state_file.suffix}.tmp")
            try:
                temporary_file.write_text(json.dumps(state_to_save, indent=2), encoding="utf-8")
                # State can hold an encrypted Tailscale auth key; keep both the temporary
                # and final files owner-only on platforms that support POSIX modes.
                temporary_file.chmod(0o600)
                temporary_file.replace(self.state_file)
            except OSError as exc:
                logger.error("Could not persist Tailscale state to %s: %s", self.state_file, exc)
                try:
                    temporary_file.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove temporary Tailscale state %s", temporary_file)
                raise RuntimeError("Could not persist Tailscale state") from exc
    
    def save_authkey(self, authkey: str) -> dict:
        """
        Save auth key to state file.
        This allows users to configure the auth key via UI.
        """
        try:
            state = self._load_state()
            state["authkey"] = encrypt_password(authkey)
            self._save_state(state, update_authkey=True)
            # Update config in memory
            self.config.authkey = authkey
            return {"success": True}
        except Exception as e:
            return {
                "success": False,
                "error": {
                    "message": "Failed to save auth key",
                    "code": "SAVE_ERROR",
                    "details": str(e)
                }
            }
    
    def _get_authkey(self) -> str:
        """Get auth key from config or saved state."""
        # First check environment/config
        if self.config.authkey:
            return self.config.authkey
        # Then check saved state
        state = self._load_state()
        stored = state.get("authkey", "")
        if not isinstance(stored, str):
            return ""
        authkey = decrypt_password(stored)
        if authkey and not is_encrypted(stored):
            state["authkey"] = encrypt_password(authkey)
            self._save_state(state, update_authkey=True)
        return authkey
    
    def _run_command(self, cmd: list[str], check: bool = False) -> tuple[bool, str, str]:
        """
        Run a shell command.
        Returns (success, stdout, stderr).
        """
        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def _run_tailscale_control(
        self, request: dict
    ) -> tuple[bool, str, str]:
        """Run one schema-validated privileged Tailscale operation."""
        cmd = [
            "sudo",
            "-n",
            str(get_easypi_root() / "scripts" / "runner"),
            "settings/tailscale_control.sh",
        ]
        try:
            result = subprocess.run(
                cmd,
                input=json.dumps(request, separators=(",", ":")),
                check=False,
                capture_output=True,
                text=True,
                timeout=95,
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Tailscale command timed out"
        except Exception as exc:
            return False, "", str(exc)
    
    def _detect_lan_cidr(self) -> Optional[str]:
        """
        Auto-detect LAN CIDR from network interface.
        
        Uses `ip addr` to find the primary interface's IP and netmask,
        then derives the CIDR notation.
        """
        interface = self.config.interface
        
        # Try to get IP info from the specified interface
        success, stdout, _ = self._run_command(["ip", "-j", "addr", "show", interface])
        
        if success and stdout:
            try:
                data = json.loads(stdout)
                if data and len(data) > 0:
                    for addr_info in data[0].get("addr_info", []):
                        if addr_info.get("family") == "inet":
                            ip = addr_info.get("local")
                            prefixlen = addr_info.get("prefixlen")
                            if ip and prefixlen:
                                # Calculate network address
                                return self._ip_to_cidr(ip, prefixlen)
            except json.JSONDecodeError:
                pass
        
        # Fallback: try parsing ip addr output directly
        success, stdout, _ = self._run_command(["ip", "addr", "show", interface])
        if success and stdout:
            # Match inet x.x.x.x/xx
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', stdout)
            if match:
                ip, prefixlen = match.group(1), int(match.group(2))
                return self._ip_to_cidr(ip, prefixlen)
        
        # Last resort: try to find any non-loopback interface
        success, stdout, _ = self._run_command(["ip", "-j", "route", "get", "1.1.1.1"])
        if success and stdout:
            try:
                data = json.loads(stdout)
                if data:
                    src_ip = data[0].get("prefsrc")
                    if src_ip:
                        # Get CIDR for this IP
                        success2, stdout2, _ = self._run_command(["ip", "-j", "addr"])
                        if success2:
                            addrs = json.loads(stdout2)
                            for iface in addrs:
                                for addr_info in iface.get("addr_info", []):
                                    if addr_info.get("local") == src_ip:
                                        prefixlen = addr_info.get("prefixlen")
                                        if prefixlen:
                                            return self._ip_to_cidr(src_ip, prefixlen)
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _ip_to_cidr(self, ip: str, prefixlen: int) -> str:
        """Convert IP address and prefix length to network CIDR."""
        parts = [int(p) for p in ip.split('.')]
        # Create netmask from prefix length
        mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
        mask_parts = [
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        ]
        # Calculate network address
        network = [parts[i] & mask_parts[i] for i in range(4)]
        return f"{'.'.join(map(str, network))}/{prefixlen}"
    
    def _enable_ip_forwarding(self) -> tuple[bool, str]:
        """Enable IP forwarding for routing."""
        command = [
            "sudo",
            "-n",
            str(get_easypi_root() / "scripts" / "runner"),
            "settings/network_firewall.sh",
            "forwarding-enable",
        ]
        success, _, stderr = self._run_command(command)
        if not success:
            return False, stderr
        return True, "IP forwarding enabled"
    
    def _setup_nat_rules(self, lan_cidr: str) -> tuple[bool, str]:
        """Set up NAT/masquerade rules for the subnet."""
        cmd = [
            "sudo", "-n", str(get_easypi_root() / "scripts" / "runner"),
            "settings/network_firewall.sh", "tailscale-nat", "add",
            lan_cidr, "tailscale0",
        ]
        success, _, stderr = self._run_command(cmd)
        
        if not success and "already exists" not in stderr.lower():
            return False, f"Failed to set NAT rules: {stderr}"
        
        return True, "NAT rules configured"

    def _set_exit_node_forwarding_optimization(self, action: str) -> None:
        """Apply or restore Tailscale's Linux UDP forwarding offloads."""
        if action not in {"apply", "restore"}:
            raise ValueError("Unsupported Tailscale performance action")
        command = [
            "sudo",
            "-n",
            str(get_easypi_root() / "scripts" / "runner"),
            "settings/tailscale_performance.sh",
            action,
        ]
        success, _, stderr = self._run_command(command)
        if not success:
            logger.warning(
                "Could not %s Tailscale exit-node performance settings: %s",
                action,
                stderr.strip() or "unknown error",
            )
    
    def _get_tailscale_status_json(self) -> Optional[dict]:
        """Get tailscale status as JSON."""
        success, stdout, _ = self._run_command(["tailscale", "status", "--json"])
        if success and stdout:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                pass
        return None

    def _get_tailscale_prefs(self) -> Optional[dict]:
        """Get tailscale prefs as JSON."""
        success, stdout, _ = self._run_tailscale_control({"action": "prefs"})
        if success and stdout:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                pass
        return None

    def _needs_login(self, status: Optional[dict]) -> bool:
        """Determine if tailscale needs login."""
        if not status:
            return True
        if status.get("AuthURL"):
            return True
        if status.get("BackendState") == "NeedsLogin":
            return True
        return False

    def _summarize_tailscale_health(self, status: Optional[dict]) -> Optional[str]:
        """Extract a readable health summary from tailscale status."""
        if not status:
            return None
        health = status.get("Health")
        if not health:
            return None
        messages: list[str] = []
        if isinstance(health, dict):
            for value in health.values():
                if isinstance(value, dict):
                    msg = value.get("Message") or value.get("message") or str(value)
                    severity = value.get("Severity") or value.get("severity")
                    messages.append(f"{severity}: {msg}" if severity else str(msg))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            msg = item.get("Message") or item.get("message") or str(item)
                            severity = item.get("Severity") or item.get("severity")
                            messages.append(f"{severity}: {msg}" if severity else str(msg))
                        else:
                            messages.append(str(item))
                else:
                    messages.append(str(value))
        if messages:
            return "; ".join(messages)
        return None

    def _format_tailscale_debug(self, status: Optional[dict]) -> str:
        """Build a concise debug string from tailscale status."""
        if not status:
            return "Tailscale status unavailable"
        parts: list[str] = []
        backend_state = status.get("BackendState")
        if backend_state:
            parts.append(f"BackendState={backend_state}")
        health_summary = self._summarize_tailscale_health(status)
        if health_summary:
            parts.append(f"Health={health_summary}")
        return "; ".join(parts) if parts else "Tailscale status unavailable"

    def _wait_for_tailscale_running(self, timeout_seconds: int = 20, interval_seconds: int = 2) -> tuple[bool, Optional[dict]]:
        """Wait briefly for Tailscale to reach Running state."""
        deadline = time.monotonic() + timeout_seconds
        last_status: Optional[dict] = None
        while time.monotonic() < deadline:
            status = self._get_tailscale_status_json()
            if status:
                last_status = status
                if status.get("BackendState") == "Running":
                    return True, status
            time.sleep(interval_seconds)
        return False, last_status
    
    def _is_tailscale_running(self) -> bool:
        """Check if tailscale is currently connected."""
        status = self._get_tailscale_status_json()
        if status:
            backend_state = status.get("BackendState", "")
            return backend_state == "Running"
        return False
    
    def enable_remote_access(self) -> dict:
        """
        Enable remote VPN access.
        
        - Detects LAN CIDR automatically
        - Runs tailscale up with fixed configuration
        - Enables IP forwarding
        - Sets up NAT rules
        
        Returns result dict with success status and details.
        """
        state = self._load_state()
        
        status_before = self._get_tailscale_status_json()
        already_running = bool(status_before and status_before.get("BackendState") == "Running")

        # Get auth key (from env or saved state)
        authkey = self._get_authkey()
        
        # Validate auth key only when we need to log in
        if not authkey and not already_running:
            return {
                "success": False,
                "error": {
                    "message": "Tailscale auth key not configured",
                    "code": "AUTH_KEY_MISSING",
                    "details": "Please enter your Tailscale auth key in the settings"
                }
            }
        
        # Detect LAN CIDR
        lan_cidr = self._detect_lan_cidr()
        if not lan_cidr:
            return {
                "success": False,
                "error": {
                    "message": "Could not detect LAN CIDR",
                    "code": "CIDR_DETECTION_FAILED",
                    "details": f"Failed to detect network on interface {self.config.interface}"
                }
            }
        
        # Enable IP forwarding
        fwd_success, fwd_msg = self._enable_ip_forwarding()
        if not fwd_success:
            return {
                "success": False,
                "error": {
                    "message": "Failed to enable IP forwarding",
                    "code": "IP_FORWARD_ERROR",
                    "details": fwd_msg
                }
            }

        if already_running:
            set_success, _, set_err = self._run_tailscale_control(
                {
                    "action": "set",
                    "routes": [lan_cidr],
                    "advertise_exit_node": True,
                    "accept_dns": False,
                }
            )
            state["enabled"] = set_success
            state["last_lan_cidr"] = lan_cidr
            state["last_enabled_at"] = datetime.now().isoformat()
            state["last_error"] = None
            if not set_success:
                warning = set_err.strip() if set_err else "Failed to apply Tailscale settings"
                state["last_error"] = warning
            self._save_state(state)
            if set_success:
                self._setup_nat_rules(lan_cidr)
                self._set_exit_node_forwarding_optimization("apply")
            details = "Tailscale is already running; settings applied."
            if state["last_error"]:
                details = f"Tailscale is running, but required routes were not applied. {state['last_error']}"
            response = {
                "success": set_success,
                "lan_cidr": lan_cidr,
                "details": details,
                "status": self.get_status().to_dict()
            }
            if not set_success:
                response["error"] = {
                    "message": "Required Tailscale routes were not applied",
                    "code": "TAILSCALE_SETTINGS_ERROR",
                    "details": state["last_error"],
                }
            return response

        # Build and run tailscale up command
        needs_login = self._needs_login(status_before)
        request = {
            "action": "up",
            "routes": [lan_cidr],
            "advertise_exit_node": True,
            "accept_dns": False,
            "reset": True,
            "timeout": 60,
        }
        if needs_login:
            request["auth_key"] = authkey
        
        success, stdout, stderr = self._run_tailscale_control(request)
        
        if not success:
            status = self._get_tailscale_status_json()
            prefs = self._get_tailscale_prefs()
            debug_info = self._format_tailscale_debug(status)
            details_parts = []
            if stderr:
                details_parts.append(stderr.strip())
            if debug_info:
                details_parts.append(debug_info)
            details = "; ".join(details_parts) if details_parts else "No additional details"
            backend_state = status.get("BackendState") if status else None

            advertised_routes = (prefs or {}).get("AdvertiseRoutes", []) or []
            exit_node_advertised = bool((prefs or {}).get("AdvertiseExitNode", False))
            if backend_state == "Running" and lan_cidr in advertised_routes and exit_node_advertised:
                state["enabled"] = True
                state["last_lan_cidr"] = lan_cidr
                state["last_error"] = None
                state["last_enabled_at"] = datetime.now().isoformat()
                self._save_state(state)
                self._setup_nat_rules(lan_cidr)
                self._set_exit_node_forwarding_optimization("apply")
                return {
                    "success": True,
                    "lan_cidr": lan_cidr,
                    "details": "Tailscale is already running with the required settings.",
                    "status": self.get_status().to_dict()
                }

            if backend_state == "Running":
                fallback_success, _, fallback_err = self._run_tailscale_control(
                    {
                        "action": "set",
                        "routes": [lan_cidr],
                        "advertise_exit_node": True,
                        "accept_dns": False,
                    }
                )
                warning = fallback_err.strip() if fallback_err else ""
                state["enabled"] = fallback_success
                state["last_lan_cidr"] = lan_cidr
                state["last_error"] = None if fallback_success else (
                    warning or "Failed to apply Tailscale settings"
                )
                state["last_enabled_at"] = datetime.now().isoformat()
                self._save_state(state)
                if fallback_success:
                    self._setup_nat_rules(lan_cidr)
                    self._set_exit_node_forwarding_optimization("apply")
                    details = "Tailscale is running; settings applied via fallback."
                elif warning:
                    details = f"Tailscale is running; could not apply settings automatically. {warning}"
                else:
                    details = "Tailscale is running; settings apply status unknown."
                response = {
                    "success": fallback_success,
                    "lan_cidr": lan_cidr,
                    "details": details,
                    "status": self.get_status().to_dict()
                }
                if not fallback_success:
                    response["error"] = {
                        "message": "Required Tailscale routes were not applied",
                        "code": "TAILSCALE_SETTINGS_ERROR",
                        "details": state["last_error"],
                    }
                return response

            message = "Failed to start Tailscale"
            if backend_state:
                message = f"Failed to start Tailscale (state: {backend_state})"
            state["last_error"] = details
            self._save_state(state)
            return {
                "success": False,
                "error": {
                    "message": message,
                    "code": "TAILSCALE_EXEC_ERROR",
                    "details": details
                }
            }

        running, status = self._wait_for_tailscale_running()
        if not running:
            debug_info = self._format_tailscale_debug(status)
            backend_state = status.get("BackendState") if status else None
            if backend_state in {"NeedsLogin", "Stopped"}:
                message = "Tailscale requires login"
                if backend_state == "Stopped":
                    message = "Tailscale service is stopped"
                state["last_error"] = debug_info
                self._save_state(state)
                return {
                    "success": False,
                    "error": {
                        "message": message,
                        "code": "TAILSCALE_NOT_RUNNING",
                        "details": debug_info
                    }
                }

            message = "Tailscale is starting. Waiting for it to come online."
            if backend_state:
                message = f"Tailscale is starting (state: {backend_state}). Waiting for it to come online."

            state["enabled"] = True
            state["last_lan_cidr"] = lan_cidr
            state["last_error"] = None
            state["last_enabled_at"] = datetime.now().isoformat()
            self._save_state(state)

            return {
                "success": True,
                "pending": True,
                "lan_cidr": lan_cidr,
                "details": f"{message} {debug_info}" if debug_info else message,
                "status": self.get_status().to_dict()
            }
        
        # Set up NAT rules (non-fatal if fails)
        self._setup_nat_rules(lan_cidr)
        self._set_exit_node_forwarding_optimization("apply")
        
        # Update state
        state["enabled"] = True
        state["last_lan_cidr"] = lan_cidr
        state["last_error"] = None
        state["last_enabled_at"] = datetime.now().isoformat()
        self._save_state(state)
        
        # Get current status
        status = self.get_status()
        
        return {
            "success": True,
            "lan_cidr": lan_cidr,
            "details": "Remote VPN access enabled",
            "status": status.to_dict()
        }
    
    def disable_remote_access(self) -> dict:
        """
        Disable remote VPN access.
        
        - Runs tailscale down
        - Updates state
        
        Returns result dict with success status.
        """
        state = self._load_state()
        
        status_before = self._get_tailscale_status_json()
        backend_state_before = status_before.get("BackendState") if status_before else None
        if backend_state_before and backend_state_before != "Running":
            self._set_exit_node_forwarding_optimization("restore")
            state["enabled"] = False
            state["last_error"] = None
            self._save_state(state)
            return {
                "success": True,
                "details": "Tailscale already stopped",
                "status": self.get_status().to_dict()
            }

        # Run tailscale down
        success, stdout, stderr = self._run_tailscale_control({"action": "down"})

        if not success:
            status_after = self._get_tailscale_status_json()
            backend_state_after = status_after.get("BackendState") if status_after else None
            if backend_state_after and backend_state_after != "Running":
                self._set_exit_node_forwarding_optimization("restore")
                state["enabled"] = False
                state["last_error"] = None
                self._save_state(state)
                details = "Tailscale already stopped"
                if stderr:
                    details = f"{details}. {stderr.strip()}"
                return {
                    "success": True,
                    "details": details,
                    "status": self.get_status().to_dict()
                }

            fallback_success, _, fallback_err = self._run_tailscale_control(
                {
                    "action": "set",
                    "routes": [],
                    "advertise_exit_node": False,
                    "accept_dns": False,
                }
            )
            if fallback_success:
                self._set_exit_node_forwarding_optimization("restore")
                state["enabled"] = True
                state["last_error"] = (
                    "Tailscale is still running. Subnet and exit-node routes were disabled, "
                    "but direct remote access to EasyPi may remain available."
                )
                self._save_state(state)
                return {
                    "success": False,
                    "details": state["last_error"],
                    "status": self.get_status().to_dict(),
                    "error": {
                        "message": "Tailscale could not be stopped",
                        "code": "TAILSCALE_STILL_RUNNING",
                        "details": state["last_error"],
                    },
                }

            state["last_error"] = stderr or fallback_err
            self._save_state(state)
            return {
                "success": False,
                "error": {
                    "message": "Failed to stop Tailscale",
                    "code": "TAILSCALE_EXEC_ERROR",
                    "details": stderr or fallback_err
                }
            }
        
        # Update state
        self._set_exit_node_forwarding_optimization("restore")
        state["enabled"] = False
        state["last_error"] = None
        self._save_state(state)
        
        return {
            "success": True,
            "details": "Remote VPN access disabled",
            "status": self.get_status().to_dict()
        }
    
    def get_install_status(self) -> dict:
        """
        Check if Tailscale is installed on the system.
        
        Returns dict with:
        - installed: bool
        - version: str or None
        - installing: bool (if install is in progress)
        """
        # Check for lock file indicating installation in progress
        lock_file = self._install_lock_path()
        if lock_file.exists():
            return {
                "installed": False,
                "version": None,
                "installing": True
            }

        # Check if tailscale binary exists (support /usr/sbin)
        known_paths = [
            Path("/usr/bin/tailscale"),
            Path("/usr/sbin/tailscale"),
            Path("/bin/tailscale"),
            Path("/usr/local/bin/tailscale"),
        ]
        tailscale_path = next((p for p in known_paths if p.exists()), None)

        # Check dpkg if installed (useful if PATH lookup fails)
        dpkg_installed = False
        dpkg_version = None
        success, stdout, _stderr = self._run_command(["dpkg-query", "-W", "-f=${Version}", "tailscale"])
        if success and stdout:
            dpkg_installed = True
            dpkg_version = stdout.strip() or None

        if tailscale_path is None:
            # Fall back to PATH lookup
            success, stdout, _stderr = self._run_command([
                "env",
                "PATH=/usr/sbin:/usr/bin:/bin",
                "bash",
                "-lc",
                "command -v tailscale",
            ])
            if success and stdout:
                tailscale_path = Path(stdout.strip())

        if tailscale_path is None:
            # Try to locate binary via dpkg file list
            success, stdout, _stderr = self._run_command(["dpkg", "-L", "tailscale"])
            if success and stdout:
                for line in stdout.splitlines():
                    if line.endswith("/tailscale"):
                        candidate = Path(line.strip())
                        if candidate.exists():
                            tailscale_path = candidate
                            break

        if tailscale_path is None and dpkg_installed:
            return {
                "installed": True,
                "version": dpkg_version,
                "installing": False
            }

        if tailscale_path is None:
            return {
                "installed": False,
                "version": None,
                "installing": False
            }
        
        # Get version
        success, stdout, stderr = self._run_command([str(tailscale_path), "--version"])
        version = None
        if success and stdout:
            # First line is typically the version
            version = stdout.strip().split('\n')[0].strip()
        if not version:
            version = dpkg_version
        
        return {
            "installed": True,
            "version": version,
            "installing": False
        }
    
    async def install_tailscale(self) -> dict:
        """
        Install Tailscale using the official install script.
        
        Returns dict with:
        - success: bool
        - message: str
        - version: str or None
        - error: ErrorDetail or None
        """
        import asyncio
        
        # Check if already installed
        status = self.get_install_status()
        if status["installed"]:
            return {
                "success": True,
                "message": f"Tailscale is already installed (version: {status['version']})",
                "version": status["version"],
                "error": None
            }
        
        if status["installing"]:
            return {
                "success": False,
                "message": "Installation is already in progress",
                "version": None,
                "error": {
                    "message": "Installation already in progress",
                    "code": "INSTALL_IN_PROGRESS",
                    "details": None
                }
            }
        
        # Create lock file
        lock_file = self._install_lock_path()
        lock_acquired = False
        try:
            lock_fd = os.open(
                lock_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(lock_fd)
            lock_acquired = True
            
            # Run the Tailscale install script via installer service
            job_id = create_install_job("services/tailscale.sh", ["install"])
            result = await asyncio.to_thread(start_install_job, job_id, 600)
            
            if result.returncode != 0:
                log_tail = read_installer_log(job_id)
                error_details = (result.stderr or result.stdout or log_tail or "Unknown error").strip()
                return {
                    "success": False,
                    "message": f"Failed to install Tailscale: {error_details[:200]}",
                    "version": None,
                    "error": {
                        "message": "Installation script failed",
                        "code": "INSTALL_FAILED",
                        "details": error_details
                    }
                }
            
            # Remove lock before verification so status doesn't report "installing"
            if lock_file.exists():
                try:
                    lock_file.unlink()
                    lock_acquired = False
                except OSError as exc:
                    logger.warning("Could not remove Tailscale installation lock: %s", exc)

            # Verify installation
            new_status = self.get_install_status()
            if new_status["installed"]:
                return {
                    "success": True,
                    "message": f"Tailscale installed successfully (version: {new_status['version']})",
                    "version": new_status["version"],
                    "error": None
                }
            else:
                return {
                    "success": False,
                    "message": "Installation completed but Tailscale not found",
                    "version": None,
                    "error": {
                        "message": "Binary not found after installation",
                        "code": "VERIFY_FAILED",
                        "details": None
                    }
                }
                
        except FileExistsError:
            return {
                "success": False,
                "message": "Installation is already in progress",
                "version": None,
                "error": {
                    "message": "Installation already in progress",
                    "code": "INSTALL_IN_PROGRESS",
                    "details": None,
                },
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Installation timed out",
                "version": None,
                "error": {
                "message": "Installation timed out",
                    "code": "TIMEOUT",
                    "details": None
                }
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Installation error: {str(e)}",
                "version": None,
                "error": {
                    "message": str(e),
                    "code": "INSTALL_ERROR",
                    "details": None
                }
            }
        finally:
            # Ensure lock file removed
            if lock_acquired and lock_file.exists():
                try:
                    lock_file.unlink()
                except OSError as exc:
                    logger.warning("Could not remove Tailscale installation lock: %s", exc)

    async def uninstall_tailscale(self) -> dict:
        """
        Uninstall Tailscale using the service script.

        Returns dict with:
        - success: bool
        - message: str
        - error: ErrorDetail or None
        """
        import asyncio

        status = self.get_install_status()
        if not status["installed"]:
            return {
                "success": True,
                "message": "Tailscale is not installed",
                "error": None,
            }

        try:
            job_id = create_install_job("services/tailscale.sh", ["uninstall"])
            result = await asyncio.to_thread(start_install_job, job_id, 600)

            if result.returncode != 0:
                log_tail = read_installer_log(job_id)
                error_details = (result.stderr or result.stdout or log_tail or "Unknown error").strip()
                return {
                    "success": False,
                    "message": f"Failed to uninstall Tailscale: {error_details[:200]}",
                    "error": {
                        "message": "Uninstall failed",
                        "code": "UNINSTALL_FAILED",
                        "details": error_details,
                    },
                }

            # Verify removal
            new_status = self.get_install_status()
            if not new_status["installed"]:
                return {
                    "success": True,
                    "message": "Tailscale uninstalled successfully",
                    "error": None,
                }

            return {
                "success": False,
                "message": "Uninstall completed but Tailscale still detected",
                "error": {
                    "message": "Binary still present after uninstall",
                    "code": "VERIFY_FAILED",
                    "details": None,
                },
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "message": "Uninstall timed out",
                "error": {
                    "message": "Uninstall timed out",
                    "code": "TIMEOUT",
                    "details": None,
                },
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Uninstall error: {str(e)}",
                "error": {
                    "message": str(e),
                    "code": "UNINSTALL_ERROR",
                    "details": None,
                },
            }

    # ------------------------------------------------------------------ advanced API
    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return None

    @staticmethod
    def _extract_login_url(*values: str) -> Optional[str]:
        for value in values:
            for line in (value or "").splitlines():
                if "https://login.tailscale.com" not in line and "https://tailscale.com" not in line:
                    continue
                match = re.search(r"https://[^\s]+", line)
                if match:
                    return match.group(0)
        return None

    async def get_detailed_status(self) -> TailscaleInfo:
        """Return the detailed status used by the API and the EasyPi assistant."""
        install_status = await asyncio.to_thread(self.get_install_status)
        if not install_status["installed"]:
            return TailscaleInfo(status=TailscaleConnectionStatus.NOT_INSTALLED)

        data = await asyncio.to_thread(self._get_tailscale_status_json)
        if not data:
            return TailscaleInfo(status=TailscaleConnectionStatus.STOPPED)

        backend_state = str(data.get("BackendState") or "")
        if backend_state == "NeedsLogin":
            return TailscaleInfo(status=TailscaleConnectionStatus.NEEDS_LOGIN)
        if backend_state != "Running":
            return TailscaleInfo(status=TailscaleConnectionStatus.STOPPED)

        self_info = data.get("Self") or {}
        current_tailnet = data.get("CurrentTailnet") or {}
        peers: list[TailscalePeer] = []
        for peer_id, peer in (data.get("Peer") or {}).items():
            addresses = peer.get("TailscaleIPs") or []
            peers.append(
                TailscalePeer(
                    id=str(peer_id),
                    hostname=peer.get("HostName", "unknown"),
                    dns_name=str(peer.get("DNSName", "")).rstrip("."),
                    tailscale_ip=addresses[0] if addresses else "",
                    os=peer.get("OS", ""),
                    online=bool(peer.get("Online", False)),
                    last_seen=self._parse_timestamp(peer.get("LastSeen")),
                    is_exit_node=bool(peer.get("ExitNode", False)),
                    is_external=bool(peer.get("ShareeNode", False)),
                )
            )

        prefs = await asyncio.to_thread(self._get_tailscale_prefs)
        advertised_routes = list((prefs or {}).get("AdvertiseRoutes", []) or [])
        if not advertised_routes:
            advertised_routes = [
                route
                for route in (self_info.get("AllowedIPs") or [])
                if not route.startswith(("100.", "fd7a:"))
            ]
        tailscale_ips = self_info.get("TailscaleIPs") or []
        is_exit_node = bool((prefs or {}).get("AdvertiseExitNode", False))
        if not is_exit_node:
            is_exit_node = any(route in {"0.0.0.0/0", "::/0"} for route in advertised_routes)

        return TailscaleInfo(
            status=TailscaleConnectionStatus.CONNECTED,
            version=data.get("Version") or install_status.get("version"),
            hostname=self_info.get("HostName"),
            tailscale_ip=tailscale_ips[0] if tailscale_ips else None,
            tailnet_name=current_tailnet.get("Name"),
            dns_name=str(self_info.get("DNSName", "")).rstrip(".") or None,
            is_subnet_router=bool(advertised_routes),
            is_exit_node=is_exit_node,
            advertised_routes=advertised_routes,
            magic_dns_enabled=bool(data.get("MagicDNSSuffix")),
            peers=peers,
        )

    async def get_local_networks(self) -> list[NetworkInfo]:
        """Detect IPv4 LANs available for subnet routing."""
        success, stdout, _ = await asyncio.to_thread(
            self._run_command, ["ip", "-j", "addr", "show"]
        )
        networks: list[NetworkInfo] = []
        if success:
            try:
                interfaces = json.loads(stdout)
            except json.JSONDecodeError:
                interfaces = []
            for interface in interfaces:
                name = str(interface.get("ifname", ""))
                if name.startswith(("lo", "br-", "veth", "tailscale", "tun")):
                    continue
                for address in interface.get("addr_info", []):
                    if address.get("family") != "inet":
                        continue
                    ip_address = str(address.get("local", ""))
                    prefix = int(address.get("prefixlen", 24))
                    if not ip_address or ip_address.startswith("127."):
                        continue
                    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    networks.append(
                        NetworkInfo(
                            interface=name,
                            ip_address=ip_address,
                            netmask=(
                                f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}."
                                f"{(mask >> 8) & 0xFF}.{mask & 0xFF}"
                            ),
                            cidr=self._ip_to_cidr(ip_address, prefix),
                            is_default=name in {"eth0", "wlan0", "end0"},
                        )
                    )

        if not networks:
            success, stdout, _ = await asyncio.to_thread(
                self._run_command, ["hostname", "-I"]
            )
            if success:
                for address in stdout.split():
                    if "." not in address or address.startswith("127."):
                        continue
                    networks.append(
                        NetworkInfo(
                            interface="unknown",
                            ip_address=address,
                            netmask="255.255.255.0",
                            cidr=self._ip_to_cidr(address, 24),
                            is_default=True,
                        )
                    )
                    break

        networks.sort(key=lambda network: (not network.is_default, network.interface))
        return networks

    async def install(self) -> tuple[bool, str]:
        result = await self.install_tailscale()
        return bool(result.get("success")), str(result.get("message", ""))

    async def uninstall(self) -> tuple[bool, str]:
        result = await self.uninstall_tailscale()
        return bool(result.get("success")), str(result.get("message", ""))

    async def login(self, auth_key: Optional[str] = None) -> tuple[bool, str, Optional[str]]:
        if not (await asyncio.to_thread(self.get_install_status))["installed"]:
            return False, "Tailscale is not installed", None
        request: dict = {"action": "up", "timeout": 30}
        if auth_key:
            request["auth_key"] = auth_key
        success, stdout, stderr = await asyncio.to_thread(
            self._run_tailscale_control, request
        )
        if success:
            return True, "Logged in successfully", None
        login_url = self._extract_login_url(stdout, stderr)
        if login_url:
            return True, "Please open the URL to authenticate", login_url
        return False, f"Login failed: {stderr.strip() or 'unknown error'}", None

    async def setup_subnet_router(
        self,
        routes: list[str],
        auth_key: Optional[str] = None,
        accept_routes: bool = True,
        exit_node: bool = False,
        hostname: Optional[str] = None,
    ) -> tuple[bool, str, Optional[str]]:
        install_status = await asyncio.to_thread(self.get_install_status)
        if not install_status["installed"]:
            installed = await self.install_tailscale()
            if not installed.get("success"):
                return False, str(installed.get("message", "Installation failed")), None

        request: dict = {
            "action": "up",
            "routes": routes,
            "accept_routes": accept_routes,
            "advertise_exit_node": exit_node,
            "accept_dns": False,
            "timeout": 60,
        }
        if auth_key:
            request["auth_key"] = auth_key
        if hostname:
            request["hostname"] = hostname
        success, stdout, stderr = await asyncio.to_thread(
            self._run_tailscale_control, request
        )
        if not success:
            login_url = self._extract_login_url(stdout, stderr)
            if login_url:
                return True, "Please open the URL to authenticate", login_url
            return False, f"Setup failed: {stderr.strip() or 'unknown error'}", None

        forwarding, forwarding_error = await asyncio.to_thread(self._enable_ip_forwarding)
        if not forwarding:
            return False, f"Subnet router started but IP forwarding failed: {forwarding_error}", None
        state = self._load_state()
        state.update(
            enabled=True,
            last_lan_cidr=routes[0] if routes else None,
            last_error=None,
            last_enabled_at=datetime.now().isoformat(),
        )
        self._save_state(state)
        return True, f"Subnet router configured. Advertised routes: {', '.join(routes)}", None

    async def update_config(
        self,
        advertise_routes: Optional[list[str]] = None,
        accept_routes: Optional[bool] = None,
        exit_node: Optional[bool] = None,
    ) -> tuple[bool, str]:
        request: dict = {"action": "set"}
        if advertise_routes is not None:
            request["routes"] = advertise_routes
        if accept_routes is not None:
            request["accept_routes"] = accept_routes
        if exit_node is not None:
            request["advertise_exit_node"] = exit_node
        if len(request) == 1:
            return True, "No configuration changes requested"
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, request
        )
        if not success:
            return False, f"Update failed: {stderr.strip() or 'unknown error'}"
        return True, "Configuration updated"

    async def start(self) -> tuple[bool, str]:
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, {"action": "up", "timeout": 30}
        )
        return (
            (True, "Tailscale started")
            if success
            else (False, f"Start failed: {stderr.strip() or 'unknown error'}")
        )

    async def stop(self) -> tuple[bool, str]:
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, {"action": "down"}
        )
        if not success:
            return False, f"Stop failed: {stderr.strip() or 'unknown error'}"
        state = self._load_state()
        state.update(enabled=False, last_error=None)
        self._save_state(state)
        return True, "Tailscale stopped"

    async def logout(self) -> tuple[bool, str]:
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, {"action": "logout"}
        )
        if not success:
            return False, f"Logout failed: {stderr.strip() or 'unknown error'}"
        state = self._load_state()
        state.update(enabled=False, last_error=None)
        self._save_state(state)
        return True, "Logged out successfully"

    async def setup_funnel(self, port: int = 443) -> tuple[bool, str, Optional[str]]:
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, {"action": "funnel", "port": port}
        )
        if not success:
            return False, f"Funnel setup failed: {stderr.strip() or 'unknown error'}", None
        status = await self.get_detailed_status()
        url = f"https://{status.dns_name}" if status.dns_name else None
        return True, "Funnel enabled", url

    async def disable_funnel(self) -> tuple[bool, str]:
        success, _, stderr = await asyncio.to_thread(
            self._run_tailscale_control, {"action": "funnel", "off": True}
        )
        if not success:
            return False, f"Failed to disable funnel: {stderr.strip() or 'unknown error'}"
        return True, "Funnel disabled"
    
    def get_status(self) -> TailscaleStatus:
        """
        Get current status of remote access.
        
        Returns comprehensive status including:
        - Whether enabled (from internal state)
        - Whether Tailscale is actually running
        - Detected LAN CIDR
        - Tailnet IPs
        - Advertised routes
        - Exit node status
        """
        state = self._load_state()
        ts_status = self._get_tailscale_status_json()
        
        # Defaults
        tailscale_running = False
        tailscale_ips: list[str] = []
        advertised_routes: list[str] = []
        exit_node_advertised = False
        hostname = None
        tailnet = None
        backend_state = None
        taildrop_device_eligible = False
        taildrop_status = self._load_taildrop_status()
        
        if ts_status:
            backend_state = ts_status.get("BackendState")
            tailscale_running = backend_state == "Running"
            
            # Get self info
            self_status = ts_status.get("Self", {}) or {}
            tailscale_ips = self_status.get("TailscaleIPs") or []
            hostname = self_status.get("HostName")
            allowed_ips = self_status.get("AllowedIPs") or []
            taildrop_device_eligible = bool(self_status.get("UserID")) and not bool(
                self_status.get("Tags") or []
            )
            
            # Get advertised routes from Self
            # In tailscale status --json, check for advertised routes
            if self_status.get("AllowedIPs"):
                # AllowedIPs on Self shows what we advertise
                pass
            
            # Check capabilities for exit node
            capabilities = self_status.get("Capabilities", [])
            if capabilities:
                exit_node_advertised = any("exit" in str(c).lower() for c in capabilities)

            if any(route in ("0.0.0.0/0", "::/0") for route in allowed_ips):
                exit_node_advertised = True
            
            # Get tailnet name from CurrentTailnet or User
            user_info = ts_status.get("User", {})
            if user_info:
                # Find our user
                self_user_id = self_status.get("UserID")
                if self_user_id and str(self_user_id) in user_info:
                    tailnet = user_info[str(self_user_id)].get("LoginName", "").split("@")[-1]
            
            # Get advertised routes from prefs
            prefs = self._get_tailscale_prefs()
            if prefs:
                advertised_routes = prefs.get("AdvertiseRoutes", []) or []
                exit_node_advertised = prefs.get("AdvertiseExitNode", False)
                if any(route in ("0.0.0.0/0", "::/0") for route in advertised_routes):
                    exit_node_advertised = True
        
        # Detect current LAN CIDR
        current_cidr = self._detect_lan_cidr()
        effective_enabled = state.get("enabled", False)
        if not effective_enabled and tailscale_running:
            cidr_candidates = {current_cidr, state.get("last_lan_cidr")}
            if exit_node_advertised or any(cidr and cidr in advertised_routes for cidr in cidr_candidates):
                effective_enabled = True
                state["enabled"] = True
                state["last_error"] = None
                if current_cidr:
                    state["last_lan_cidr"] = current_cidr
                if not state.get("last_enabled_at"):
                    state["last_enabled_at"] = datetime.now().isoformat()
                self._save_state(state)
        
        importer_service_active = self._run_command(
            ["systemctl", "is-active", "--quiet", "easypi-taildrop-import.service"]
        )[0]

        return TailscaleStatus(
            enabled=effective_enabled,
            tailscale_running=tailscale_running,
            lan_cidr=current_cidr or state.get("last_lan_cidr"),
            tailscale_ips=tailscale_ips,
            advertised_routes=advertised_routes,
            exit_node_advertised=exit_node_advertised,
            hostname=hostname,
            tailnet=tailnet,
            backend_state=backend_state,
            last_error=state.get("last_error"),
            last_enabled_at=state.get("last_enabled_at"),
            taildrop_importer_active=importer_service_active and tailscale_running,
            taildrop_device_eligible=taildrop_device_eligible,
            taildrop_error=(
                str(taildrop_status["error"])
                if taildrop_status.get("error")
                else None
            ),
            taildrop_free_bytes=(
                int(taildrop_status["free_bytes"])
                if isinstance(taildrop_status.get("free_bytes"), int)
                else None
            ),
            taildrop_reserve_bytes=(
                int(taildrop_status["reserve_bytes"])
                if isinstance(taildrop_status.get("reserve_bytes"), int)
                else None
            ),
        )


# Singleton instance
_service_instance: Optional[TailscaleRemoteAccessService] = None


def get_tailscale_service() -> TailscaleRemoteAccessService:
    """Get or create the Tailscale service singleton."""
    global _service_instance
    if _service_instance is None:
        _service_instance = TailscaleRemoteAccessService()
    return _service_instance
