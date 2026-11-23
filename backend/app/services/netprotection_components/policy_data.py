"""PolicyData operations for NetProtection."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.services.netprotection_components.runtime_context import (
    MULTI_PART_TLDS,
    lists_lock,
    logger,
    write_text_atomic,
)

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))+$"
)

# Second-level names under which country zones register sites (co.uk,
# com.au, ac.jp). Covers the zones the engine's MULTI_PART_TLDS list misses.
_SHARED_SECOND_LEVEL = frozenset(
    {
        "ac", "co", "com", "ed", "edu", "go", "gob", "gov", "govt", "ltd",
        "mil", "ne", "net", "nic", "or", "org", "plc", "sch",
    }
)


def normalize_list_domain(value: str) -> str:
    """The one host name the user meant, as the engine will store it.

    Accepts what people paste (a URL, host:port, "*.example.com") and returns
    the bare host in ASCII. Raises ValueError for anything else, so a list
    line can never carry extra lines, spaces or other text.
    """
    host = (value or "").strip().lower()
    if "://" in host:
        host = urlparse(host).hostname or ""
    else:
        host = host.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    host = host.strip().rstrip(".")
    if host.startswith("*."):  # the engine already covers subdomains
        host = host[2:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = ""
    if not _HOSTNAME.fullmatch(host):
        raise ValueError("Enter a single host name such as example.com")
    return host


def is_shared_zone(host: str) -> bool:
    """A zone that many unrelated owners register under, e.g. co.uk."""
    labels = host.split(".")
    return host in MULTI_PART_TLDS or (
        len(labels) == 2 and len(labels[1]) == 2 and labels[0] in _SHARED_SECOND_LEVEL
    )

# Where a user's allow decision was made. The allowlist is the single store
# for those decisions; the source only tells the user which screen they used.
ALLOWLIST_SOURCE_LISTS = "lists"
ALLOWLIST_SOURCE_SHADOW_MODE = "shadow-mode"
ALLOWLIST_SOURCE_BLOCKED_TAB = "blocked-tab"
ALLOWLIST_SOURCE_ASSISTANT = "assistant"
ALLOWLIST_SOURCES = frozenset(
    {
        ALLOWLIST_SOURCE_LISTS,
        ALLOWLIST_SOURCE_SHADOW_MODE,
        ALLOWLIST_SOURCE_BLOCKED_TAB,
        ALLOWLIST_SOURCE_ASSISTANT,
    }
)


class PolicyDataMixin:
    """Internal behavior mixed into the stable service facade."""

    async def get_matchers(self) -> List[Dict[str, Any]]:
        """Get all matchers (blocklist rules)."""
        matchers_path = self.data_dir / "matchers.json"

        if matchers_path.exists():
            return json.loads(matchers_path.read_text())

        # Default matchers
        return [
            {
                "id": "builtin_ads",
                "name": "Advertising & Trackers",
                "kind": "blocklist",
                "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                "enabled": True,
                "rules_count": 180000,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "tags": ["ads", "tracking"],
            },
            {
                "id": "builtin_malware",
                "name": "Malware Domains",
                "kind": "blocklist",
                "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
                "enabled": True,
                "rules_count": 45000,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "tags": ["malware", "security"],
            },
            {
                "id": "builtin_phishing",
                "name": "Phishing Domains",
                "kind": "blocklist",
                "url": "https://phishing.army/download/phishing_army_blocklist.txt",
                "enabled": True,
                "rules_count": 12000,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "tags": ["phishing", "security"],
            },
            {
                "id": "threat_intel",
                "name": "EasyPi Threat Intelligence",
                "kind": "blocklist",
                "source": "local",
                "enabled": True,
                "rules_count": 0,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "tags": ["easypi", "threat-intel"],
            },
        ]

    async def add_matcher(self, matcher: Dict[str, Any]) -> Dict[str, Any]:
        """Add new matcher."""

        matchers = await self.get_matchers()
        matcher["id"] = str(uuid.uuid4())[:8]
        matcher["created_at"] = datetime.now(timezone.utc).isoformat()
        matchers.append(matcher)

        matchers_path = self.data_dir / "matchers.json"
        matchers_path.write_text(json.dumps(matchers, indent=2))

        return matcher

    async def update_matcher(
        self, matcher_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update matcher by ID."""
        matchers = await self.get_matchers()

        for i, m in enumerate(matchers):
            if m["id"] == matcher_id:
                matchers[i].update(updates)
                matchers[i]["updated_at"] = datetime.now(timezone.utc).isoformat()

                matchers_path = self.data_dir / "matchers.json"
                matchers_path.write_text(json.dumps(matchers, indent=2))

                return matchers[i]

        return None

    async def delete_matcher(self, matcher_id: str) -> bool:
        """Delete matcher by ID."""
        matchers = await self.get_matchers()
        original_len = len(matchers)

        matchers = [m for m in matchers if m["id"] != matcher_id]

        if len(matchers) < original_len:
            matchers_path = self.data_dir / "matchers.json"
            matchers_path.write_text(json.dumps(matchers, indent=2))
            return True

        return False

    # ============ Whitelist / Blacklist ============
    #
    # allowlist.txt and user_blocklist.txt hold one host per line; the engine
    # also applies an entry to its subdomains. Their *_meta.json files are
    # shared with the engine's hit counters, so every read-change-write runs
    # under the shared list lock and replaces the file in one step.

    def _trigger_lists_reload(self) -> None:
        """Create signal file to trigger immediate reload of allowlist/blocklist in NetProtection."""
        try:
            signal_file = self.data_dir / ".lists_reload"
            signal_file.touch()
            logger.debug("Triggered NetProtection lists reload")
        except Exception as e:
            logger.warning(f"Failed to trigger lists reload: {e}")

    def _load_list_metadata(self, meta_file: Path) -> Dict[str, Dict[str, Any]]:
        """Load metadata (hits, addedAt) from JSON file."""
        if meta_file.exists():
            try:
                return json.loads(meta_file.read_text())
            except Exception as e:
                logger.warning(f"Failed to load list metadata: {e}")
        return {}

    def _save_list_metadata(
        self, meta_file: Path, metadata: Dict[str, Dict[str, Any]]
    ) -> None:
        """Save metadata to JSON file."""
        try:
            write_text_atomic(meta_file, json.dumps(metadata, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save list metadata: {e}")

    @staticmethod
    def _read_list_domains(list_path: Path) -> List[str]:
        """Entries of a list file, without blank lines and comments."""
        if not list_path.exists():
            return []
        return [
            line.strip()
            for line in list_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def _sync_metadata_with_domains(
        self, domains: List[str], metadata: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Sync metadata with domain list - remove stale entries, keep existing ones."""
        synced = {}
        for domain in domains:
            if domain in metadata:
                synced[domain] = metadata[domain]
            else:
                # New domain without metadata - create default
                synced[domain] = {
                    "addedAt": datetime.now().isoformat(),
                    "hits": 0,
                    "type": "exact",
                    "comment": "",
                }
        return synced

    def _list_with_metadata(self, list_name: str, meta_name: str) -> List[Dict[str, Any]]:
        """Entries of one list with their metadata, dropping stale metadata."""
        with lists_lock(self.data_dir):
            domains = self._read_list_domains(self.data_dir / list_name)
            meta_path = self.data_dir / meta_name
            metadata = self._load_list_metadata(meta_path)
            metadata = self._sync_metadata_with_domains(domains, metadata)
            self._save_list_metadata(meta_path, metadata)
        return [
            {
                "domain": domain,
                "addedAt": metadata.get(domain, {}).get("addedAt", ""),
                "hits": metadata.get(domain, {}).get("hits", 0),
                "type": metadata.get(domain, {}).get("type", "exact"),
                "comment": metadata.get(domain, {}).get("comment", ""),
                "source": metadata.get(domain, {}).get("source"),
            }
            for domain in domains
        ]

    def _add_list_entry(
        self,
        list_name: str,
        meta_name: str,
        domain: str,
        domain_type: str,
        comment: Optional[str],
        extra: Dict[str, Any],
    ) -> None:
        """Add one host to a list, or update its metadata if already present."""
        list_path = self.data_dir / list_name
        meta_path = self.data_dir / meta_name
        with lists_lock(self.data_dir):
            domains = self._read_list_domains(list_path)
            metadata = self._load_list_metadata(meta_path)
            if domain not in domains:
                domains.append(domain)
                write_text_atomic(list_path, "\n".join(domains))
                metadata[domain] = {
                    "addedAt": datetime.now().isoformat(),
                    "hits": 0,
                    "type": domain_type or "exact",
                    "comment": comment or "",
                    **extra,
                }
                self._save_list_metadata(meta_path, metadata)
                self._trigger_lists_reload()
            else:
                # Already present: update metadata in place, preserving hits/addedAt
                # (this is what the UI "edit" flow relies on).
                entry = metadata.get(domain, {})
                entry["type"] = domain_type or entry.get("type", "exact")
                if comment is not None:
                    entry["comment"] = comment
                entry.setdefault("hits", 0)
                entry.setdefault("addedAt", datetime.now().isoformat())
                metadata[domain] = entry
                self._save_list_metadata(meta_path, metadata)

    def _remove_list_entry(self, list_name: str, meta_name: str, domain: str) -> str:
        """Remove one entry exactly as stored, so malformed old lines can go too."""
        domain = domain.lower().strip()
        list_path = self.data_dir / list_name
        meta_path = self.data_dir / meta_name
        with lists_lock(self.data_dir):
            domains = self._read_list_domains(list_path)
            if domain in domains:
                domains.remove(domain)
                write_text_atomic(list_path, "\n".join(domains))
                metadata = self._load_list_metadata(meta_path)
                metadata.pop(domain, None)
                self._save_list_metadata(meta_path, metadata)
                self._trigger_lists_reload()
        return domain

    async def get_whitelist(self) -> List[Dict[str, Any]]:
        """Get user whitelist with metadata. Uses allowlist.txt for NetProtection integration."""
        entries = self._list_with_metadata("allowlist.txt", "allowlist_meta.json")
        for entry in entries:
            # Entries made before sources were recorded came from Lists.
            entry["source"] = entry["source"] or ALLOWLIST_SOURCE_LISTS
        return entries

    async def add_to_whitelist(
        self,
        domain: str,
        domain_type: str = "exact",
        comment: str = None,
        source: str = ALLOWLIST_SOURCE_LISTS,
    ) -> Dict[str, Any]:
        """Add domain to whitelist (allowlist.txt for NetProtection).

        Raises ValueError for anything but one host name, and for a shared
        zone such as co.uk: an allow covers subdomains, so allowing a zone
        would let every site registered under it through.
        """
        if source not in ALLOWLIST_SOURCES:
            raise ValueError(f"Unknown allowlist source: {source}")
        domain = normalize_list_domain(domain)
        if is_shared_zone(domain):
            raise ValueError(
                f"{domain} is a shared domain zone; allow a specific site instead"
            )
        self._add_list_entry(
            "allowlist.txt",
            "allowlist_meta.json",
            domain,
            domain_type,
            comment,
            {"source": source},
        )
        return {"success": True, "domain": domain}

    async def remove_from_whitelist(self, domain: str) -> Dict[str, Any]:
        """Remove domain from whitelist (allowlist.txt for NetProtection)."""
        domain = self._remove_list_entry("allowlist.txt", "allowlist_meta.json", domain)
        return {"success": True, "domain": domain}

    async def get_blacklist(self) -> List[Dict[str, Any]]:
        """Get user blacklist with metadata. Uses user_blocklist.txt for NetProtection integration."""
        entries = self._list_with_metadata("user_blocklist.txt", "user_blocklist_meta.json")
        for entry in entries:
            entry.pop("source", None)
        return entries

    async def add_to_blacklist(
        self, domain: str, domain_type: str = "exact", comment: str = None
    ) -> Dict[str, Any]:
        """Add domain to blacklist (user_blocklist.txt for NetProtection).

        Raises ValueError for anything but one host name.
        """
        domain = normalize_list_domain(domain)
        self._add_list_entry(
            "user_blocklist.txt",
            "user_blocklist_meta.json",
            domain,
            domain_type,
            comment,
            {},
        )
        return {"success": True, "domain": domain}

    async def remove_from_blacklist(self, domain: str) -> Dict[str, Any]:
        """Remove domain from blacklist (user_blocklist.txt for NetProtection)."""
        domain = self._remove_list_entry(
            "user_blocklist.txt", "user_blocklist_meta.json", domain
        )
        return {"success": True, "domain": domain}

    async def increment_whitelist_hits(self, domain: str) -> None:
        """Increment hits counter for whitelist domain."""
        self._increment_list_hits("allowlist_meta.json", domain)

    async def increment_blacklist_hits(self, domain: str) -> None:
        """Increment hits counter for blacklist domain."""
        self._increment_list_hits("user_blocklist_meta.json", domain)

    def _increment_list_hits(self, meta_name: str, domain: str) -> None:
        meta_path = self.data_dir / meta_name
        with lists_lock(self.data_dir):
            metadata = self._load_list_metadata(meta_path)
            if domain in metadata:
                metadata[domain]["hits"] = metadata[domain].get("hits", 0) + 1
                self._save_list_metadata(meta_path, metadata)

    # ============ DNS Rewrites ============

    async def get_rewrites(self) -> List[Dict[str, Any]]:
        """Get DNS rewrite rules from rewrites.json."""
        rewrites_path = self.data_dir / "rewrites.json"

        if not rewrites_path.exists():
            return []

        try:
            data = json.loads(rewrites_path.read_text())
            rules = data.get("rules", [])
            return [
                {
                    "id": r.get("id", ""),
                    "domain": r.get("domain", ""),
                    "answer": r.get("answer", ""),
                    "type": r.get("rewrite_type", "A"),
                    "enabled": r.get("enabled", True),
                    "comment": r.get("comment", ""),
                }
                for r in rules
            ]
        except Exception as e:
            logger.error(f"Error reading rewrites: {e}")
            return []

    async def add_rewrite(
        self, domain: str, answer: str, rewrite_type: str = "A", comment: str = ""
    ) -> Dict[str, Any]:
        """Add a DNS rewrite rule with input validation."""
        import re

        # === INPUT VALIDATION ===
        # Validate domain (allow wildcards like *.example.com)
        domain = domain.lower().strip()
        if not domain:
            raise ValueError("Domain cannot be empty")
        if len(domain) > 253:
            raise ValueError("Domain too long (max 253 chars)")
        # Valid domain pattern: alphanumeric, hyphens, dots, optional wildcard prefix
        domain_pattern = r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")

        # Validate answer (IP address or domain)
        answer = answer.strip()
        if not answer:
            raise ValueError("Answer cannot be empty")
        if len(answer) > 253:
            raise ValueError("Answer too long")
        # Allow: IPv4, IPv6, domain, or special values (0.0.0.0, ::)
        ipv4_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ipv6_pattern = r"^([0-9a-fA-F:]+)$"
        if not (
            re.match(ipv4_pattern, answer)
            or re.match(ipv6_pattern, answer)
            or re.match(domain_pattern, answer)
        ):
            raise ValueError("Answer must be valid IP or domain")

        # Validate rewrite_type
        allowed_types = ["A", "AAAA", "CNAME", "MX", "TXT"]
        if rewrite_type not in allowed_types:
            rewrite_type = "A"

        # Sanitize comment (prevent injection)
        comment = comment[:200].replace("\n", " ").replace("\r", "") if comment else ""

        # === MAX RULES LIMIT ===
        MAX_RULES = 1000

        rewrites_path = self.data_dir / "rewrites.json"

        # Load existing
        data = {"rules": [], "version": 1}
        if rewrites_path.exists():
            try:
                data = json.loads(rewrites_path.read_text())
            except Exception:
                pass

        rules = data.get("rules", [])

        # Check limit
        if len(rules) >= MAX_RULES:
            raise ValueError(f"Maximum {MAX_RULES} rules allowed")

        # Check for duplicates
        for r in rules:
            if r.get("domain") == domain and r.get("answer") == answer:
                raise ValueError("Duplicate rule exists")

        # Create new rule
        new_rule = {
            "id": str(uuid.uuid4()),
            "domain": domain,
            "answer": answer,
            "rewrite_type": rewrite_type,
            "enabled": True,
            "comment": comment,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        rules.append(new_rule)
        data["rules"] = rules

        # Save atomically
        tmp_path = rewrites_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2))
        tmp_path.replace(rewrites_path)

        return {"success": True, "rule": new_rule}

    async def delete_rewrite(self, domain: str, answer: str) -> Dict[str, Any]:
        """Delete a DNS rewrite rule by domain and answer."""
        rewrites_path = self.data_dir / "rewrites.json"

        if not rewrites_path.exists():
            return {"success": False, "error": "No rewrites file"}

        try:
            data = json.loads(rewrites_path.read_text())
            rules = data.get("rules", [])

            # Find and remove
            original_count = len(rules)
            rules = [
                r
                for r in rules
                if not (r.get("domain") == domain and r.get("answer") == answer)
            ]

            if len(rules) == original_count:
                return {"success": False, "error": "Rewrite not found"}

            data["rules"] = rules
            rewrites_path.write_text(json.dumps(data, indent=2))

            return {"success": True}
        except Exception as e:
            logger.error(f"Error deleting rewrite: {e}")
            return {"success": False, "error": str(e)}

    # ============ Shield Profiles ============

    async def get_shield_profiles(self) -> List[Dict[str, Any]]:
        """Get available shield profiles."""
        return [
            {
                "id": "strict",
                "name": "Strict",
                "description": "Maximum protection. Blocks ads, trackers, telemetry, and potentially dangerous domains.",
                "icon": "shield-check",
                "blocks": [
                    "ads",
                    "trackers",
                    "telemetry",
                    "malware",
                    "phishing",
                    "adult",
                ],
            },
            {
                "id": "balanced",
                "name": "Balanced",
                "description": "Standard protection. Blocks ads and known trackers. Allows OS telemetry.",
                "icon": "shield",
                "blocks": ["ads", "trackers", "malware", "phishing"],
            },
            {
                "id": "kids",
                "name": "Kids",
                "description": "Child-safe mode. Forced SafeSearch, adult content blocking, limited social media.",
                "icon": "baby",
                "blocks": [
                    "ads",
                    "trackers",
                    "malware",
                    "phishing",
                    "adult",
                    "gambling",
                    "social",
                ],
                "safe_search": True,
            },
            {
                "id": "minimal",
                "name": "Minimal",
                "description": "Only malware and phishing. Ads and trackers allowed.",
                "icon": "shield-off",
                "blocks": ["malware", "phishing"],
            },
            {
                "id": "custom",
                "name": "Custom",
                "description": "User-defined configuration.",
                "icon": "settings",
                "blocks": [],
            },
        ]

    async def get_current_shield_profile(self) -> str:
        """Get current shield profile."""
        config = await self.get_config()
        return config.get("shield_profile", "balanced")

    async def set_shield_profile(self, profile_id: str) -> Dict[str, Any]:
        """Set shield profile."""
        profiles = await self.get_shield_profiles()
        if not any(p["id"] == profile_id for p in profiles):
            raise ValueError(f"Unknown profile: {profile_id}")

        config = await self.get_config()
        config["shield_profile"] = profile_id
        await self.update_config(config)

        return {"success": True, "profile": profile_id}

    # ============ Devices ============

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get discovered devices."""
        devices_path = self.data_dir / "devices.json"

        if devices_path.exists():
            return json.loads(devices_path.read_text())

        return []

    async def create_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device entry."""
        import ipaddress

        devices = await self.get_devices()

        # Validate and sanitize IP
        ip = device_data.get("ip")
        if ip:
            try:
                # Validate IP format
                ip_obj = ipaddress.ip_address(ip)
                ip = str(ip_obj)  # Normalize
                # Block localhost and link-local for security
                if ip_obj.is_loopback or ip_obj.is_link_local:
                    raise ValueError("Loopback and link-local IPs not allowed")
            except ValueError as e:
                logger.warning(f"Invalid IP address: {ip} - {e}")
                raise ValueError(f"Invalid IP address: {ip}")

        # Validate MAC format if provided
        mac = device_data.get("mac")
        if mac:
            mac = mac.upper().replace("-", ":")
            import re

            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                logger.warning(f"Invalid MAC address: {mac}")
                mac = None  # Ignore invalid MAC instead of failing

        # Generate unique ID if not provided
        device_id = device_data.get("id") or str(uuid.uuid4())[:8]

        # Check for duplicate IP or MAC
        for d in devices:
            if ip and d.get("ip") == ip:
                # Update existing device instead
                return await self.update_device(d["id"], device_data) or d
            if mac and d.get("mac") == mac:
                return await self.update_device(d["id"], device_data) or d

        # Sanitize name (prevent XSS)
        name = device_data.get("name", f"Device-{device_id}")
        name = name[:64].replace("<", "&lt;").replace(">", "&gt;")

        # Create new device
        new_device = {
            "id": device_id,
            "name": name,
            "ip": ip,
            "mac": mac,
            "parental": device_data.get("parental", False),
            "safesearch": device_data.get("safesearch", False),
            "enabled": device_data.get("enabled", True),
            "blocked_services": device_data.get("blocked_services", []),
            "profile_id": device_data.get("profile_id"),
            "created_at": datetime.now().isoformat(),
        }

        devices.append(new_device)

        devices_path = self.data_dir / "devices.json"
        devices_path.write_text(json.dumps(devices, indent=2))

        # Sync blocklist with NetProtection
        await self._sync_blocklist()

        return new_device

    async def delete_device(self, device_id: str) -> bool:
        """Delete a device and its associated profile/bindings."""
        devices = await self.get_devices()

        # Find and remove the device
        original_len = len(devices)
        devices = [d for d in devices if d.get("id") != device_id]

        if len(devices) == original_len:
            return False  # Device not found

        # Save updated devices
        devices_path = self.data_dir / "devices.json"
        devices_path.write_text(json.dumps(devices, indent=2))

        # Remove associated profile and binding
        profiles_path = self.data_dir / "profiles.json"
        bindings_path = self.data_dir / "bindings.json"
        profile_id = f"parental_device_{device_id}"

        # Clean up profile
        if profiles_path.exists():
            profiles_data = json.loads(profiles_path.read_text())
            profiles_data["profiles"] = [
                p
                for p in profiles_data.get("profiles", [])
                if p.get("id") != profile_id
            ]
            profiles_data["updated_at"] = datetime.now().isoformat()
            profiles_path.write_text(json.dumps(profiles_data, indent=2))

        # Clean up binding
        if bindings_path.exists():
            bindings_data = json.loads(bindings_path.read_text())
            bindings_data["bindings"] = [
                b
                for b in bindings_data.get("bindings", [])
                if b.get("profile_id") != profile_id
            ]
            bindings_data["updated_at"] = datetime.now().isoformat()
            bindings_path.write_text(json.dumps(bindings_data, indent=2))

        logger.info(f"Deleted device {device_id} and its profile/bindings")
        return True

    async def update_device(
        self, device_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update device settings."""
        devices = await self.get_devices()

        for i, d in enumerate(devices):
            if d["id"] == device_id:
                devices[i].update(updates)

                devices_path = self.data_dir / "devices.json"
                devices_path.write_text(json.dumps(devices, indent=2))

                # Sync blocklist with NetProtection
                await self._sync_blocklist()

                # Auto-sync app blocking if blocked_apps changed
                if "blocked_apps" in updates:
                    await self.sync_app_blocking()

                return devices[i]

        return None
