"""ShadowApps operations for NetProtection."""

import asyncio
import json
from typing import Any, Dict, List, Optional

from app.services.netprotection_components.policy_data import (
    ALLOWLIST_SOURCE_SHADOW_MODE,
)
from app.services.netprotection_components.runtime_context import logger
from app.utils.time import utc_now


class ShadowAppsMixin:
    """Internal behavior mixed into the stable service facade."""

    async def get_shadow_domains(
        self, status: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get domains observed in shadow mode.

        Reads from shadow_mode.db which is populated by NetProtection's
        verdict engine when shadow mode is enabled.
        """
        import sqlite3

        shadow_db = self.data_dir / "shadow_mode.db"

        if not shadow_db.exists():
            return {
                "success": True,
                "data": [],
                "total": 0,
                "message": "No shadow mode data yet",
            }

        try:
            conn = sqlite3.connect(str(shadow_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Build query based on status filter
            # Statuses in DB: observed, auto_blocked, promoted (user blocked), dismissed (user approved)
            where_clause = ""
            params = []

            if status == "observing":
                # Review queue: gray-zone domains that are NOT blocked (admin decides)
                where_clause = "WHERE action IS NULL OR action = 'observed'"
            elif status == "blocked":
                # Blocked by a human
                where_clause = "WHERE action = 'promoted' AND (action_by IS NULL OR action_by != 'auto')"
            elif status == "approved":
                # User manually approved/dismissed
                where_clause = "WHERE action = 'dismissed'"
            elif status == "auto_blocked":
                # Actually auto-blocked by Shadow Mode (auto-promoted)
                where_clause = "WHERE action = 'auto_blocked' OR (action = 'promoted' AND action_by = 'auto')"
            elif status == "pending":
                # Legacy alias for the review queue
                where_clause = "WHERE action IS NULL OR action = 'observed'"

            # Get total count
            count_query = f"SELECT COUNT(*) FROM shadow_domains {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]

            # Get domains
            query = f"""
                SELECT
                    domain,
                    first_observed,
                    last_observed,
                    hit_count,
                    max_score,
                    total_score,
                    action,
                    action_at,
                    action_by,
                    notes
                FROM shadow_domains
                {where_clause}
                ORDER BY last_observed DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, params + [limit, offset])

            domains = []
            for row in cursor.fetchall():
                # Map action to status: 'observed' or null -> 'pending', else use action
                action = row["action"]
                if action in (None, "observed"):
                    status_val = "pending"
                else:
                    status_val = action

                # Convert timestamp to ISO format
                from datetime import datetime

                first_observed_iso = None
                last_observed_iso = None

                if row["first_observed"]:
                    try:
                        first_observed_iso = datetime.utcfromtimestamp(
                            row["first_observed"]
                        ).isoformat()
                    except (ValueError, OSError):
                        first_observed_iso = utc_now().isoformat()

                if row["last_observed"]:
                    try:
                        last_observed_iso = datetime.utcfromtimestamp(
                            row["last_observed"]
                        ).isoformat()
                    except (ValueError, OSError):
                        last_observed_iso = utc_now().isoformat()

                # Get signals from shadow_history notes
                signals = {}
                domain_name = row["domain"]
                try:
                    signal_cursor = conn.cursor()
                    signal_cursor.execute(
                        "SELECT notes FROM shadow_history WHERE domain = ? AND notes LIKE '%Reasons:%' ORDER BY timestamp DESC LIMIT 1",
                        (domain_name,),
                    )
                    signal_row = signal_cursor.fetchone()
                    if signal_row and signal_row[0]:
                        notes_text = signal_row[0]
                        if "Reasons:" in notes_text:
                            reasons_part = notes_text.split("Reasons:")[1].strip()
                            for reason in reasons_part.split(";"):
                                reason = reason.strip()
                                if not reason:
                                    continue
                                # Map reason text to signal key based on actual heuristics output
                                reason_lower = reason.lower()

                                # DGA detector patterns
                                if any(
                                    p in reason_lower
                                    for p in [
                                        "consonant ratio",
                                        "digit ratio",
                                        "no vowels",
                                        "more digits than",
                                        "bigram",
                                        "hex-like",
                                        "hex pattern",
                                        "alternating consonant",
                                        "dga",
                                        "algorithmically",
                                        "long consonant",
                                        "character diversity",
                                        "repeating",
                                        "suspicious tld",
                                    ]
                                ):
                                    signals["dga"] = signals.get("dga", 0) + 15.0

                                # Entropy patterns
                                elif (
                                    "entropy" in reason_lower
                                    or "random" in reason_lower
                                ):
                                    signals["entropy"] = (
                                        signals.get("entropy", 0) + 15.0
                                    )

                                # Homoglyph/brand patterns
                                elif any(
                                    p in reason_lower
                                    for p in [
                                        "brand",
                                        "homoglyph",
                                        "digit substitution",
                                        "lookalike",
                                        "impersonation",
                                        "typosquat",
                                        "punycode",
                                        "non-ascii",
                                        "mixed character scripts",
                                        "with suffix",
                                    ]
                                ):
                                    signals["homoglyph"] = (
                                        signals.get("homoglyph", 0) + 15.0
                                    )

                                # First seen / new domain
                                elif any(
                                    p in reason_lower
                                    for p in ["never seen", "first seen", "new domain"]
                                ):
                                    signals["first_seen"] = (
                                        signals.get("first_seen", 0) + 10.0
                                    )

                                # Length patterns (long domain, long sld)
                                elif (
                                    any(
                                        p in reason_lower
                                        for p in [
                                            "long domain",
                                            "long sld",
                                            "very long",
                                            "chars",
                                        ]
                                    )
                                    and "subdomain" not in reason_lower
                                ):
                                    signals["length"] = signals.get("length", 0) + 5.0

                                # Subdomain depth
                                elif any(
                                    p in reason_lower
                                    for p in ["subdomain", "deep", "levels"]
                                ):
                                    signals["subdomain_depth"] = (
                                        signals.get("subdomain_depth", 0) + 10.0
                                    )

                                # Reputation patterns
                                elif any(
                                    p in reason_lower
                                    for p in [
                                        "reputation",
                                        "threat intel",
                                        "blocklist",
                                        "manual blocklist",
                                    ]
                                ):
                                    signals["reputation"] = (
                                        signals.get("reputation", 0) + 15.0
                                    )

                                # Beaconing patterns (spikes, flood, deviation)
                                elif any(
                                    p in reason_lower
                                    for p in [
                                        "beacon",
                                        "spike",
                                        "flood",
                                        "deviation",
                                        "queries",
                                    ]
                                ):
                                    signals["beaconing"] = (
                                        signals.get("beaconing", 0) + 10.0
                                    )

                                # ASN/IP patterns - map to reputation
                                elif any(
                                    p in reason_lower
                                    for p in [
                                        "hostile",
                                        "suspicious",
                                        "abused asn",
                                        "ip hostile",
                                        "ip suspicious",
                                    ]
                                ):
                                    signals["reputation"] = (
                                        signals.get("reputation", 0) + 10.0
                                    )

                                # Skip benign/safe reasons - don't add to signals
                                elif any(
                                    p in reason_lower
                                    for p in [
                                        "safe",
                                        "normal",
                                        "whitelist",
                                        "no suspicious",
                                        "no brand",
                                        "no reputation",
                                        "too short",
                                        "trusted",
                                    ]
                                ):
                                    pass  # Ignore benign reasons

                                else:
                                    # Generic signal for unmatched
                                    signals["other"] = signals.get("other", 0) + 5.0
                except Exception:
                    pass

                domains.append(
                    {
                        "domain": row["domain"],
                        "first_observed": first_observed_iso,
                        "last_observed": last_observed_iso,
                        "hit_count": row["hit_count"],
                        "max_score": row["max_score"],
                        "avg_score": round(row["total_score"] / row["hit_count"], 1)
                        if row["hit_count"] > 0
                        else 0,
                        "action": action,
                        "action_at": row["action_at"],
                        "action_by": row["action_by"],
                        "notes": row["notes"],
                        "status": status_val,
                        "signals": signals,
                    }
                )

            conn.close()

            return {"success": True, "data": domains, "total": total}

        except Exception as e:
            logger.error(f"Error reading shadow domains: {e}")
            return {"success": False, "error": str(e), "data": [], "total": 0}

    async def get_shadow_stats(self) -> Dict[str, Any]:
        """Get shadow mode statistics."""
        import sqlite3

        shadow_db = self.data_dir / "shadow_mode.db"

        if not shadow_db.exists():
            return {
                "success": True,
                "data": {
                    "total_observed": 0,
                    "pending": 0,
                    "promoted": 0,
                    "dismissed": 0,
                    "avg_score": 0,
                },
            }

        try:
            conn = sqlite3.connect(str(shadow_db))
            cursor = conn.cursor()

            # Get counts by action type
            cursor.execute("SELECT COUNT(*) FROM shadow_domains")
            total = cursor.fetchone()[0]

            # Observing = the review queue: gray-zone domains that are NOT blocked.
            # These are only watched; the admin decides Block vs Approve.
            cursor.execute(
                "SELECT COUNT(*) FROM shadow_domains WHERE action IS NULL OR action = 'observed'"
            )
            observing = cursor.fetchone()[0]

            # User Blocked = promoted to the blocklist by a human (action_by is not the
            # internal 'auto' promoter).
            cursor.execute(
                "SELECT COUNT(*) FROM shadow_domains "
                "WHERE action = 'promoted' AND (action_by IS NULL OR action_by != 'auto')"
            )
            blocked = cursor.fetchone()[0]

            # Auto-blocked = actually blocked automatically by Shadow Mode
            # (auto-promoted on high score/frequency). This is the only bucket that is
            # genuinely blocked without the admin, so the UI offers only 'Unblock' there.
            cursor.execute(
                "SELECT COUNT(*) FROM shadow_domains "
                "WHERE action = 'auto_blocked' OR (action = 'promoted' AND action_by = 'auto')"
            )
            auto_blocked = cursor.fetchone()[0]

            # Approved = dismissed by the user (marked safe)
            cursor.execute(
                "SELECT COUNT(*) FROM shadow_domains WHERE action = 'dismissed'"
            )
            approved = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(max_score) FROM shadow_domains")
            avg_score = cursor.fetchone()[0] or 0

            conn.close()

            return {
                "success": True,
                "data": {
                    "total_observed": total,
                    "observing": observing,  # review queue (watched, NOT blocked)
                    "blocked": blocked,  # blocked by the user
                    "approved": approved,  # approved (dismissed) by the user
                    "auto_blocked": auto_blocked,  # actually auto-blocked by Shadow Mode
                    "avg_score": round(avg_score, 1),
                },
            }

        except Exception as e:
            logger.error(f"Error getting shadow stats: {e}")
            return {"success": False, "error": str(e)}

    async def shadow_domain_action(
        self, domain: str, action: str, user: str = "admin", notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Take action on a shadow domain.

        Actions:
        - promote: Add to blocklist
        - dismiss: Approve as safe. The domain is added to the user's
          allowlist, the one place a user's allow decision is kept. The engine
          checks the allowlist before Shadow Mode, so the approval stays in
          force even if Shadow Mode would otherwise promote the domain again.
        """
        import sqlite3
        import re

        # Validate domain format
        domain = domain.lower().strip().rstrip(".")
        if not domain or len(domain) > 253:
            return {"success": False, "error": "Invalid domain format"}
        if not re.match(r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$", domain):
            return {"success": False, "error": "Invalid domain format"}

        if action not in ("promote", "dismiss"):
            return {"success": False, "error": f"Invalid action: {action}"}

        shadow_db = self.data_dir / "shadow_mode.db"

        if not shadow_db.exists():
            return {"success": False, "error": "Shadow mode database not found"}

        try:
            conn = sqlite3.connect(str(shadow_db))
            cursor = conn.cursor()
            known = cursor.execute(
                "SELECT 1 FROM shadow_domains WHERE domain = ?", (domain,)
            ).fetchone()
            if known is None:
                conn.close()
                return {"success": False, "error": f"Domain not found: {domain}"}

            if action == "dismiss":
                # Record the decision in the allowlist before the Shadow Mode
                # record: an "approved" record without an allowlist entry would
                # not stop the engine from blocking the domain.
                try:
                    await self.add_to_whitelist(
                        domain,
                        comment="Approved in Shadow Mode",
                        source=ALLOWLIST_SOURCE_SHADOW_MODE,
                    )
                except Exception:
                    conn.close()
                    raise

            # Update domain action
            action_value = "promoted" if action == "promote" else "dismissed"
            import time

            now_timestamp = time.time()  # Store as Unix timestamp like other fields

            cursor.execute(
                """
                UPDATE shadow_domains
                SET action = ?, action_at = ?, action_by = ?, notes = ?
                WHERE domain = ?
            """,
                (action_value, now_timestamp, user, notes, domain),
            )

            if cursor.rowcount == 0:
                conn.close()
                return {"success": False, "error": f"Domain not found: {domain}"}

            conn.commit()
            conn.close()

            # If promoted, add to blocklist
            if action == "promote":
                # Blocking is the user's latest decision. An earlier allowlist
                # entry would otherwise keep overriding the Shadow Mode block.
                await self.remove_from_whitelist(domain)
                await self._add_to_blocklist_from_shadow(domain)
                logger.info(f"Shadow domain promoted to blocklist: {domain}")
            else:
                logger.info(f"Shadow domain approved and allowlisted: {domain}")

            return {
                "success": True,
                "domain": domain,
                "action": action_value,
                "message": f"Domain {action_value}",
            }

        except Exception as e:
            logger.error(f"Error updating shadow domain: {e}")
            return {"success": False, "error": str(e)}

    async def _add_to_blocklist_from_shadow(self, domain: str) -> None:
        """Add a promoted shadow domain to the blocklist."""
        try:
            # Create a wildcard matcher for the domain
            await self.add_matcher(
                {
                    "name": f"Shadow: {domain}",
                    "kind": "wildcard",
                    "pattern": f"*.{domain}",
                    "action": "deny",
                    "priority": 150,
                    "enabled": True,
                    "tags": ["shadow-promoted", "auto"],
                }
            )
            # Also add exact match
            await self.add_matcher(
                {
                    "name": f"Shadow: {domain} (exact)",
                    "kind": "exact",
                    "pattern": domain,
                    "action": "deny",
                    "priority": 150,
                    "enabled": True,
                    "tags": ["shadow-promoted", "auto"],
                }
            )
        except Exception as e:
            logger.error(f"Error adding shadow domain to blocklist: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # APP BLOCKING (IP-based for DNS-bypass apps)
    # ════════════════════════════════════════════════════════════════════════

    async def get_blockable_apps(self) -> List[Dict[str, Any]]:
        """
        Get list of apps that can be blocked via IP.

        Returns list of apps like Telegram, WhatsApp, Signal that bypass DNS.
        """
        try:
            from easypi_netprotection.parental import get_parental_controller

            controller = get_parental_controller()
            return controller.get_blockable_apps()
        except ImportError:
            logger.warning("Parental controller not available for app blocking")
            return []
        except Exception as e:
            logger.error(f"Error getting blockable apps: {e}")
            return []

    async def get_app_blocking_status(self, device_id: str) -> Dict[str, Any]:
        """Get app blocking status for a device."""
        try:
            # Find device to get IP
            devices = await self.get_devices()
            device = next((d for d in devices if d.get("id") == device_id), None)

            if not device:
                return {"active": False, "apps": [], "error": "Device not found"}

            device_ip = device.get("ip")
            if not device_ip:
                return {"active": False, "apps": [], "error": "Device has no IP"}

            from easypi_netprotection.parental import get_parental_controller

            controller = get_parental_controller()
            return controller.get_app_blocking_status(device_ip)

        except ImportError:
            return {"active": False, "apps": [], "available": False}
        except Exception as e:
            logger.error(f"Error getting app blocking status: {e}")
            return {"active": False, "apps": [], "error": str(e)}

    async def set_device_blocked_apps(self, device_id: str, apps: List[str]) -> bool:
        """
        Set blocked apps for a device.

        Updates the device's blocked_apps field and syncs iptables rules.
        """
        try:
            # Load devices
            devices_file = self.data_dir / "devices.json"
            devices = []

            if devices_file.exists():
                with open(devices_file, "r") as f:
                    devices = json.load(f)

            # Find and update device
            device_found = False
            for device in devices:
                if device.get("id") == device_id:
                    device["blocked_apps"] = apps
                    device_found = True
                    break

            if not device_found:
                return False

            # Save devices
            with open(devices_file, "w") as f:
                json.dump(devices, f, indent=2)

            # Sync app blocking rules
            await self.sync_app_blocking()

            return True

        except Exception as e:
            logger.error(f"Error setting device blocked apps: {e}")
            return False

    async def sync_app_blocking(self) -> bool:
        """Sync app blocking rules with iptables."""
        try:
            from easypi_netprotection.parental import get_parental_controller

            controller = get_parental_controller()
            return controller.sync_app_blocking()
        except ImportError:
            logger.warning("Parental controller not available")
            return False
        except Exception as e:
            logger.error(f"Error syncing app blocking: {e}")
            return False

    async def update_app_ip_lists(self) -> bool:
        """Update IP lists for blockable apps from external sources."""
        try:
            import subprocess
            from app.core.paths import get_easypi_root

            runner_path = get_easypi_root() / "scripts" / "runner"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_app_blocking.sh",
                    "update-lists",
                ],
                capture_output=True,
                timeout=60,
                text=True,
            )

            if result.returncode == 0:
                logger.info("App IP lists updated successfully")
                return True
            else:
                logger.error(f"Failed to update app IP lists: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Timeout updating app IP lists")
            return False
        except Exception as e:
            logger.error(f"Error updating app IP lists: {e}")
            return False

    async def get_whatsapp_block_mode(self) -> Dict[str, Any]:
        """
        Get global WhatsApp app-blocking mode.

        Modes:
        - balanced: SNI-first (lower collateral impact)
        - aggressive: full IP mode with Meta shared ranges
        """
        import subprocess

        try:
            from app.core.paths import get_easypi_root

            runner_path = get_easypi_root() / "scripts" / "runner"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_app_blocking.sh",
                    "get-whatsapp-mode",
                ],
                capture_output=True,
                timeout=20,
                text=True,
            )
            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                logger.error(f"Failed to get WhatsApp block mode: {stderr}")
                return {
                    "success": False,
                    "mode": "balanced",
                    "error": stderr or "runner failed",
                }

            mode = str(result.stdout or "").strip().lower()
            if mode not in {"balanced", "aggressive"}:
                mode = "balanced"
            return {"success": True, "mode": mode}

        except subprocess.TimeoutExpired:
            logger.error("Timeout getting WhatsApp block mode")
            return {"success": False, "mode": "balanced", "error": "timeout"}
        except Exception as e:
            logger.error(f"Error getting WhatsApp block mode: {e}")
            return {"success": False, "mode": "balanced", "error": str(e)}

    async def set_whatsapp_block_mode(self, mode: str) -> Dict[str, Any]:
        """
        Set global WhatsApp app-blocking mode and apply it immediately.

        Accepted values: balanced, aggressive
        """
        mode_s = str(mode or "").strip().lower()
        if mode_s not in {"balanced", "aggressive"}:
            return {"success": False, "error": "Invalid mode"}

        import subprocess

        try:
            from app.core.paths import get_easypi_root

            runner_path = get_easypi_root() / "scripts" / "runner"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_app_blocking.sh",
                    "set-whatsapp-mode",
                    mode_s,
                ],
                capture_output=True,
                timeout=120,
                text=True,
            )
            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                logger.error(f"Failed to set WhatsApp block mode ({mode_s}): {stderr}")
                return {
                    "success": False,
                    "mode": mode_s,
                    "error": stderr or "runner failed",
                }

            logger.info(f"WhatsApp block mode updated: {mode_s}")
            return {"success": True, "mode": mode_s}

        except subprocess.TimeoutExpired:
            logger.error("Timeout setting WhatsApp block mode")
            return {"success": False, "mode": mode_s, "error": "timeout"}
        except Exception as e:
            logger.error(f"Error setting WhatsApp block mode: {e}")
            return {"success": False, "mode": mode_s, "error": str(e)}
