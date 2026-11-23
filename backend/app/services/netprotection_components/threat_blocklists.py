"""ThreatBlocklists operations for NetProtection."""

from typing import Any, Dict, List, Optional


class ThreatBlocklistsMixin:
    """Internal behavior mixed into the stable service facade."""

    async def get_threat_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        stats = {
            "total_threats": 0,
            "confirmed": 0,
            "quarantine": 0,
            "by_category": {},
            "by_type": {
                "malware": 0,
                "phishing": 0,
                "ads": 0,
                "trackers": 0,
            },
        }

        if self._threat_db:
            try:
                db_stats = await self._threat_db.get_statistics()
                stats.update(db_stats)
            except Exception:
                pass

        # Get blocked counts from FlowLogger if available
        if self._flow_logger:
            try:
                flow_stats = await self._flow_logger.get_stats()
                blocked = flow_stats.get("blocked_total", 0)
                # If we have blocked queries, use that as ads count (most common)
                if blocked > 0:
                    stats["by_type"]["ads"] = blocked
                    stats["total_threats"] = blocked
            except Exception:
                pass

        return stats

    async def get_blocklist_info(self) -> Dict[str, Any]:
        """Get blocklist file info."""
        if self._domain_exporter:
            return self._domain_exporter.get_blocklist_info()
        return {"exists": False}

    async def generate_blocklist(self, confirmed_by: str = "admin") -> Dict[str, Any]:
        """Generate blocklist from threat intelligence."""
        if self._domain_exporter:
            count, path = await self._domain_exporter.generate_blocklist(
                confirmed_by=confirmed_by
            )
            return {
                "success": True,
                "domain_count": count,
                "path": str(path),
            }
        return {"success": False, "error": "Domain exporter not available"}

    async def cleanup_expired_threats(self) -> Dict[str, Any]:
        """Cleanup expired threat entries."""
        if self._domain_exporter:
            removed, remaining = await self._domain_exporter.cleanup_expired()
            return {
                "removed": removed,
                "remaining": remaining,
            }
        return {"removed": 0, "remaining": 0}

    # ============ Two-Layer Blocklist Manager ============

    def _get_blocklist_manager(self):
        """Get or create blocklist manager instance."""
        if not hasattr(self, "_blocklist_manager"):
            from easypi_netprotection.blocklist_manager import BlocklistManager

            self._blocklist_manager = BlocklistManager(self.data_dir)
        return self._blocklist_manager

    async def get_blocklist_status(self) -> Dict[str, Any]:
        """Get status of all blocklist layers."""
        mgr = self._get_blocklist_manager()
        return mgr.get_status()

    async def get_verified_sources(self) -> List[Dict[str, Any]]:
        """Get hardcoded verified CC0/MIT sources."""
        mgr = self._get_blocklist_manager()
        return mgr.get_verified_sources()

    async def set_verified_source_enabled(
        self, source_id: str, enabled: bool, user_confirmed_risks: bool = False
    ) -> bool:
        """Enable/disable a verified source (enabling a non-permissive one needs consent)."""
        mgr = self._get_blocklist_manager()
        return mgr.set_verified_source_enabled(source_id, enabled, user_confirmed_risks)

    async def get_custom_sources(self) -> List[Dict[str, Any]]:
        """Get user-added custom sources."""
        mgr = self._get_blocklist_manager()
        return mgr.get_custom_sources()

    async def get_filters(self) -> Dict[str, Any]:
        """Legacy compatibility wrapper for setup flows that expect filter objects."""
        sources = await self.get_custom_sources()
        return {
            "filters": [
                {
                    "id": source.get("id"),
                    "name": source.get("name"),
                    "url": source.get("url"),
                    "enabled": source.get("enabled", True),
                    "format": source.get("format"),
                }
                for source in sources
            ]
        }

    async def add_custom_source(
        self, url: str, name: str, format: str, user_confirmed: bool
    ) -> Dict[str, Any]:
        """Add custom blocklist source."""
        mgr = self._get_blocklist_manager()
        return mgr.add_custom_source(
            name=name, url=url, format=format, user_confirmed_risks=user_confirmed
        )

    async def add_filter(
        self, url: str, name: str, whitelist: bool = False
    ) -> Dict[str, Any]:
        """Legacy compatibility wrapper for setup flows that add default sources."""
        if whitelist:
            raise ValueError(
                "Whitelist filters are not supported by the NetProtection compatibility layer"
            )
        return await self.add_custom_source(
            url=url,
            name=name,
            format="hosts",
            user_confirmed=True,
        )

    async def add_custom_source_from_file(
        self, name: str, content: str, format: str, user_confirmed: bool
    ) -> Dict[str, Any]:
        """Add custom blocklist from uploaded file content."""
        mgr = self._get_blocklist_manager()
        return mgr.add_custom_source_from_file(
            name=name,
            content=content,
            format=format,
            user_confirmed_risks=user_confirmed,
        )

    async def remove_custom_source(self, source_id: str) -> bool:
        """Remove custom blocklist source."""
        mgr = self._get_blocklist_manager()
        return mgr.remove_custom_source(source_id)

    async def set_custom_source_enabled(self, source_id: str, enabled: bool) -> bool:
        """Enable/disable a custom source."""
        mgr = self._get_blocklist_manager()
        return mgr.set_custom_source_enabled(source_id, enabled)

    def get_use_custom_blocklist(self) -> Dict[str, Any]:
        """Check if using custom blocklist."""
        from easypi_netprotection.verdict.blocklist_filter import get_blocklist_filter

        try:
            bf = get_blocklist_filter()
            custom_exists = bf.custom_file.exists()
            return {
                "use_custom": bf.use_custom,
                "custom_available": custom_exists,
                "current_file": "custom" if bf.use_custom else "verified",
            }
        except Exception as e:
            return {"use_custom": False, "custom_available": False, "error": str(e)}

    def set_use_custom_blocklist(self, enabled: bool) -> Dict[str, Any]:
        """Switch between verified and custom blocklist."""
        from easypi_netprotection.verdict.blocklist_filter import get_blocklist_filter

        try:
            bf = get_blocklist_filter()
            success = bf.set_use_custom(enabled)
            return {
                "success": success,
                "use_custom": bf.use_custom,
                "current_file": "custom" if bf.use_custom else "verified",
                "domains_loaded": bf.get_stats().get("domains_loaded", 0),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_blocklists(self, force_clean: bool = True) -> Dict[str, Any]:
        """
        Generate all blocklist layers:
        1. verified_blocklist.txt (CC0/MIT sources)
        2. custom_blocklist.txt (user sources)
        3. effective_blocklist.txt (combined, deduplicated)

        Args:
            force_clean: If True, delete existing blocklists before regenerating
        """
        mgr = self._get_blocklist_manager()
        return await mgr.generate_all(force_clean=force_clean)

    async def refresh_filters(self) -> Dict[str, Any]:
        """Legacy compatibility wrapper for setup flows that expect a filter refresh hook."""
        return await self.generate_blocklists(force_clean=True)

    def clear_blocklists(self) -> Dict[str, Any]:
        """Clear all blocklist files."""
        mgr = self._get_blocklist_manager()
        return mgr.clear_blocklists()

    async def get_blocklist_progress(self) -> Optional[Dict[str, Any]]:
        """Get current generation progress."""
        mgr = self._get_blocklist_manager()
        return mgr.get_progress()

    def get_effective_domains(self) -> set[str]:
        """Get domains from effective blocklist for DNS filtering."""
        mgr = self._get_blocklist_manager()
        return mgr.get_effective_domains()
