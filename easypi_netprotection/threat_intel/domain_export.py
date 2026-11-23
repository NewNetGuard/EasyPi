"""
Domain Export — Export confirmed threats to blocklist files.

This module handles exporting confirmed/verified threat domains
to blocklist files that can be used by DNS resolvers.

Key principles:
- Only export CONFIRMED threats (never heuristics alone)
- Multiple formats: hosts, domains, dnsmasq, unbound
- METADATA in each line: source/weight/confirmed_by/date (for easy cleanup/rollback)
- ATOMIC writes: tmp → rename (prevents corrupted files)
- TTL/decay: auto-cleanup of old entries
- APPEND mode: программа дополняет файл, не перезаписывая
- GENERATE mode: UI кнопка создаёт файл с нуля

Workflow:
1. UI: Пользователь нажимает "Сгенерировать файл" → generate_blocklist()
2. Program: При подтверждении домена → append_domain() добавляет в файл
3. Background: cleanup_expired() удаляет устаревшие записи по TTL
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .threat_db import ThreatDatabase


class ExportFormat(str, Enum):
    """Supported export formats."""
    HOSTS = "hosts"  # /etc/hosts format (0.0.0.0 domain)
    DOMAINS = "domains"  # One domain per line
    DNSMASQ = "dnsmasq"  # dnsmasq format (address=/domain/)
    UNBOUND = "unbound"  # Unbound format (local-zone: "domain" refuse)
    ADBLOCK = "adblock"  # AdBlock format (||domain^)


class ExportCriteria(str, Enum):
    """Criteria for which domains to export."""
    CONFIRMED_ONLY = "confirmed"  # Only admin-confirmed
    MULTI_SIGNAL = "multi_signal"  # Multiple independent signals
    HIGH_CONFIDENCE = "high_confidence"  # Confidence >= threshold
    FEED_VERIFIED = "feed_verified"  # Verified via trusted feeds


@dataclass
class DomainMetadata:
    """Metadata for exported domain entry."""
    domain: str
    source: str  # admin_confirmed, feed_cc0, multi_signal, etc.
    weight: int  # Source weight (10-90)
    confirmed_by: str  # Username or "system"
    added_date: datetime | None  # None = use current time
    ttl_days: int  # Days until auto-expiry
    category: str  # malware, phishing, etc.
    confidence: float
    
    def __post_init__(self):
        """Set default date if None."""
        if self.added_date is None:
            self.added_date = datetime.now(timezone.utc)
    
    def is_expired(self) -> bool:
        """Check if entry has expired based on TTL."""
        if self.ttl_days <= 0 or self.added_date is None:
            return False  # No expiry
        expiry = self.added_date + timedelta(days=self.ttl_days)
        return datetime.now(timezone.utc) > expiry
    
    def days_until_expiry(self) -> int | None:
        """Return days until expiry, or None if no expiry."""
        if self.ttl_days <= 0 or self.added_date is None:
            return None
        expiry = self.added_date + timedelta(days=self.ttl_days)
        delta = expiry - datetime.now(timezone.utc)
        return max(0, delta.days)
    
    def to_comment(self) -> str:
        """Format metadata as comment string."""
        date_str = self.added_date.strftime("%Y-%m-%d") if self.added_date else "unknown"
        ttl_str = f"{self.ttl_days}d" if self.ttl_days > 0 else "permanent"
        return f"{self.source}|w{self.weight}|{self.confirmed_by}|{date_str}|ttl:{ttl_str}|{self.category}"
    
    @classmethod
    def from_comment(cls, domain: str, comment: str) -> "DomainMetadata | None":
        """Parse metadata from comment string."""
        try:
            parts = comment.split("|")
            if len(parts) < 6:
                return None
            
            source = parts[0]
            weight = int(parts[1].replace("w", ""))
            confirmed_by = parts[2]
            added_date = datetime.strptime(parts[3], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            ttl_str = parts[4].replace("ttl:", "")
            ttl_days = 0 if ttl_str == "permanent" else int(ttl_str.replace("d", ""))
            category = parts[5] if len(parts) > 5 else "unknown"
            
            return cls(
                domain=domain,
                source=source,
                weight=weight,
                confirmed_by=confirmed_by,
                added_date=added_date,
                ttl_days=ttl_days,
                category=category,
                confidence=0,  # Not stored in comment
            )
        except (ValueError, IndexError):
            return None


# Default TTL by source type (in days)
DEFAULT_TTL_BY_SOURCE = {
    "heuristic": 7,
    "ct_logs": 14,
    "user_report": 30,
    "feed_cc0": 60,
    "feed_mit": 60,
    "feed_permissive": 60,
    "user_confirmed": 90,
    "admin_confirmed": 365,
    "manual": 365,
    "multi_signal": 30,
}


class DomainExporter:
    """
    Export confirmed threat domains to blocklist files.
    
    Features:
    - ATOMIC writes (tmp → rename) to prevent corruption
    - METADATA per entry for easy audit/rollback
    - TTL-based auto-cleanup of old entries
    - Duplicate detection
    
    Two modes of operation:
    
    1. GENERATE (UI button):
       - generate_blocklist() creates file from scratch
       - Includes all confirmed domains from DB
       - Creates backup of existing file
    
    2. APPEND (automatic):
       - append_domain() adds single domain to existing file
       - Checks for duplicates before adding
       - Does NOT overwrite existing content
    
    IMPORTANT: Only exports domains that meet strict criteria.
    Heuristic-only detections are NEVER exported automatically.
    """
    
    # Minimum requirements for automatic export
    MIN_CONFIDENCE_FOR_EXPORT = 70
    MIN_SIGNALS_FOR_AUTO_EXPORT = 3
    
    # Markers for file parsing
    HEADER_MARKER = "# EasyPi NetProtection"
    DOMAIN_COUNT_PATTERN = re.compile(r"^# Domain count: (\d+)")
    METADATA_PATTERN = re.compile(r"#\s*(.+\|.+\|.+\|.+\|.+)")
    
    def __init__(
        self,
        db: ThreatDatabase,
        export_dir: str | Path = "exports",
        backup_count: int = 5,
        default_file: str = "blocklist.txt",
        default_format: ExportFormat = ExportFormat.HOSTS,
        enable_ttl_cleanup: bool = True,
    ):
        """
        Initialize domain exporter.
        
        Args:
            db: Threat database instance
            export_dir: Directory for export files
            backup_count: Number of backup files to keep
            default_file: Default blocklist filename
            default_format: Default export format
            enable_ttl_cleanup: Enable automatic TTL-based cleanup
        """
        self.db = db
        self.export_dir = Path(export_dir)
        self.backup_count = backup_count
        self.default_file = default_file
        self.default_format = default_format
        self.enable_ttl_cleanup = enable_ttl_cleanup
        
        self.export_dir.mkdir(parents=True, exist_ok=True)
    
    # ========================================
    # ATOMIC WRITE — tmp → rename
    # ========================================
    
    def _atomic_write(self, file_path: Path, content: str) -> None:
        """
        Write file atomically using tmp → rename pattern.
        
        This prevents corrupted files if the process crashes mid-write.
        """
        # Create temp file in same directory (for same filesystem rename)
        fd, tmp_path = tempfile.mkstemp(
            suffix=".tmp",
            prefix=file_path.stem + "_",
            dir=file_path.parent,
        )
        
        try:
            # Write content to temp file
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())  # Ensure written to disk
            
            # Atomic rename (on POSIX; Windows may need special handling)
            tmp = Path(tmp_path)
            tmp.replace(file_path)  # Atomic on same filesystem
            
        except Exception:
            # Cleanup temp file on error
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    
    # ========================================
    # GENERATE MODE — UI Button creates file
    # ========================================
    
    async def generate_blocklist(
        self,
        output_file: str | Path | None = None,
        format_type: ExportFormat | None = None,
        criteria: ExportCriteria = ExportCriteria.CONFIRMED_ONLY,
        min_confidence: float | None = None,
        categories: list[str] | None = None,
        confirmed_by: str = "system",
    ) -> tuple[int, Path]:
        """
        Generate blocklist file from scratch (UI button action).
        
        This completely regenerates the file with all confirmed domains.
        Creates backup of existing file before overwriting.
        Uses ATOMIC write (tmp → rename) to prevent corruption.
        
        Args:
            output_file: Output filename (relative to export_dir)
            format_type: Output format
            criteria: Selection criteria
            min_confidence: Override minimum confidence
            categories: Filter by categories
            confirmed_by: Who triggered regeneration
        
        Returns:
            Tuple of (domain count, output path)
        """
        output_path = self.export_dir / (output_file or self.default_file)
        fmt = format_type or self.default_format
        
        # Backup existing file before overwriting
        if output_path.exists():
            self._rotate_backups(output_path)
        
        # Get ALL domains matching criteria from DB
        domains = await self._get_exportable_domains(
            criteria, min_confidence, categories
        )
        
        # Generate file content with metadata
        content = self._format_domains_with_metadata(domains, fmt, confirmed_by)
        
        # ATOMIC WRITE: tmp → rename
        self._atomic_write(output_path, content)
        
        return len(domains), output_path
    
    # ========================================
    # APPEND MODE — Program adds domains
    # ========================================
    
    async def append_domain(
        self,
        domain: str,
        category: str = "confirmed",
        confidence: float = 100.0,
        source: str = "admin_confirmed",
        weight: int = 80,
        confirmed_by: str = "system",
        ttl_days: int | None = None,
        output_file: str | Path | None = None,
        format_type: ExportFormat | None = None,
    ) -> tuple[bool, str]:
        """
        Append a single domain to existing blocklist file.
        
        This method is called when a domain is confirmed.
        It adds the domain to the file WITHOUT regenerating everything.
        Includes full metadata for audit/rollback.
        
        Args:
            domain: Domain to add
            category: Threat category
            confidence: Confidence score
            source: Source type
            weight: Source weight
            confirmed_by: Who confirmed (username or "system")
            ttl_days: Days until auto-expiry (None = use default for source)
            output_file: Target file (default: default_file)
            format_type: Export format (default: default_format)
        
        Returns:
            Tuple of (success, message)
            - (True, "added") if domain was added
            - (True, "exists") if domain already in file
            - (False, error) if file doesn't exist or error
        """
        output_path = self.export_dir / (output_file or self.default_file)
        fmt = format_type or self.default_format
        
        # Check if file exists
        if not output_path.exists():
            return False, "File not found. Generate blocklist first."
        
        # Read existing domains
        existing_domains = self._read_domains_from_file(output_path, fmt)
        
        # Check for duplicate
        if domain.lower() in existing_domains:
            return True, "exists"
        
        # Determine TTL
        actual_ttl = ttl_days if ttl_days is not None else DEFAULT_TTL_BY_SOURCE.get(source, 30)
        
        # Create metadata
        metadata = DomainMetadata(
            domain=domain.lower(),
            source=source,
            weight=weight,
            confirmed_by=confirmed_by,
            added_date=datetime.now(timezone.utc),
            ttl_days=actual_ttl,
            category=category,
            confidence=confidence,
        )
        
        # Format new domain line with metadata
        new_line = self._format_single_domain_with_metadata(domain, fmt, metadata)
        
        # Append to file (simple append is atomic enough for single line)
        with output_path.open("a", encoding="utf-8") as f:
            f.write(new_line + "\n")
        
        # Update domain count in header
        self._update_domain_count(output_path, len(existing_domains) + 1)
        
        return True, "added"
    
    async def append_domains_batch(
        self,
        domains: list[dict],
        confirmed_by: str = "system",
        output_file: str | Path | None = None,
        format_type: ExportFormat | None = None,
    ) -> tuple[int, int, int]:
        """
        Append multiple domains at once (batch operation).
        
        More efficient than calling append_domain() multiple times.
        Uses ATOMIC write for the entire batch.
        
        Args:
            domains: List of dicts with {domain, category, confidence, source, weight}
            confirmed_by: Who confirmed
            output_file: Target file
            format_type: Export format
        
        Returns:
            Tuple of (added_count, skipped_count, error_count)
        """
        output_path = self.export_dir / (output_file or self.default_file)
        fmt = format_type or self.default_format
        
        if not output_path.exists():
            return 0, 0, len(domains)
        
        # Read existing content and domains
        existing_content = output_path.read_text(encoding="utf-8")
        existing_domains = self._read_domains_from_file(output_path, fmt)
        
        added = 0
        skipped = 0
        new_lines = []
        now = datetime.now(timezone.utc)
        
        for d in domains:
            domain = d.get("domain", "").lower()
            if not domain:
                continue
            
            if domain in existing_domains:
                skipped += 1
            else:
                # Create metadata for each domain
                source = d.get("source", "admin_confirmed")
                metadata = DomainMetadata(
                    domain=domain,
                    source=source,
                    weight=d.get("weight", 80),
                    confirmed_by=confirmed_by,
                    added_date=now,
                    ttl_days=d.get("ttl_days") or DEFAULT_TTL_BY_SOURCE.get(source, 30),
                    category=d.get("category", "confirmed"),
                    confidence=d.get("confidence", 100.0),
                )
                new_lines.append(self._format_single_domain_with_metadata(domain, fmt, metadata))
                existing_domains.add(domain)
                added += 1
        
        # ATOMIC WRITE: rebuild entire file with new entries
        if new_lines:
            # Update header count
            new_content = self._update_header_count(existing_content, len(existing_domains))
            new_content = new_content.rstrip("\n") + "\n" + "\n".join(new_lines) + "\n"
            
            self._atomic_write(output_path, new_content)
        
        return added, skipped, 0
    
    def _read_domains_from_file(
        self,
        file_path: Path,
        format_type: ExportFormat,
    ) -> set[str]:
        """Read existing domains from blocklist file."""
        domains = set()
        
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return domains
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # Extract domain based on format (ignore metadata comment)
            domain = self._extract_domain_from_line(line, format_type)
            if domain:
                domains.add(domain.lower())
        
        return domains
    
    def _read_entries_with_metadata(
        self,
        file_path: Path,
        format_type: ExportFormat,
    ) -> list[DomainMetadata]:
        """Read domains with their metadata for TTL cleanup."""
        entries = []
        
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return entries
        
        for line in content.splitlines():
            line = line.strip()
            
            if not line or line.startswith("#"):
                continue
            
            # Extract domain and metadata
            domain = self._extract_domain_from_line(line, format_type)
            if not domain:
                continue
            
            # Try to parse metadata from comment
            metadata = None
            if "#" in line:
                comment = line.split("#", 1)[1].strip()
                metadata = DomainMetadata.from_comment(domain, comment)
            
            if metadata:
                entries.append(metadata)
            else:
                # Entry without metadata - create default
                entries.append(DomainMetadata(
                    domain=domain,
                    source="unknown",
                    weight=50,
                    confirmed_by="unknown",
                    added_date=datetime.now(timezone.utc),
                    ttl_days=0,  # No expiry for legacy entries
                    category="unknown",
                    confidence=0,
                ))
        
        return entries
    
    def _extract_domain_from_line(
        self,
        line: str,
        format_type: ExportFormat,
    ) -> str | None:
        """Extract domain from a blocklist line."""
        line = line.strip()
        
        if format_type == ExportFormat.HOSTS:
            # "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
        
        elif format_type == ExportFormat.DOMAINS:
            # Just the domain, possibly with comment
            if "#" in line:
                line = line.split("#")[0].strip()
            return line if line else None
        
        elif format_type == ExportFormat.DNSMASQ:
            # "address=/domain.com/"
            match = re.match(r"address=/([^/]+)/", line)
            if match:
                return match.group(1)
        
        elif format_type == ExportFormat.UNBOUND:
            # 'local-zone: "domain.com" refuse'
            match = re.match(r'local-zone:\s*"([^"]+)"', line)
            if match:
                return match.group(1)
        
        elif format_type == ExportFormat.ADBLOCK:
            # "||domain.com^"
            match = re.match(r"\|\|([^^]+)\^", line)
            if match:
                return match.group(1)
        
        return None
    
    def _format_single_domain(
        self,
        domain: str,
        format_type: ExportFormat,
    ) -> str:
        """Format a single domain for the blocklist."""
        domain = domain.lower().strip()
        
        if format_type == ExportFormat.HOSTS:
            return f"0.0.0.0 {domain}"
        elif format_type == ExportFormat.DOMAINS:
            return domain
        elif format_type == ExportFormat.DNSMASQ:
            return f"address=/{domain}/"
        elif format_type == ExportFormat.UNBOUND:
            return f'local-zone: "{domain}" refuse'
        elif format_type == ExportFormat.ADBLOCK:
            return f"||{domain}^"
        
        return domain
    
    def _format_single_domain_with_metadata(
        self,
        domain: str,
        format_type: ExportFormat,
        metadata: DomainMetadata,
    ) -> str:
        """Format domain with metadata comment for audit/rollback."""
        domain = domain.lower().strip()
        meta_comment = metadata.to_comment()
        
        if format_type == ExportFormat.HOSTS:
            return f"0.0.0.0 {domain} # {meta_comment}"
        elif format_type == ExportFormat.DOMAINS:
            return f"{domain} # {meta_comment}"
        elif format_type == ExportFormat.DNSMASQ:
            # dnsmasq doesn't support inline comments well, put on previous line
            return f"# {meta_comment}\naddress=/{domain}/"
        elif format_type == ExportFormat.UNBOUND:
            return f'local-zone: "{domain}" refuse # {meta_comment}'
        elif format_type == ExportFormat.ADBLOCK:
            return f"||{domain}^ # {meta_comment}"
        
        return f"{domain} # {meta_comment}"
    
    def _update_header_count(self, content: str, new_count: int) -> str:
        """Update domain count in header and return modified content."""
        lines = content.splitlines()
        now = datetime.now(timezone.utc).isoformat()
        
        for i, line in enumerate(lines):
            if line.startswith("# Domain count:"):
                lines[i] = f"# Domain count: {new_count}"
            elif line.startswith("# Last updated:"):
                lines[i] = f"# Last updated: {now}"
        
        return "\n".join(lines)
    
    def _update_domain_count(self, file_path: Path, new_count: int) -> None:
        """Update domain count in file header (atomic)."""
        try:
            content = file_path.read_text(encoding="utf-8")
            new_content = self._update_header_count(content, new_count)
            self._atomic_write(file_path, new_content + "\n")
        except Exception:
            pass  # Non-critical, don't fail
    
    # ========================================
    # TTL CLEANUP — Auto-remove expired entries
    # ========================================
    
    async def cleanup_expired(
        self,
        file_path: str | Path | None = None,
        format_type: ExportFormat | None = None,
    ) -> tuple[int, int]:
        """
        Remove expired entries based on TTL.
        
        Returns:
            Tuple of (removed_count, remaining_count)
        """
        path = self.export_dir / (file_path or self.default_file)
        fmt = format_type or self.default_format
        
        if not path.exists():
            return 0, 0
        
        entries = self._read_entries_with_metadata(path, fmt)
        
        active_entries = []
        removed_count = 0
        
        for entry in entries:
            if entry.is_expired():
                removed_count += 1
            else:
                active_entries.append(entry)
        
        if removed_count > 0:
            # Rebuild file with only active entries
            content = self._rebuild_file_content(active_entries, fmt)
            self._atomic_write(path, content)
        
        return removed_count, len(active_entries)
    
    def _rebuild_file_content(
        self,
        entries: list[DomainMetadata],
        format_type: ExportFormat,
    ) -> str:
        """Rebuild entire file content from entries."""
        now = datetime.now(timezone.utc).isoformat()
        
        header = [
            "# EasyPi NetProtection - Confirmed Threats Blocklist",
            f"# Generated: {now}",
            f"# Last updated: {now}",
            f"# Format: {format_type.value}",
            f"# Domain count: {len(entries)}",
            "#",
            "# Metadata format: source|weight|confirmed_by|date|ttl|category",
            "# Entries with expired TTL are automatically removed.",
            "#",
            "# [!] WARNING: This file may contain false positives.",
            "# Review quarantined domains before permanent blocking.",
            "#",
            "",
        ]
        
        lines = header.copy()
        for entry in entries:
            lines.append(self._format_single_domain_with_metadata(
                entry.domain, format_type, entry
            ))
        
        return "\n".join(lines) + "\n"
    
    async def _get_exportable_domains(
        self,
        criteria: ExportCriteria,
        min_confidence: float | None,
        categories: list[str] | None,
    ) -> list[dict]:
        """
        Get domains that meet export criteria.
        
        Returns list of dicts with domain info:
        {domain, category, confidence, source, signals, weight, created_at}
        """
        await self.db.initialize()
        
        min_conf = min_confidence or self.MIN_CONFIDENCE_FOR_EXPORT
        params: list[object] = []
        
        # Build query based on criteria
        if criteria == ExportCriteria.CONFIRMED_ONLY:
            # Only admin-confirmed domains
            query = """
                SELECT domain, category, current_confidence, source_type, 
                       signal_count, source_details, source_weight, created_at
                FROM threats
                WHERE status = 'confirmed'
                AND source_type IN ('admin_confirmed', 'manual')
            """
        
        elif criteria == ExportCriteria.MULTI_SIGNAL:
            # Multiple independent signals
            query = """
                SELECT domain, category, current_confidence, source_type,
                       signal_count, source_details, source_weight, created_at
                FROM threats
                WHERE status IN ('confirmed', 'quarantine')
                AND signal_count >= ?
                AND current_confidence >= ?
            """
            params.extend((self.MIN_SIGNALS_FOR_AUTO_EXPORT, min_conf))
        
        elif criteria == ExportCriteria.HIGH_CONFIDENCE:
            # High confidence from any source
            query = """
                SELECT domain, category, current_confidence, source_type,
                       signal_count, source_details, created_at
                FROM threats
                WHERE status IN ('confirmed', 'quarantine')
                AND current_confidence >= ?
                AND source_weight >= 50
            """
            params.append(min_conf)
        
        elif criteria == ExportCriteria.FEED_VERIFIED:
            # Verified via trusted feeds
            query = """
                SELECT domain, category, current_confidence, source_type,
                       signal_count, source_details, created_at
                FROM threats
                WHERE status IN ('confirmed', 'observed')
                AND source_type IN ('feed_cc0', 'feed_mit', 'feed_permissive')
                AND current_confidence >= ?
            """
            params.append(min_conf)
        
        else:
            # Default: confirmed only
            query = """
                SELECT domain, category, current_confidence, source_type,
                       signal_count, source_details, created_at
                FROM threats
                WHERE status = 'confirmed'
            """
        
        # Add category filter
        if categories:
            placeholders = ", ".join("?" for _ in categories)
            query += f" AND category IN ({placeholders})"
            params.extend(categories)
        
        query += " ORDER BY current_confidence DESC"
        
        with self.db._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        
        return [
            {
                "domain": row["domain"],
                "category": row["category"],
                "confidence": row["current_confidence"],
                "source": row["source_type"],
                "signals": row["signal_count"],
                "details": row["source_details"],
                "created": row["created_at"],
            }
            for row in rows
        ]
    
    def _format_domains(
        self,
        domains: list[dict],
        format_type: ExportFormat,
    ) -> str:
        """Format domains into blocklist file content."""
        now = datetime.now(timezone.utc).isoformat()
        
        # Header with metadata
        header_lines = [
            "# EasyPi NetProtection - Confirmed Threats Blocklist",
            f"# Generated: {now}",
            f"# Last updated: {now}",
            f"# Format: {format_type.value}",
            f"# Domain count: {len(domains)}",
            "# ",
            "# This file can be:",
            "#   - Regenerated via UI button (replaces all)",
            "#   - Auto-updated when threats are confirmed (appends)",
            "# ",
            "# Only CONFIRMED threats are included.",
            "#",
            "",
        ]
        
        lines = header_lines.copy()
        
        for d in domains:
            domain = d["domain"]
            lines.append(self._format_single_domain(domain, format_type))
        
        return "\n".join(lines) + "\n"
    
    def _format_domains_with_metadata(
        self,
        domains: list[dict],
        format_type: ExportFormat,
        confirmed_by: str = "system",
    ) -> str:
        """
        Format domains with full metadata (for audit/rollback).
        
        Each line includes: source|weight|confirmed_by|date|ttl|category
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        
        header_lines = [
            "# EasyPi NetProtection - Confirmed Threats Blocklist",
            f"# Generated: {now_iso}",
            f"# Last updated: {now_iso}",
            f"# Format: {format_type.value}",
            f"# Domain count: {len(domains)}",
            "#",
            "# Metadata format: source|weight|confirmed_by|date|ttl|category",
            "# Entries with expired TTL are automatically removed.",
            "#",
            "# [!] WARNING: This file may contain FALSE POSITIVES.",
            "#    Heuristic detection can produce incorrect results.",
            "#    Review quarantined domains before permanent blocking.",
            "#    Use 'cleanup_expired' to remove old entries by TTL.",
            "#",
            "",
        ]
        
        lines = header_lines.copy()
        
        for d in domains:
            domain = d.get("domain", "")
            if not domain:
                continue
            
            source = d.get("source", "confirmed")
            weight = d.get("weight", 80)
            ttl = DEFAULT_TTL_BY_SOURCE.get(source, 30)
            
            metadata = DomainMetadata(
                domain=domain.lower(),
                source=source,
                weight=weight,
                confirmed_by=confirmed_by,
                added_date=now,
                ttl_days=ttl,
                category=d.get("category", "unknown"),
                confidence=d.get("confidence", 100.0),
            )
            
            lines.append(self._format_single_domain_with_metadata(
                domain, format_type, metadata
            ))
        
        return "\n".join(lines) + "\n"
    
    def _rotate_backups(self, file_path: Path) -> None:
        """Rotate backup files."""
        # Remove oldest backup
        oldest = file_path.with_suffix(f".bak.{self.backup_count}")
        if oldest.exists():
            oldest.unlink()
        
        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            current = file_path.with_suffix(f".bak.{i}")
            next_backup = file_path.with_suffix(f".bak.{i + 1}")
            if current.exists():
                current.rename(next_backup)
        
        # Move current to .bak.1
        first_backup = file_path.with_suffix(".bak.1")
        file_path.rename(first_backup)
    
    async def export_with_metadata(
        self,
        output_file: str | Path,
        format_type: ExportFormat = ExportFormat.DOMAINS,
    ) -> tuple[int, Path]:
        """
        Export domains with full metadata as comments.
        
        Includes: source, confidence, category, date for each domain.
        """
        output_path = self.export_dir / output_file
        
        if output_path.exists():
            self._rotate_backups(output_path)
        
        domains = await self._get_exportable_domains(
            ExportCriteria.CONFIRMED_ONLY, None, None
        )
        
        now = datetime.now(timezone.utc).isoformat()
        
        lines = [
            "# EasyPi NetProtection - Confirmed Threats (with metadata)",
            f"# Generated: {now}",
            f"# Domain count: {len(domains)}",
            "#",
            "# Format: domain # category | confidence | source | date",
            "#",
            "",
        ]
        
        for d in domains:
            meta = f"{d['category']} | {d['confidence']:.0f}% | {d['source']} | {d['created'][:10]}"
            lines.append(f"{d['domain']} # {meta}")
        
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        
        return len(domains), output_path
    
    # ========================================
    # Backwards compatibility
    # ========================================
    
    async def export_confirmed_domains(
        self,
        output_file: str | Path,
        format_type: ExportFormat = ExportFormat.HOSTS,
        criteria: ExportCriteria = ExportCriteria.CONFIRMED_ONLY,
        min_confidence: float | None = None,
        categories: list[str] | None = None,
    ) -> tuple[int, Path]:
        """
        Alias for generate_blocklist() for backwards compatibility.
        """
        return await self.generate_blocklist(
            output_file, format_type, criteria, min_confidence, categories
        )
    
    # ========================================
    # File info and status
    # ========================================
    
    def get_blocklist_info(
        self,
        file_path: str | Path | None = None,
    ) -> dict:
        """
        Get information about existing blocklist file for UI display.
        
        Includes FP warning info for UI.
        
        Returns:
            Dict with file status:
            - exists: bool
            - path: str
            - domain_count: int
            - generated: str (timestamp)
            - last_updated: str (timestamp)
            - format: str
            - file_size_kb: float
            - sources_breakdown: dict (count by source type)
            - expiring_soon: int (entries expiring in 7 days)
            - warning: str (FP warning message for UI)
        """
        path = self.export_dir / (file_path or self.default_file)
        
        info = {
            "exists": False,
            "path": str(path),
            "domain_count": 0,
            "generated": None,
            "last_updated": None,
            "format": None,
            "file_size_kb": 0.0,
            "sources_breakdown": {},
            "expiring_soon": 0,
            "warning": None,
        }
        
        if not path.exists():
            return info
        
        info["exists"] = True
        
        try:
            info["file_size_kb"] = round(path.stat().st_size / 1024, 2)
            content = path.read_text(encoding="utf-8")
            
            for line in content.splitlines()[:20]:  # Check first 20 lines
                if line.startswith("# Generated:"):
                    info["generated"] = line.split(":", 1)[1].strip()
                elif line.startswith("# Last updated:"):
                    info["last_updated"] = line.split(":", 1)[1].strip()
                elif line.startswith("# Format:"):
                    info["format"] = line.split(":", 1)[1].strip()
                elif line.startswith("# Domain count:"):
                    try:
                        info["domain_count"] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
            
            # Parse entries for detailed stats
            fmt = ExportFormat(info["format"]) if info["format"] else self.default_format
            entries = self._read_entries_with_metadata(path, fmt)
            
            if entries:
                # Actual count from file
                info["domain_count"] = len(entries)
                
                # Breakdown by source
                sources: dict[str, int] = {}
                expiring_soon = 0
                heuristic_count = 0
                
                for entry in entries:
                    src = entry.source
                    sources[src] = sources.get(src, 0) + 1
                    
                    # Check if expiring in 7 days
                    days_until_expiry = entry.days_until_expiry()
                    if days_until_expiry is not None and 0 < days_until_expiry <= 7:
                        expiring_soon += 1
                    
                    # Count heuristic entries
                    if src in ("heuristic", "behavioral", "ct_logs"):
                        heuristic_count += 1
                
                info["sources_breakdown"] = sources
                info["expiring_soon"] = expiring_soon
                
                # FP warning if significant heuristic entries
                if heuristic_count > 0:
                    heuristic_pct = (heuristic_count / len(entries)) * 100
                    info["warning"] = (
                        f"[!] {heuristic_count} domains ({heuristic_pct:.0f}%) from heuristic "
                        f"detection. May contain FALSE POSITIVES. Review before permanent use."
                    )
            elif info["domain_count"] == 0:
                # Fallback: count domains manually if no metadata
                info["domain_count"] = len(self._read_domains_from_file(path, fmt))
        
        except Exception:
            pass
        
        return info


class AutoExporter:
    """
    Automatic domain export triggered by confirmations.
    
    When a domain is confirmed (manually or via multi-signal threshold),
    automatically APPENDS to the blocklist file (does not regenerate).
    
    Workflow:
    1. User clicks "Generate blocklist" in UI → generate_blocklist()
    2. Domain gets confirmed → on_domain_confirmed() → append_domain()
    """
    
    def __init__(
        self,
        exporter: DomainExporter,
        auto_export_file: str = "blocklist.txt",
        export_format: ExportFormat = ExportFormat.HOSTS,
        debounce_seconds: float = 5.0,
    ):
        """
        Initialize auto-exporter.
        
        Args:
            exporter: Domain exporter instance
            auto_export_file: Output filename
            export_format: Output format
            debounce_seconds: Delay before append (to batch multiple confirms)
        """
        self.exporter = exporter
        self.auto_export_file = auto_export_file
        self.export_format = export_format
        self.debounce_seconds = debounce_seconds
        
        self._pending_domains: list[dict] = []
        self._export_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
    
    async def on_domain_confirmed(
        self,
        domain: str,
        category: str = "confirmed",
        confidence: float = 100.0,
        source: str = "admin_confirmed",
    ) -> None:
        """
        Called when a domain is confirmed.
        
        Adds domain to pending queue and triggers debounced append.
        Multiple domains confirmed quickly will be batched together.
        """
        async with self._lock:
            self._pending_domains.append({
                "domain": domain,
                "category": category,
                "confidence": confidence,
                "source": source,
            })
        
        if self._export_task is None or self._export_task.done():
            self._export_task = asyncio.create_task(self._debounced_append())
    
    async def _debounced_append(self) -> None:
        """Append pending domains after debounce delay."""
        await asyncio.sleep(self.debounce_seconds)
        
        async with self._lock:
            if not self._pending_domains:
                return
            
            domains_to_add = self._pending_domains.copy()
            self._pending_domains.clear()
        
        # Batch append all pending domains
        added, skipped, errors = await self.exporter.append_domains_batch(
            domains_to_add,
            self.auto_export_file,
            self.export_format,
        )
        
        # If file doesn't exist, no action (user needs to generate first)
        if errors > 0 and added == 0 and skipped == 0:
            # Re-queue domains for later (file not ready yet)
            async with self._lock:
                self._pending_domains.extend(domains_to_add)
    
    async def force_regenerate(self) -> tuple[int, Path]:
        """
        Force full regeneration of blocklist (like UI button).
        
        Clears pending queue and regenerates from database.
        """
        async with self._lock:
            self._pending_domains.clear()
        
        return await self.exporter.generate_blocklist(
            self.auto_export_file,
            self.export_format,
            ExportCriteria.CONFIRMED_ONLY,
        )
    
    def get_pending_count(self) -> int:
        """Get number of domains pending append."""
        return len(self._pending_domains)
