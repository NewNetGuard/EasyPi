"""
Schedule Manager

Time-based access control for parental controls.

Features:
- Per-day schedules (different rules for weekdays/weekends)
- Multiple time windows per day
- Bedtime enforcement
- Homework time (educational sites only)
- Internet pause/resume with auto-expire

TIMEZONE HANDLING:
- All times stored and compared in UTC
- Conversion to local time happens at display layer (frontend)
- Server uses system timezone for default conversions

PAUSE BEHAVIOR:
- Pause has explicit expiration time
- Auto-expires when checked after expiration
- Manual resume always works
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from enum import Enum
from typing import Any


logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    """Get current time in UTC."""
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DayOfWeek(Enum):
    """Days of the week."""
    
    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"
    
    @classmethod
    def from_datetime(cls, dt: datetime) -> "DayOfWeek":
        """Get DayOfWeek from datetime (uses local timezone for day calculation)."""
        days = [
            cls.MONDAY, cls.TUESDAY, cls.WEDNESDAY, cls.THURSDAY,
            cls.FRIDAY, cls.SATURDAY, cls.SUNDAY
        ]
        return days[dt.weekday()]
    
    @classmethod
    def today(cls) -> "DayOfWeek":
        return cls.from_datetime(datetime.now())
    
    @property
    def is_weekend(self) -> bool:
        return self in (DayOfWeek.SATURDAY, DayOfWeek.SUNDAY)
    
    @property
    def is_weekday(self) -> bool:
        return not self.is_weekend


class ScheduleAction(Enum):
    """Actions that can be scheduled."""
    
    ALLOW = "allow"              # Normal access
    BLOCK = "block"              # Block all internet
    BEDTIME = "bedtime"          # Block entertainment, allow educational
    HOMEWORK = "homework"        # Only educational sites
    LIMIT = "limit"              # Rate-limited access


# Categories allowed during different schedule modes
SCHEDULE_ALLOWED_CATEGORIES: dict[ScheduleAction, set[str]] = {
    ScheduleAction.ALLOW: set(),  # Everything allowed (use age filter)
    ScheduleAction.BLOCK: set(),  # Nothing allowed
    ScheduleAction.BEDTIME: {
        # Only allow essential services during bedtime
        "educational", "health", "emergency",
    },
    ScheduleAction.HOMEWORK: {
        # Educational resources only
        "educational", "search_engine", "library", "encyclopedia",
    },
    ScheduleAction.LIMIT: set(),  # Rate-limited, use age filter
}

# Domains always allowed (safety/essential)
ALWAYS_ALLOWED_DOMAINS: frozenset[str] = frozenset({
    # Safety & Emergency
    "911.gov",
    "redcross.org",
    
    # Family communication
    "messages.google.com",
    "web.whatsapp.com",
    
    # Essential educational
    "google.com",  # Search
    "bing.com",
    "duckduckgo.com",
    "wikipedia.org",
    "khanacademy.org",
    "education.com",
    "britannica.com",
})


@dataclass
class TimeWindow:
    """A time window within a day."""
    
    start: time
    end: time
    action: ScheduleAction = ScheduleAction.ALLOW
    
    def contains(self, t: time) -> bool:
        """Check if time is within this window."""
        if self.start <= self.end:
            # Normal case: 09:00 - 17:00
            return self.start <= t < self.end
        else:
            # Overnight case: 22:00 - 06:00
            return t >= self.start or t < self.end
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.strftime("%H:%M"),
            "end": self.end.strftime("%H:%M"),
            "action": self.action.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimeWindow":
        return cls(
            start=time.fromisoformat(data["start"]),
            end=time.fromisoformat(data["end"]),
            action=ScheduleAction(data.get("action", "allow")),
        )


@dataclass
class DaySchedule:
    """Schedule for a single day."""
    
    day: DayOfWeek
    windows: list[TimeWindow] = field(default_factory=list)
    default_action: ScheduleAction = ScheduleAction.ALLOW
    
    def get_action(self, t: time) -> ScheduleAction:
        """Get the action for a specific time."""
        for window in self.windows:
            if window.contains(t):
                return window.action
        return self.default_action
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "day": self.day.value,
            "windows": [w.to_dict() for w in self.windows],
            "default_action": self.default_action.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DaySchedule":
        return cls(
            day=DayOfWeek(data["day"]),
            windows=[TimeWindow.from_dict(w) for w in data.get("windows", [])],
            default_action=ScheduleAction(data.get("default_action", "allow")),
        )


@dataclass
class ScheduleRule:
    """A complete schedule rule with optional expiration."""
    
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    
    # Schedule per day
    day_schedules: dict[DayOfWeek, DaySchedule] = field(default_factory=dict)
    
    # Shortcuts for common patterns
    weekday_default: ScheduleAction = ScheduleAction.ALLOW
    weekend_default: ScheduleAction = ScheduleAction.ALLOW
    
    # Bedtime settings (applies to all days unless overridden)
    bedtime_enabled: bool = False
    bedtime_start: time = field(default_factory=lambda: time(21, 0))  # 9 PM
    bedtime_end: time = field(default_factory=lambda: time(7, 0))     # 7 AM
    bedtime_weekend_start: time = field(default_factory=lambda: time(22, 0))  # 10 PM
    bedtime_weekend_end: time = field(default_factory=lambda: time(9, 0))     # 9 AM
    
    # Internet pause (temporary override)
    paused: bool = False
    paused_until: datetime | None = None
    
    # Daily time limits (minutes)
    daily_limit_enabled: bool = False
    daily_limit_minutes: int = 120  # 2 hours default
    
    created_at: datetime = field(default_factory=_now_utc)
    updated_at: datetime = field(default_factory=_now_utc)
    
    def get_current_action(self, now: datetime | None = None) -> ScheduleAction:
        """
        Get the current schedule action.
        
        Auto-expires pause when checked after expiration time.
        """
        if now is None:
            now = _now_utc()
        else:
            now = _ensure_utc(now)
        
        # Check pause with auto-expire
        if self.paused:
            if self.paused_until:
                pause_until_utc = _ensure_utc(self.paused_until)
                if now >= pause_until_utc:
                    # Pause expired - auto-clear
                    logger.info(f"Schedule '{self.name}' pause auto-expired")
                    self.paused = False
                    self.paused_until = None
                else:
                    return ScheduleAction.BLOCK
            else:
                # Paused indefinitely (shouldn't happen, but handle it)
                return ScheduleAction.BLOCK
        
        current_day = DayOfWeek.from_datetime(now)
        current_time = now.time()
        
        # Check bedtime
        if self.bedtime_enabled:
            if current_day.is_weekend:
                bedtime_start = self.bedtime_weekend_start
                bedtime_end = self.bedtime_weekend_end
            else:
                bedtime_start = self.bedtime_start
                bedtime_end = self.bedtime_end
            
            # Check if in bedtime window
            bedtime_window = TimeWindow(bedtime_start, bedtime_end, ScheduleAction.BEDTIME)
            if bedtime_window.contains(current_time):
                return ScheduleAction.BEDTIME
        
        # Check day-specific schedule
        if current_day in self.day_schedules:
            return self.day_schedules[current_day].get_action(current_time)
        
        # Use default for weekday/weekend
        if current_day.is_weekend:
            return self.weekend_default
        return self.weekday_default
    
    def pause(self, duration_minutes: int = 30) -> None:
        """
        Pause internet access for specified duration.
        
        Pause auto-expires after duration_minutes.
        """
        self.paused = True
        self.paused_until = _now_utc() + timedelta(minutes=duration_minutes)
        logger.info(f"Schedule '{self.name}' paused for {duration_minutes} minutes (until {self.paused_until})")
    
    def resume(self) -> None:
        """Resume internet access (manual override)."""
        self.paused = False
        self.paused_until = None
        logger.info(f"Schedule '{self.name}' resumed")
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "day_schedules": {
                day.value: sched.to_dict()
                for day, sched in self.day_schedules.items()
            },
            "weekday_default": self.weekday_default.value,
            "weekend_default": self.weekend_default.value,
            "bedtime_enabled": self.bedtime_enabled,
            "bedtime_start": self.bedtime_start.strftime("%H:%M"),
            "bedtime_end": self.bedtime_end.strftime("%H:%M"),
            "bedtime_weekend_start": self.bedtime_weekend_start.strftime("%H:%M"),
            "bedtime_weekend_end": self.bedtime_weekend_end.strftime("%H:%M"),
            "paused": self.paused,
            "paused_until": self.paused_until.isoformat() if self.paused_until else None,
            "daily_limit_enabled": self.daily_limit_enabled,
            "daily_limit_minutes": self.daily_limit_minutes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScheduleRule":
        day_schedules = {}
        for day_str, sched_data in data.get("day_schedules", {}).items():
            day = DayOfWeek(day_str)
            day_schedules[day] = DaySchedule.from_dict(sched_data)
        
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            day_schedules=day_schedules,
            weekday_default=ScheduleAction(data.get("weekday_default", "allow")),
            weekend_default=ScheduleAction(data.get("weekend_default", "allow")),
            bedtime_enabled=data.get("bedtime_enabled", False),
            bedtime_start=time.fromisoformat(data.get("bedtime_start", "21:00")),
            bedtime_end=time.fromisoformat(data.get("bedtime_end", "07:00")),
            bedtime_weekend_start=time.fromisoformat(data.get("bedtime_weekend_start", "22:00")),
            bedtime_weekend_end=time.fromisoformat(data.get("bedtime_weekend_end", "09:00")),
            paused=data.get("paused", False),
            paused_until=datetime.fromisoformat(data["paused_until"]) if data.get("paused_until") else None,
            daily_limit_enabled=data.get("daily_limit_enabled", False),
            daily_limit_minutes=data.get("daily_limit_minutes", 120),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )


@dataclass
class Schedule:
    """Complete schedule configuration for a profile."""
    
    profile_id: str
    rule: ScheduleRule | None = None
    enabled: bool = True
    
    # Usage tracking (no PII - just counts)
    today_usage_minutes: int = 0
    last_usage_reset: datetime = field(default_factory=datetime.now)
    
    def check_access(self, domain: str, now: datetime | None = None) -> tuple[bool, str]:
        """
        Check if access is allowed based on schedule.
        
        Returns:
            (allowed, reason)
        """
        if not self.enabled or not self.rule or not self.rule.enabled:
            return True, "Schedule disabled"
        
        if now is None:
            now = datetime.now()
        
        # Reset daily usage if new day
        if now.date() > self.last_usage_reset.date():
            self.today_usage_minutes = 0
            self.last_usage_reset = now
        
        # Check daily limit
        if self.rule.daily_limit_enabled:
            if self.today_usage_minutes >= self.rule.daily_limit_minutes:
                return False, f"Daily limit reached ({self.rule.daily_limit_minutes} min)"
        
        action = self.rule.get_current_action(now)
        
        # Always allow essential domains
        domain_lower = domain.lower().rstrip('.')
        for safe_domain in ALWAYS_ALLOWED_DOMAINS:
            if domain_lower == safe_domain or domain_lower.endswith('.' + safe_domain):
                return True, "Essential domain"
        
        if action == ScheduleAction.ALLOW:
            return True, "Allowed by schedule"
        
        elif action == ScheduleAction.BLOCK:
            return False, "Blocked by schedule (pause or block time)"
        
        elif action == ScheduleAction.BEDTIME:
            # During bedtime, check if domain is educational/essential
            # For now, allow only explicitly allowed domains
            return False, "Bedtime: only essential sites allowed"
        
        elif action == ScheduleAction.HOMEWORK:
            # Only educational domains
            return False, "Homework time: only educational sites allowed"
        
        elif action == ScheduleAction.LIMIT:
            # Rate limited - allow but track
            return True, "Rate-limited access"
        
        return True, "Default allow"
    
    def record_usage(self, minutes: int = 1) -> None:
        """Record usage time."""
        self.today_usage_minutes += minutes
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "rule": self.rule.to_dict() if self.rule else None,
            "enabled": self.enabled,
            "today_usage_minutes": self.today_usage_minutes,
            "last_usage_reset": self.last_usage_reset.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Schedule":
        return cls(
            profile_id=data["profile_id"],
            rule=ScheduleRule.from_dict(data["rule"]) if data.get("rule") else None,
            enabled=data.get("enabled", True),
            today_usage_minutes=data.get("today_usage_minutes", 0),
            last_usage_reset=datetime.fromisoformat(data["last_usage_reset"]) if data.get("last_usage_reset") else datetime.now(),
        )


class ScheduleManager:
    """
    Manages schedules for all profiles.
    """
    
    def __init__(self):
        self._schedules: dict[str, Schedule] = {}
        self._stats = {
            "checks": 0,
            "blocked_by_schedule": 0,
            "blocked_by_bedtime": 0,
            "blocked_by_limit": 0,
        }
    
    def get_schedule(self, profile_id: str) -> Schedule | None:
        """Get schedule for a profile."""
        return self._schedules.get(profile_id)
    
    def set_schedule(self, profile_id: str, schedule: Schedule) -> None:
        """Set schedule for a profile."""
        self._schedules[profile_id] = schedule
    
    def create_schedule(
        self,
        profile_id: str,
        rule_name: str = "Default Schedule",
        bedtime_enabled: bool = False,
        daily_limit_minutes: int | None = None,
    ) -> Schedule:
        """Create a new schedule with common defaults."""
        import uuid
        
        rule = ScheduleRule(
            id=str(uuid.uuid4()),
            name=rule_name,
            bedtime_enabled=bedtime_enabled,
            daily_limit_enabled=daily_limit_minutes is not None,
            daily_limit_minutes=daily_limit_minutes or 120,
        )
        
        schedule = Schedule(
            profile_id=profile_id,
            rule=rule,
            enabled=True,
        )
        
        self._schedules[profile_id] = schedule
        return schedule
    
    def check_access(
        self,
        profile_id: str,
        domain: str,
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        """Check if access is allowed for a profile."""
        self._stats["checks"] += 1
        
        schedule = self._schedules.get(profile_id)
        if not schedule:
            return True, "No schedule"
        
        allowed, reason = schedule.check_access(domain, now)
        
        if not allowed:
            if "bedtime" in reason.lower():
                self._stats["blocked_by_bedtime"] += 1
            elif "limit" in reason.lower():
                self._stats["blocked_by_limit"] += 1
            else:
                self._stats["blocked_by_schedule"] += 1
        
        return allowed, reason
    
    def pause_profile(self, profile_id: str, duration_minutes: int = 30) -> bool:
        """Pause internet for a profile."""
        schedule = self._schedules.get(profile_id)
        if schedule and schedule.rule:
            schedule.rule.pause(duration_minutes)
            return True
        return False
    
    def resume_profile(self, profile_id: str) -> bool:
        """Resume internet for a profile."""
        schedule = self._schedules.get(profile_id)
        if schedule and schedule.rule:
            schedule.rule.resume()
            return True
        return False
    
    def get_stats(self) -> dict[str, Any]:
        """Get manager statistics."""
        return {
            "total_checks": self._stats["checks"],
            "blocked_by_schedule": self._stats["blocked_by_schedule"],
            "blocked_by_bedtime": self._stats["blocked_by_bedtime"],
            "blocked_by_limit": self._stats["blocked_by_limit"],
            "active_schedules": len(self._schedules),
        }
    
    def load_schedules(self, data: list[dict[str, Any]]) -> int:
        """Load schedules from serialized data."""
        count = 0
        for item in data:
            try:
                schedule = Schedule.from_dict(item)
                self._schedules[schedule.profile_id] = schedule
                count += 1
            except Exception as e:
                logger.warning(f"Failed to load schedule: {e}")
        return count
    
    def save_schedules(self) -> list[dict[str, Any]]:
        """Serialize all schedules."""
        return [s.to_dict() for s in self._schedules.values()]


# Singleton
_schedule_manager: ScheduleManager | None = None


def get_schedule_manager() -> ScheduleManager:
    """Get singleton ScheduleManager."""
    global _schedule_manager
    if _schedule_manager is None:
        _schedule_manager = ScheduleManager()
    return _schedule_manager
