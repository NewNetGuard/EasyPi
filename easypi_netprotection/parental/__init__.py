"""
Parental Control Module

Age-based filtering and scheduling for family-friendly DNS protection.

Components:
- AgeFilter: Category-based content filtering by age group
- Scheduler: Time-based access control (bedtime, homework, limits)
- AppBlocker: IP-based blocking for apps that bypass DNS (Telegram, WhatsApp, etc.)
- Controller: Main coordinator for all parental control features
"""

from .age_filter import AgeCategory, AgeFilter, get_age_filter
from .scheduler import (
    Schedule,
    ScheduleRule,
    DayOfWeek,
    ScheduleAction,
    ScheduleManager,
    TimeWindow,
    DaySchedule,
    get_schedule_manager,
)
from .controller import ParentalController, get_parental_controller
from .app_blocker import (
    AppBlocker,
    AppNetworkInfo,
    BLOCKABLE_APPS,
    get_app_blocker,
)

__all__ = [
    # Age Filter
    "AgeCategory",
    "AgeFilter",
    "get_age_filter",
    # Scheduler
    "Schedule",
    "ScheduleRule", 
    "DayOfWeek",
    "ScheduleAction",
    "ScheduleManager",
    "TimeWindow",
    "DaySchedule",
    "get_schedule_manager",
    # App Blocker (IP-based)
    "AppBlocker",
    "AppNetworkInfo",
    "BLOCKABLE_APPS",
    "get_app_blocker",
    # Controller
    "ParentalController",
    "get_parental_controller",
]
