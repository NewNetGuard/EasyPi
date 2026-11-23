"""
EasyPi NetProtection — Shield Package.

Policy Layer: profiles, per-device policies, schedules.
"""

from .profiles import (
    ShieldProfile,
    ShieldProfileType,
    ShieldProfileType as ProfileType,  # Alias for backwards compatibility
    ProfileManager,
    create_strict_profile,
    create_balanced_profile,
    create_kids_profile,
    create_minimal_profile,
)

from .devices import (
    Device,
    DeviceType,
    DeviceStatus,
    DeviceManager,
    DeviceFingerprinter,
)

from .schedules import (
    Schedule,
    ScheduleType,
    ScheduleAction,
    ScheduleManager,
    TimeSlot,
    DaySchedule,
    Weekday,
    create_school_hours_schedule,
    create_bedtime_schedule,
    create_homework_schedule,
    create_work_hours_schedule,
)

__all__ = [
    # Profiles
    "ShieldProfile",
    "ShieldProfileType",
    "ProfileType",
    "ProfileManager",
    "create_strict_profile",
    "create_balanced_profile",
    "create_kids_profile",
    "create_minimal_profile",
    
    # Devices
    "Device",
    "DeviceType",
    "DeviceStatus",
    "DeviceManager",
    "DeviceFingerprinter",
    
    # Schedules
    "Schedule",
    "ScheduleType",
    "ScheduleAction",
    "ScheduleManager",
    "TimeSlot",
    "DaySchedule",
    "Weekday",
    "create_school_hours_schedule",
    "create_bedtime_schedule",
    "create_homework_schedule",
    "create_work_hours_schedule",
]
