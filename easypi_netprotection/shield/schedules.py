"""
EasyPi NetProtection — Schedule Management Module.

Временные расписания доступа для устройств.
Поддержка дневных расписаний, исключений и праздников.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, time, date, timedelta
from enum import Enum
from typing import Any
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class Weekday(int, Enum):
    """Дни недели (ISO 8601: понедельник = 1)."""
    
    MONDAY = 1
    TUESDAY = 2
    WEDNESDAY = 3
    THURSDAY = 4
    FRIDAY = 5
    SATURDAY = 6
    SUNDAY = 7
    
    @classmethod
    def from_date(cls, d: date) -> "Weekday":
        """Получение дня недели из даты."""
        return cls(d.isoweekday())
    
    @classmethod
    def today(cls, tz: ZoneInfo | None = None) -> "Weekday":
        """Текущий день недели."""
        now = datetime.now(tz) if tz else datetime.now()
        return cls.from_date(now.date())


class ScheduleAction(str, Enum):
    """Действие расписания."""
    
    ALLOW = "allow"      # Разрешить доступ
    BLOCK = "block"      # Заблокировать доступ
    KIDS = "kids"        # Применить детский профиль
    CUSTOM = "custom"    # Применить кастомный профиль


class ScheduleType(str, Enum):
    """Тип расписания."""
    
    DAILY = "daily"          # Ежедневное
    WEEKLY = "weekly"        # Еженедельное
    RECURRING = "recurring"  # Повторяющееся
    ONE_TIME = "one_time"    # Одноразовое


# ════════════════════════════════════════════════════════════════════════════════
# TIME SLOT
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TimeSlot:
    """Временной слот."""
    
    start: time
    end: time
    
    def __post_init__(self):
        # Валидация
        if self.start >= self.end:
            # Слот через полночь не поддерживается в одном TimeSlot
            # Нужно создавать два слота: до полуночи и после
            pass
    
    def contains(self, t: time) -> bool:
        """Проверка, входит ли время в слот."""
        if self.start <= self.end:
            # Обычный слот в пределах одного дня
            return self.start <= t < self.end
        else:
            # Слот через полночь (например 22:00 - 06:00)
            return t >= self.start or t < self.end
    
    def duration_minutes(self) -> int:
        """Длительность слота в минутах."""
        start_minutes = self.start.hour * 60 + self.start.minute
        end_minutes = self.end.hour * 60 + self.end.minute
        
        if end_minutes > start_minutes:
            return end_minutes - start_minutes
        else:
            # Через полночь
            return (24 * 60 - start_minutes) + end_minutes
    
    def to_dict(self) -> dict[str, str]:
        """Сериализация."""
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "TimeSlot":
        """Десериализация."""
        return cls(
            start=time.fromisoformat(data["start"]),
            end=time.fromisoformat(data["end"]),
        )
    
    def __str__(self) -> str:
        return f"{self.start.strftime('%H:%M')}-{self.end.strftime('%H:%M')}"


# ════════════════════════════════════════════════════════════════════════════════
# DAY SCHEDULE
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class DaySchedule:
    """Расписание на один день."""
    
    weekday: Weekday
    slots: list[TimeSlot] = field(default_factory=list)
    action: ScheduleAction = ScheduleAction.BLOCK
    profile_id: str | None = None  # Для CUSTOM action
    
    def is_active_at(self, t: time) -> bool:
        """Проверка, активно ли расписание в указанное время."""
        return any(slot.contains(t) for slot in self.slots)
    
    def total_minutes(self) -> int:
        """Общее время в минутах."""
        return sum(slot.duration_minutes() for slot in self.slots)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "weekday": self.weekday.value,
            "slots": [s.to_dict() for s in self.slots],
            "action": self.action.value,
            "profile_id": self.profile_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DaySchedule":
        """Десериализация."""
        return cls(
            weekday=Weekday(data["weekday"]),
            slots=[TimeSlot.from_dict(s) for s in data.get("slots", [])],
            action=ScheduleAction(data.get("action", "block")),
            profile_id=data.get("profile_id"),
        )


# ════════════════════════════════════════════════════════════════════════════════
# SCHEDULE EXCEPTION
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ScheduleException:
    """Исключение из расписания (праздник, особый день)."""
    
    id: str
    name: str
    date: date
    action: ScheduleAction
    profile_id: str | None = None
    
    # Опционально: переопределение слотов на этот день
    override_slots: list[TimeSlot] | None = None
    
    # Если True, расписание полностью отключено в этот день
    disable_schedule: bool = False
    
    def applies_to(self, d: date) -> bool:
        """Применяется ли исключение к указанной дате."""
        return self.date == d
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "id": self.id,
            "name": self.name,
            "date": self.date.isoformat(),
            "action": self.action.value,
            "profile_id": self.profile_id,
            "override_slots": [s.to_dict() for s in self.override_slots] if self.override_slots else None,
            "disable_schedule": self.disable_schedule,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScheduleException":
        """Десериализация."""
        return cls(
            id=data["id"],
            name=data["name"],
            date=date.fromisoformat(data["date"]),
            action=ScheduleAction(data.get("action", "allow")),
            profile_id=data.get("profile_id"),
            override_slots=[TimeSlot.from_dict(s) for s in data["override_slots"]] if data.get("override_slots") else None,
            disable_schedule=data.get("disable_schedule", False),
        )


# ════════════════════════════════════════════════════════════════════════════════
# SCHEDULE
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Schedule:
    """Полное расписание для устройства или группы."""
    
    id: str
    name: str
    description: str = ""
    
    # Тип расписания
    schedule_type: ScheduleType = ScheduleType.WEEKLY
    
    # Расписание по дням недели
    days: dict[Weekday, DaySchedule] = field(default_factory=dict)
    
    # Исключения (праздники, особые дни)
    exceptions: list[ScheduleException] = field(default_factory=list)
    
    # Таймзона
    timezone: str = "UTC"
    
    # Привязка
    device_ids: list[str] = field(default_factory=list)
    
    # Метаданные
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    @property
    def tz(self) -> ZoneInfo:
        """ZoneInfo для таймзоны."""
        try:
            return ZoneInfo(self.timezone)
        except Exception:
            return ZoneInfo("UTC")
    
    def get_current_state(self) -> tuple[ScheduleAction, str | None]:
        """
        Получение текущего состояния расписания.
        
        Returns:
            (action, profile_id)
        """
        if not self.enabled:
            return ScheduleAction.ALLOW, None
        
        now = datetime.now(self.tz)
        today = now.date()
        current_time = now.time()
        
        # Проверяем исключения
        for exc in self.exceptions:
            if exc.applies_to(today):
                if exc.disable_schedule:
                    return ScheduleAction.ALLOW, None
                
                if exc.override_slots:
                    # Проверяем кастомные слоты исключения
                    if any(slot.contains(current_time) for slot in exc.override_slots):
                        return exc.action, exc.profile_id
                    return ScheduleAction.ALLOW, None
                
                return exc.action, exc.profile_id
        
        # Проверяем обычное расписание
        weekday = Weekday.from_date(today)
        
        if weekday in self.days:
            day_schedule = self.days[weekday]
            if day_schedule.is_active_at(current_time):
                return day_schedule.action, day_schedule.profile_id
        
        return ScheduleAction.ALLOW, None
    
    def is_blocked_now(self) -> bool:
        """Заблокирован ли доступ сейчас."""
        action, _ = self.get_current_state()
        return action == ScheduleAction.BLOCK
    
    def get_next_change(self) -> datetime | None:
        """
        Время следующего изменения состояния.
        
        Полезно для UI — показать "заблокировано до XX:XX".
        """
        if not self.enabled:
            return None
        
        now = datetime.now(self.tz)
        today = now.date()
        current_time = now.time()
        weekday = Weekday.from_date(today)
        
        # Ищем в текущем дне
        if weekday in self.days:
            day_schedule = self.days[weekday]
            for slot in sorted(day_schedule.slots, key=lambda s: s.start):
                if current_time < slot.start:
                    # Следующее начало слота
                    return datetime.combine(today, slot.start, tzinfo=self.tz)
                elif slot.contains(current_time):
                    # Текущий слот — возвращаем его конец
                    return datetime.combine(today, slot.end, tzinfo=self.tz)
        
        # Ищем в следующих днях (до 7 дней вперёд)
        for days_ahead in range(1, 8):
            future_date = today + timedelta(days=days_ahead)
            future_weekday = Weekday.from_date(future_date)
            
            if future_weekday in self.days:
                day_schedule = self.days[future_weekday]
                if day_schedule.slots:
                    first_slot = min(day_schedule.slots, key=lambda s: s.start)
                    return datetime.combine(future_date, first_slot.start, tzinfo=self.tz)
        
        return None
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "schedule_type": self.schedule_type.value,
            "days": {str(k.value): v.to_dict() for k, v in self.days.items()},
            "exceptions": [e.to_dict() for e in self.exceptions],
            "timezone": self.timezone,
            "device_ids": self.device_ids,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Schedule":
        """Десериализация."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            schedule_type=ScheduleType(data.get("schedule_type", "weekly")),
            days={
                Weekday(int(k)): DaySchedule.from_dict(v)
                for k, v in data.get("days", {}).items()
            },
            exceptions=[ScheduleException.from_dict(e) for e in data.get("exceptions", [])],
            timezone=data.get("timezone", "UTC"),
            device_ids=data.get("device_ids", []),
            enabled=data.get("enabled", True),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now(),
        )


# ════════════════════════════════════════════════════════════════════════════════
# PRESET SCHEDULES
# ════════════════════════════════════════════════════════════════════════════════

def create_school_hours_schedule(schedule_id: str = "sched_school") -> Schedule:
    """
    Расписание 'Школьные часы'.
    
    Блокировка развлекательного контента в школьное время.
    Пн-Пт: 08:00-15:00
    """
    days = {}
    
    for weekday in [Weekday.MONDAY, Weekday.TUESDAY, Weekday.WEDNESDAY,
                    Weekday.THURSDAY, Weekday.FRIDAY]:
        days[weekday] = DaySchedule(
            weekday=weekday,
            slots=[TimeSlot(time(8, 0), time(15, 0))],
            action=ScheduleAction.KIDS,
        )
    
    return Schedule(
        id=schedule_id,
        name="School Hours",
        description="Детский режим в школьные часы (Пн-Пт 08:00-15:00)",
        days=days,
    )


def create_bedtime_schedule(schedule_id: str = "sched_bedtime") -> Schedule:
    """
    Расписание 'Время сна'.
    
    Блокировка доступа в ночное время.
    Ежедневно: 22:00-07:00
    """
    days = {}
    
    for weekday in Weekday:
        days[weekday] = DaySchedule(
            weekday=weekday,
            slots=[
                TimeSlot(time(22, 0), time(23, 59)),
                TimeSlot(time(0, 0), time(7, 0)),
            ],
            action=ScheduleAction.BLOCK,
        )
    
    return Schedule(
        id=schedule_id,
        name="Bedtime",
        description="Блокировка интернета в ночное время (22:00-07:00)",
        days=days,
    )


def create_homework_schedule(schedule_id: str = "sched_homework") -> Schedule:
    """
    Расписание 'Время уроков'.
    
    Блокировка развлекательного контента в вечернее время.
    Пн-Чт: 16:00-19:00
    """
    days = {}
    
    for weekday in [Weekday.MONDAY, Weekday.TUESDAY, Weekday.WEDNESDAY, Weekday.THURSDAY]:
        days[weekday] = DaySchedule(
            weekday=weekday,
            slots=[TimeSlot(time(16, 0), time(19, 0))],
            action=ScheduleAction.KIDS,
        )
    
    return Schedule(
        id=schedule_id,
        name="Homework Time",
        description="Детский режим во время выполнения домашних заданий (Пн-Чт 16:00-19:00)",
        days=days,
    )


def create_work_hours_schedule(schedule_id: str = "sched_work") -> Schedule:
    """
    Расписание 'Рабочие часы'.
    
    Полный доступ в рабочее время.
    Пн-Пт: 09:00-18:00
    """
    days = {}
    
    for weekday in [Weekday.MONDAY, Weekday.TUESDAY, Weekday.WEDNESDAY,
                    Weekday.THURSDAY, Weekday.FRIDAY]:
        days[weekday] = DaySchedule(
            weekday=weekday,
            slots=[TimeSlot(time(9, 0), time(18, 0))],
            action=ScheduleAction.ALLOW,
        )
    
    return Schedule(
        id=schedule_id,
        name="Work Hours",
        description="Полный доступ в рабочее время (Пн-Пт 09:00-18:00)",
        days=days,
    )


# ════════════════════════════════════════════════════════════════════════════════
# SCHEDULE MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class ScheduleManager:
    """
    Менеджер расписаний.
    
    Управляет:
    - Созданием и редактированием расписаний
    - Привязкой расписаний к устройствам
    - Проверкой текущего состояния
    """
    
    def __init__(self, default_timezone: str = "UTC"):
        self._schedules: dict[str, Schedule] = {}
        self._device_schedules: dict[str, list[str]] = {}  # device_id -> [schedule_ids]
        self._default_timezone = default_timezone
        
        # Загружаем preset расписания
        self._load_presets()
        
        logger.info("ScheduleManager initialized")
    
    def _load_presets(self) -> None:
        """Загрузка preset расписаний."""
        presets = [
            create_school_hours_schedule(),
            create_bedtime_schedule(),
            create_homework_schedule(),
            create_work_hours_schedule(),
        ]
        
        for schedule in presets:
            self._schedules[schedule.id] = schedule
    
    # ─────────────────────────────────────────────────────────────────────────
    # Schedule CRUD
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_schedule(self, schedule_id: str) -> Schedule | None:
        """Получение расписания по ID."""
        return self._schedules.get(schedule_id)
    
    def get_all_schedules(self) -> list[Schedule]:
        """Список всех расписаний."""
        return list(self._schedules.values())
    
    def get_preset_schedules(self) -> list[Schedule]:
        """Список preset расписаний."""
        return [s for s in self._schedules.values() if s.id.startswith("sched_")]
    
    def add_schedule(self, schedule: Schedule) -> None:
        """Добавление расписания."""
        if schedule.id in self._schedules:
            raise ValueError(f"Schedule {schedule.id} already exists")
        
        schedule.timezone = schedule.timezone or self._default_timezone
        self._schedules[schedule.id] = schedule
        
        # Обновляем привязки устройств
        for device_id in schedule.device_ids:
            if device_id not in self._device_schedules:
                self._device_schedules[device_id] = []
            if schedule.id not in self._device_schedules[device_id]:
                self._device_schedules[device_id].append(schedule.id)
        
        logger.info("Added schedule: %s", schedule.id)
    
    def update_schedule(self, schedule: Schedule) -> None:
        """Обновление расписания."""
        if schedule.id not in self._schedules:
            raise ValueError(f"Schedule {schedule.id} not found")
        
        old_schedule = self._schedules[schedule.id]
        
        # Обновляем привязки устройств
        for device_id in old_schedule.device_ids:
            if device_id in self._device_schedules:
                self._device_schedules[device_id] = [
                    sid for sid in self._device_schedules[device_id]
                    if sid != schedule.id
                ]
        
        for device_id in schedule.device_ids:
            if device_id not in self._device_schedules:
                self._device_schedules[device_id] = []
            if schedule.id not in self._device_schedules[device_id]:
                self._device_schedules[device_id].append(schedule.id)
        
        schedule.updated_at = datetime.now()
        self._schedules[schedule.id] = schedule
        logger.info("Updated schedule: %s", schedule.id)
    
    def delete_schedule(self, schedule_id: str) -> None:
        """Удаление расписания."""
        if schedule_id not in self._schedules:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        schedule = self._schedules[schedule_id]
        
        # Удаляем привязки
        for device_id in schedule.device_ids:
            if device_id in self._device_schedules:
                self._device_schedules[device_id] = [
                    sid for sid in self._device_schedules[device_id]
                    if sid != schedule_id
                ]
        
        del self._schedules[schedule_id]
        logger.info("Deleted schedule: %s", schedule_id)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Device Bindings
    # ─────────────────────────────────────────────────────────────────────────
    
    def assign_schedule(self, device_id: str, schedule_id: str) -> None:
        """Привязка расписания к устройству."""
        if schedule_id not in self._schedules:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        schedule = self._schedules[schedule_id]
        
        if device_id not in schedule.device_ids:
            schedule.device_ids.append(device_id)
        
        if device_id not in self._device_schedules:
            self._device_schedules[device_id] = []
        if schedule_id not in self._device_schedules[device_id]:
            self._device_schedules[device_id].append(schedule_id)
        
        logger.debug("Assigned schedule %s to device %s", schedule_id, device_id)
    
    def unassign_schedule(self, device_id: str, schedule_id: str) -> None:
        """Отвязка расписания от устройства."""
        if schedule_id in self._schedules:
            schedule = self._schedules[schedule_id]
            schedule.device_ids = [d for d in schedule.device_ids if d != device_id]
        
        if device_id in self._device_schedules:
            self._device_schedules[device_id] = [
                sid for sid in self._device_schedules[device_id]
                if sid != schedule_id
            ]
    
    def get_device_schedules(self, device_id: str) -> list[Schedule]:
        """Получение расписаний устройства."""
        schedule_ids = self._device_schedules.get(device_id, [])
        return [self._schedules[sid] for sid in schedule_ids if sid in self._schedules]
    
    # ─────────────────────────────────────────────────────────────────────────
    # State Evaluation
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_device_state(self, device_id: str) -> tuple[ScheduleAction, str | None]:
        """
        Получение текущего состояния для устройства.
        
        Если несколько расписаний, приоритет:
        BLOCK > KIDS > CUSTOM > ALLOW
        
        Returns:
            (action, profile_id)
        """
        schedules = self.get_device_schedules(device_id)
        
        if not schedules:
            return ScheduleAction.ALLOW, None
        
        # Собираем состояния всех расписаний
        states: list[tuple[ScheduleAction, str | None]] = []
        
        for schedule in schedules:
            if schedule.enabled:
                state = schedule.get_current_state()
                states.append(state)
        
        if not states:
            return ScheduleAction.ALLOW, None
        
        # Приоритет действий
        priority = {
            ScheduleAction.BLOCK: 3,
            ScheduleAction.KIDS: 2,
            ScheduleAction.CUSTOM: 1,
            ScheduleAction.ALLOW: 0,
        }
        
        # Выбираем действие с наивысшим приоритетом
        best_state = max(states, key=lambda s: priority.get(s[0], 0))
        return best_state
    
    def is_device_blocked(self, device_id: str) -> bool:
        """Заблокировано ли устройство сейчас."""
        action, _ = self.get_device_state(device_id)
        return action == ScheduleAction.BLOCK
    
    def get_device_profile_override(self, device_id: str) -> str | None:
        """
        Получение переопределения профиля для устройства.
        
        Если расписание требует KIDS или CUSTOM, возвращает profile_id.
        """
        action, profile_id = self.get_device_state(device_id)
        
        if action == ScheduleAction.KIDS:
            return "shield_kids"  # Встроенный детский профиль
        elif action == ScheduleAction.CUSTOM and profile_id:
            return profile_id
        
        return None
    
    # ─────────────────────────────────────────────────────────────────────────
    # Exceptions
    # ─────────────────────────────────────────────────────────────────────────
    
    def add_exception(
        self,
        schedule_id: str,
        exception: ScheduleException,
    ) -> None:
        """Добавление исключения в расписание."""
        if schedule_id not in self._schedules:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        schedule = self._schedules[schedule_id]
        
        # Удаляем существующее исключение на ту же дату
        schedule.exceptions = [
            e for e in schedule.exceptions
            if e.date != exception.date
        ]
        
        schedule.exceptions.append(exception)
        schedule.updated_at = datetime.now()
    
    def remove_exception(self, schedule_id: str, exception_id: str) -> None:
        """Удаление исключения из расписания."""
        if schedule_id not in self._schedules:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        schedule = self._schedules[schedule_id]
        schedule.exceptions = [
            e for e in schedule.exceptions
            if e.id != exception_id
        ]
        schedule.updated_at = datetime.now()


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def create_simple_schedule(
    schedule_id: str,
    name: str,
    weekdays: list[Weekday],
    start_time: time,
    end_time: time,
    action: ScheduleAction = ScheduleAction.BLOCK,
    timezone: str = "UTC",
) -> Schedule:
    """
    Создание простого расписания.
    
    Одинаковые слоты для указанных дней недели.
    """
    days = {}
    
    for weekday in weekdays:
        days[weekday] = DaySchedule(
            weekday=weekday,
            slots=[TimeSlot(start_time, end_time)],
            action=action,
        )
    
    return Schedule(
        id=schedule_id,
        name=name,
        days=days,
        timezone=timezone,
    )


def is_time_in_range(
    current: time,
    start: time,
    end: time,
) -> bool:
    """Проверка, находится ли время в диапазоне."""
    slot = TimeSlot(start, end)
    return slot.contains(current)


def get_preset_schedules() -> list[Schedule]:
    """Список preset расписаний."""
    return [
        create_school_hours_schedule(),
        create_bedtime_schedule(),
        create_homework_schedule(),
        create_work_hours_schedule(),
    ]
