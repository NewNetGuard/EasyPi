"""
EasyPi NetProtection — Shield Profiles Module.

Предустановленные профили защиты с настраиваемыми политиками.
Каждый профиль определяет набор категорий для блокировки и дополнительные опции.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# PROFILE TYPES
# ════════════════════════════════════════════════════════════════════════════════

class ShieldProfileType(str, Enum):
    """Типы Shield-профилей."""
    
    STRICT = "strict"
    BALANCED = "balanced"
    KIDS = "kids"
    MINIMAL = "minimal"
    CUSTOM = "custom"


# Alias for backward compatibility
ProfileType = ShieldProfileType


class BlockCategory(str, Enum):
    """Категории для блокировки."""
    
    # Реклама и трекинг
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    ANALYTICS = "analytics"
    
    # Безопасность
    MALWARE = "malware"
    PHISHING = "phishing"
    CRYPTOMINING = "cryptomining"
    BOTNET = "botnet"
    
    # Контент
    ADULT = "adult"
    GAMBLING = "gambling"
    DATING = "dating"
    DRUGS = "drugs"
    WEAPONS = "weapons"
    VIOLENCE = "violence"
    
    # Социальные сети и развлечения
    SOCIAL_MEDIA = "social_media"
    GAMING = "gaming"
    STREAMING = "streaming"
    
    # Телеметрия
    TELEMETRY = "telemetry"
    TELEMETRY_WINDOWS = "telemetry_windows"
    TELEMETRY_APPLE = "telemetry_apple"
    TELEMETRY_GOOGLE = "telemetry_google"
    
    # Прочее
    PIRACY = "piracy"
    VPN_PROXY = "vpn_proxy"
    FAKE_NEWS = "fake_news"


class SafeSearchMode(str, Enum):
    """Режимы SafeSearch."""
    
    OFF = "off"
    MODERATE = "moderate"
    STRICT = "strict"


# ════════════════════════════════════════════════════════════════════════════════
# PROFILE SETTINGS
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ProfileSettings:
    """Настройки Shield-профиля."""
    
    # Категории для блокировки
    blocked_categories: set[BlockCategory] = field(default_factory=set)
    
    # SafeSearch
    safe_search: SafeSearchMode = SafeSearchMode.OFF
    
    # CNAME Uncloaking
    cname_uncloaking: bool = True
    
    # DNS Tunneling Detection
    block_dns_tunneling: bool = True
    
    # DGA Detection
    block_dga_domains: bool = True
    
    # Новые домены (зарегистрированы < 30 дней)
    block_newly_registered: bool = False
    newly_registered_days: int = 30
    
    # Парковка доменов
    block_parked_domains: bool = False
    
    # Минимальный confidence для блокировки
    min_block_confidence: int = 70
    
    # Логирование
    log_allowed: bool = False
    log_blocked: bool = True
    
    # Кастомные allow/deny списки (IDs из repository)
    custom_allow_lists: list[str] = field(default_factory=list)
    custom_deny_lists: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "blocked_categories": [c.value for c in self.blocked_categories],
            "safe_search": self.safe_search.value,
            "cname_uncloaking": self.cname_uncloaking,
            "block_dns_tunneling": self.block_dns_tunneling,
            "block_dga_domains": self.block_dga_domains,
            "block_newly_registered": self.block_newly_registered,
            "newly_registered_days": self.newly_registered_days,
            "block_parked_domains": self.block_parked_domains,
            "min_block_confidence": self.min_block_confidence,
            "log_allowed": self.log_allowed,
            "log_blocked": self.log_blocked,
            "custom_allow_lists": self.custom_allow_lists,
            "custom_deny_lists": self.custom_deny_lists,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProfileSettings":
        """Десериализация из словаря."""
        return cls(
            blocked_categories={
                BlockCategory(c) for c in data.get("blocked_categories", [])
            },
            safe_search=SafeSearchMode(data.get("safe_search", "off")),
            cname_uncloaking=data.get("cname_uncloaking", True),
            block_dns_tunneling=data.get("block_dns_tunneling", True),
            block_dga_domains=data.get("block_dga_domains", True),
            block_newly_registered=data.get("block_newly_registered", False),
            newly_registered_days=data.get("newly_registered_days", 30),
            block_parked_domains=data.get("block_parked_domains", False),
            min_block_confidence=data.get("min_block_confidence", 70),
            log_allowed=data.get("log_allowed", False),
            log_blocked=data.get("log_blocked", True),
            custom_allow_lists=data.get("custom_allow_lists", []),
            custom_deny_lists=data.get("custom_deny_lists", []),
        )


# ════════════════════════════════════════════════════════════════════════════════
# SHIELD PROFILE
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ShieldProfile:
    """Shield-профиль защиты."""
    
    id: str
    name: str
    profile_type: ShieldProfileType
    description: str
    settings: ProfileSettings
    
    # Метаданные
    icon: str = "shield"
    color: str = "#3B82F6"
    is_builtin: bool = False
    is_default: bool = False
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "id": self.id,
            "name": self.name,
            "profile_type": self.profile_type.value,
            "description": self.description,
            "settings": self.settings.to_dict(),
            "icon": self.icon,
            "color": self.color,
            "is_builtin": self.is_builtin,
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShieldProfile":
        """Десериализация из словаря."""
        return cls(
            id=data["id"],
            name=data["name"],
            profile_type=ShieldProfileType(data["profile_type"]),
            description=data.get("description", ""),
            settings=ProfileSettings.from_dict(data.get("settings", {})),
            icon=data.get("icon", "shield"),
            color=data.get("color", "#3B82F6"),
            is_builtin=data.get("is_builtin", False),
            is_default=data.get("is_default", False),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now(),
        )


# ════════════════════════════════════════════════════════════════════════════════
# BUILTIN PROFILES
# ════════════════════════════════════════════════════════════════════════════════

def create_strict_profile() -> ShieldProfile:
    """
    Профиль STRICT — максимальная защита.
    
    Блокирует: рекламу, трекеры, телеметрию, malware, adult и многое другое.
    """
    return ShieldProfile(
        id="shield_strict",
        name="Strict",
        profile_type=ShieldProfileType.STRICT,
        description="Максимальная защита. Блокирует рекламу, трекеры, телеметрию и потенциально опасные домены.",
        icon="shield-check",
        color="#EF4444",  # Red
        is_builtin=True,
        settings=ProfileSettings(
            blocked_categories={
                BlockCategory.ADVERTISING,
                BlockCategory.TRACKING,
                BlockCategory.ANALYTICS,
                BlockCategory.MALWARE,
                BlockCategory.PHISHING,
                BlockCategory.CRYPTOMINING,
                BlockCategory.BOTNET,
                BlockCategory.TELEMETRY,
                BlockCategory.TELEMETRY_WINDOWS,
                BlockCategory.TELEMETRY_APPLE,
                BlockCategory.TELEMETRY_GOOGLE,
            },
            safe_search=SafeSearchMode.MODERATE,
            cname_uncloaking=True,
            block_dns_tunneling=True,
            block_dga_domains=True,
            block_newly_registered=True,
            newly_registered_days=7,
            block_parked_domains=True,
            min_block_confidence=60,
            log_allowed=False,
            log_blocked=True,
        ),
    )


def create_balanced_profile() -> ShieldProfile:
    """
    Профиль BALANCED — стандартный режим.
    
    Блокирует: рекламу, известные трекеры, malware.
    Разрешает: телеметрию ОС, аналитику.
    """
    return ShieldProfile(
        id="shield_balanced",
        name="Balanced",
        profile_type=ShieldProfileType.BALANCED,
        description="Стандартный режим. Блокирует рекламу и известные трекеры. Разрешает телеметрию ОС.",
        icon="shield",
        color="#3B82F6",  # Blue
        is_builtin=True,
        is_default=True,
        settings=ProfileSettings(
            blocked_categories={
                BlockCategory.ADVERTISING,
                BlockCategory.TRACKING,
                BlockCategory.MALWARE,
                BlockCategory.PHISHING,
                BlockCategory.CRYPTOMINING,
                BlockCategory.BOTNET,
            },
            safe_search=SafeSearchMode.OFF,
            cname_uncloaking=True,
            block_dns_tunneling=True,
            block_dga_domains=True,
            block_newly_registered=False,
            block_parked_domains=False,
            min_block_confidence=70,
            log_allowed=False,
            log_blocked=True,
        ),
    )


def create_kids_profile() -> ShieldProfile:
    """
    Профиль KIDS — детский режим.
    
    Включает: SafeSearch принудительно, блокировку adult-контента.
    Ограничивает: социальные сети, игровые платформы.
    """
    return ShieldProfile(
        id="shield_kids",
        name="Kids",
        profile_type=ShieldProfileType.KIDS,
        description="Детский режим. Принудительный SafeSearch, блокировка adult-контента, ограничение соцсетей.",
        icon="child",
        color="#8B5CF6",  # Purple
        is_builtin=True,
        settings=ProfileSettings(
            blocked_categories={
                BlockCategory.ADVERTISING,
                BlockCategory.TRACKING,
                BlockCategory.MALWARE,
                BlockCategory.PHISHING,
                BlockCategory.CRYPTOMINING,
                BlockCategory.BOTNET,
                BlockCategory.ADULT,
                BlockCategory.GAMBLING,
                BlockCategory.DATING,
                BlockCategory.DRUGS,
                BlockCategory.WEAPONS,
                BlockCategory.VIOLENCE,
                BlockCategory.SOCIAL_MEDIA,
                BlockCategory.GAMING,
            },
            safe_search=SafeSearchMode.STRICT,
            cname_uncloaking=True,
            block_dns_tunneling=True,
            block_dga_domains=True,
            block_newly_registered=True,
            newly_registered_days=14,
            block_parked_domains=True,
            min_block_confidence=50,
            log_allowed=True,
            log_blocked=True,
        ),
    )


def create_minimal_profile() -> ShieldProfile:
    """
    Профиль MINIMAL — минимальная фильтрация.
    
    Блокирует только: malware, фишинг, ботнеты.
    Реклама и трекеры разрешены.
    """
    return ShieldProfile(
        id="shield_minimal",
        name="Minimal",
        profile_type=ShieldProfileType.MINIMAL,
        description="Минимальная фильтрация. Только malware и фишинг. Реклама и трекеры разрешены.",
        icon="shield-off",
        color="#6B7280",  # Gray
        is_builtin=True,
        settings=ProfileSettings(
            blocked_categories={
                BlockCategory.MALWARE,
                BlockCategory.PHISHING,
                BlockCategory.BOTNET,
            },
            safe_search=SafeSearchMode.OFF,
            cname_uncloaking=False,
            block_dns_tunneling=True,
            block_dga_domains=True,
            block_newly_registered=False,
            block_parked_domains=False,
            min_block_confidence=80,
            log_allowed=False,
            log_blocked=True,
        ),
    )


def create_custom_profile(
    profile_id: str,
    name: str,
    description: str = "",
    settings: ProfileSettings | None = None,
) -> ShieldProfile:
    """Создание кастомного профиля."""
    return ShieldProfile(
        id=profile_id,
        name=name,
        profile_type=ShieldProfileType.CUSTOM,
        description=description or f"Custom profile: {name}",
        icon="settings",
        color="#10B981",  # Green
        is_builtin=False,
        settings=settings or ProfileSettings(),
    )


# ════════════════════════════════════════════════════════════════════════════════
# PROFILE MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class ProfileManager:
    """
    Менеджер Shield-профилей.
    
    Управляет:
    - Встроенными профилями
    - Кастомными профилями
    - Назначением профилей устройствам
    """
    
    def __init__(self):
        self._profiles: dict[str, ShieldProfile] = {}
        self._device_assignments: dict[str, str] = {}  # device_id -> profile_id
        self._default_profile_id: str = "shield_balanced"
        
        # Загружаем встроенные профили
        self._load_builtin_profiles()
        
        logger.info(
            "ProfileManager initialized with %d builtin profiles",
            len(self._profiles)
        )
    
    def _load_builtin_profiles(self) -> None:
        """Загрузка встроенных профилей."""
        builtin = [
            create_strict_profile(),
            create_balanced_profile(),
            create_kids_profile(),
            create_minimal_profile(),
        ]
        
        for profile in builtin:
            self._profiles[profile.id] = profile
            if profile.is_default:
                self._default_profile_id = profile.id
    
    # ─────────────────────────────────────────────────────────────────────────
    # Profile CRUD
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_profile(self, profile_id: str) -> ShieldProfile | None:
        """Получение профиля по ID."""
        return self._profiles.get(profile_id)
    
    def get_all_profiles(self) -> list[ShieldProfile]:
        """Список всех профилей."""
        return list(self._profiles.values())
    
    def get_builtin_profiles(self) -> list[ShieldProfile]:
        """Список встроенных профилей."""
        return [p for p in self._profiles.values() if p.is_builtin]
    
    def get_custom_profiles(self) -> list[ShieldProfile]:
        """Список кастомных профилей."""
        return [p for p in self._profiles.values() if not p.is_builtin]
    
    def get_default_profile(self) -> ShieldProfile:
        """Профиль по умолчанию."""
        return self._profiles[self._default_profile_id]
    
    def add_profile(self, profile: ShieldProfile) -> None:
        """Добавление профиля."""
        if profile.id in self._profiles:
            raise ValueError(f"Profile {profile.id} already exists")
        
        self._profiles[profile.id] = profile
        logger.info("Added profile: %s", profile.id)
    
    def update_profile(self, profile: ShieldProfile) -> None:
        """Обновление профиля."""
        if profile.id not in self._profiles:
            raise ValueError(f"Profile {profile.id} not found")
        
        existing = self._profiles[profile.id]
        if existing.is_builtin:
            raise ValueError("Cannot modify builtin profiles")
        
        profile.updated_at = datetime.now()
        self._profiles[profile.id] = profile
        logger.info("Updated profile: %s", profile.id)
    
    def delete_profile(self, profile_id: str) -> None:
        """Удаление профиля."""
        if profile_id not in self._profiles:
            raise ValueError(f"Profile {profile_id} not found")
        
        profile = self._profiles[profile_id]
        if profile.is_builtin:
            raise ValueError("Cannot delete builtin profiles")
        
        # Переназначаем устройства на default
        for device_id, assigned_id in list(self._device_assignments.items()):
            if assigned_id == profile_id:
                self._device_assignments[device_id] = self._default_profile_id
        
        del self._profiles[profile_id]
        logger.info("Deleted profile: %s", profile_id)
    
    def set_default_profile(self, profile_id: str) -> None:
        """Установка профиля по умолчанию."""
        if profile_id not in self._profiles:
            raise ValueError(f"Profile {profile_id} not found")
        
        # Сбрасываем старый default
        for profile in self._profiles.values():
            profile.is_default = False
        
        self._profiles[profile_id].is_default = True
        self._default_profile_id = profile_id
        logger.info("Set default profile: %s", profile_id)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Device Assignments
    # ─────────────────────────────────────────────────────────────────────────
    
    def assign_profile(self, device_id: str, profile_id: str) -> None:
        """Назначение профиля устройству."""
        if profile_id not in self._profiles:
            raise ValueError(f"Profile {profile_id} not found")
        
        self._device_assignments[device_id] = profile_id
        logger.debug("Assigned profile %s to device %s", profile_id, device_id)
    
    def get_device_profile(self, device_id: str) -> ShieldProfile:
        """Получение профиля для устройства."""
        profile_id = self._device_assignments.get(device_id, self._default_profile_id)
        return self._profiles[profile_id]
    
    def remove_device_assignment(self, device_id: str) -> None:
        """Удаление назначения профиля устройству."""
        if device_id in self._device_assignments:
            del self._device_assignments[device_id]
            logger.debug("Removed profile assignment for device %s", device_id)
    
    def get_devices_by_profile(self, profile_id: str) -> list[str]:
        """Список устройств с данным профилем."""
        return [
            device_id
            for device_id, assigned_id in self._device_assignments.items()
            if assigned_id == profile_id
        ]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Policy Evaluation
    # ─────────────────────────────────────────────────────────────────────────
    
    def should_block_category(
        self,
        device_id: str,
        category: BlockCategory,
    ) -> bool:
        """Проверка, должна ли категория быть заблокирована для устройства."""
        profile = self.get_device_profile(device_id)
        return category in profile.settings.blocked_categories
    
    def get_safe_search_mode(self, device_id: str) -> SafeSearchMode:
        """Получение режима SafeSearch для устройства."""
        profile = self.get_device_profile(device_id)
        return profile.settings.safe_search
    
    def get_min_confidence(self, device_id: str) -> int:
        """Минимальный confidence для блокировки."""
        profile = self.get_device_profile(device_id)
        return profile.settings.min_block_confidence
    
    def should_log_allowed(self, device_id: str) -> bool:
        """Нужно ли логировать разрешённые запросы."""
        profile = self.get_device_profile(device_id)
        return profile.settings.log_allowed
    
    def should_log_blocked(self, device_id: str) -> bool:
        """Нужно ли логировать заблокированные запросы."""
        profile = self.get_device_profile(device_id)
        return profile.settings.log_blocked


# ════════════════════════════════════════════════════════════════════════════════
# SAFESEARCH ENFORCER
# ════════════════════════════════════════════════════════════════════════════════

class SafeSearchEnforcer:
    """
    Принудительное применение SafeSearch.
    
    Перенаправляет поисковые запросы на SafeSearch-версии.
    """
    
    # Маппинг доменов поисковиков на SafeSearch версии
    SAFESEARCH_CNAMES: dict[str, dict[str, str]] = {
        # Google
        "www.google.com": {
            "moderate": "forcesafesearch.google.com",
            "strict": "forcesafesearch.google.com",
        },
        "google.com": {
            "moderate": "forcesafesearch.google.com",
            "strict": "forcesafesearch.google.com",
        },
        # Bing
        "www.bing.com": {
            "moderate": "strict.bing.com",
            "strict": "strict.bing.com",
        },
        "bing.com": {
            "moderate": "strict.bing.com",
            "strict": "strict.bing.com",
        },
        # DuckDuckGo
        "duckduckgo.com": {
            "moderate": "safe.duckduckgo.com",
            "strict": "safe.duckduckgo.com",
        },
        # YouTube
        "www.youtube.com": {
            "moderate": "restrictmoderate.youtube.com",
            "strict": "restrict.youtube.com",
        },
        "youtube.com": {
            "moderate": "restrictmoderate.youtube.com",
            "strict": "restrict.youtube.com",
        },
        "m.youtube.com": {
            "moderate": "restrictmoderate.youtube.com",
            "strict": "restrict.youtube.com",
        },
    }
    
    @classmethod
    def get_safesearch_cname(
        cls,
        domain: str,
        mode: SafeSearchMode,
    ) -> str | None:
        """
        Получение SafeSearch CNAME для домена.
        
        Returns:
            CNAME для перенаправления или None если SafeSearch не применим
        """
        if mode == SafeSearchMode.OFF:
            return None
        
        domain = domain.lower().strip('.')
        
        if domain in cls.SAFESEARCH_CNAMES:
            return cls.SAFESEARCH_CNAMES[domain].get(mode.value)
        
        return None
    
    @classmethod
    def is_search_engine(cls, domain: str) -> bool:
        """Проверка, является ли домен поисковиком."""
        domain = domain.lower().strip('.')
        return domain in cls.SAFESEARCH_CNAMES


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def get_builtin_profiles() -> list[ShieldProfile]:
    """Список встроенных профилей."""
    return [
        create_strict_profile(),
        create_balanced_profile(),
        create_kids_profile(),
        create_minimal_profile(),
    ]


def get_profile_by_type(profile_type: ShieldProfileType) -> ShieldProfile:
    """Получение встроенного профиля по типу."""
    creators = {
        ShieldProfileType.STRICT: create_strict_profile,
        ShieldProfileType.BALANCED: create_balanced_profile,
        ShieldProfileType.KIDS: create_kids_profile,
        ShieldProfileType.MINIMAL: create_minimal_profile,
    }
    
    if profile_type not in creators:
        raise ValueError(f"Unknown profile type: {profile_type}")
    
    return creators[profile_type]()
