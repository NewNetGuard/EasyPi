"""
EasyPi NetProtection — Device Management Module.

Управление устройствами в сети с автоопределением типа.
Device fingerprinting через MAC OUI, hostname и traffic patterns.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# DEVICE TYPES
# ════════════════════════════════════════════════════════════════════════════════

class DeviceType(str, Enum):
    """Типы устройств."""
    
    PC = "pc"
    LAPTOP = "laptop"
    PHONE = "phone"
    TABLET = "tablet"
    TV = "tv"
    IOT = "iot"
    GAMING = "gaming"
    ROUTER = "router"
    PRINTER = "printer"
    CAMERA = "camera"
    SPEAKER = "speaker"
    WEARABLE = "wearable"
    UNKNOWN = "unknown"


class DeviceOS(str, Enum):
    """Операционные системы устройств."""
    
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    IOS = "ios"
    ANDROID = "android"
    TVOS = "tvos"
    ROKU = "roku"
    TIZEN = "tizen"  # Samsung TV
    WEBOS = "webos"  # LG TV
    CHROMEOS = "chromeos"
    FREEBSD = "freebsd"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    """Статус устройства."""
    
    ONLINE = "online"
    OFFLINE = "offline"
    IDLE = "idle"  # Нет активности > 1 час


# ════════════════════════════════════════════════════════════════════════════════
# MAC OUI DATABASE
# ════════════════════════════════════════════════════════════════════════════════

# Формат: OUI prefix (первые 3 байта MAC) -> (Vendor, DeviceType hint)
MAC_OUI_DATABASE: dict[str, tuple[str, DeviceType | None]] = {
    # Apple
    "00:03:93": ("Apple", DeviceType.PC),
    "00:0A:95": ("Apple", None),
    "00:0D:93": ("Apple", None),
    "00:1C:B3": ("Apple", None),
    "00:1E:C2": ("Apple", None),
    "00:25:00": ("Apple", None),
    "00:26:BB": ("Apple", None),
    "3C:06:30": ("Apple", DeviceType.PHONE),
    "A4:83:E7": ("Apple", DeviceType.PHONE),
    "AC:BC:32": ("Apple", None),
    "F0:99:BF": ("Apple", DeviceType.PHONE),
    
    # Samsung
    "00:12:47": ("Samsung", None),
    "00:15:B9": ("Samsung", None),
    "00:1A:8A": ("Samsung", None),
    "00:21:4C": ("Samsung", None),
    "00:26:37": ("Samsung", None),
    "5C:0A:5B": ("Samsung", DeviceType.PHONE),
    "8C:71:F8": ("Samsung", DeviceType.TV),
    "AC:5A:14": ("Samsung", DeviceType.TV),
    "BC:14:85": ("Samsung", DeviceType.TV),
    
    # Google/Nest
    "18:D6:C7": ("Google/Nest", DeviceType.IOT),
    "1C:F2:9A": ("Google", DeviceType.IOT),
    "54:60:09": ("Google", DeviceType.IOT),
    "F4:F5:D8": ("Google", DeviceType.SPEAKER),
    
    # Amazon
    "00:FC:8B": ("Amazon", DeviceType.IOT),
    "0C:47:C9": ("Amazon", DeviceType.IOT),
    "18:74:2E": ("Amazon", DeviceType.IOT),
    "34:D2:70": ("Amazon", DeviceType.SPEAKER),
    "44:65:0D": ("Amazon", DeviceType.TV),
    "68:37:E9": ("Amazon", DeviceType.IOT),
    "74:C2:46": ("Amazon", DeviceType.SPEAKER),
    "A0:02:DC": ("Amazon", DeviceType.SPEAKER),
    "FC:65:DE": ("Amazon", DeviceType.TV),
    
    # Microsoft/Xbox
    "00:50:F2": ("Microsoft", DeviceType.PC),
    "28:18:78": ("Microsoft", DeviceType.GAMING),
    "60:45:BD": ("Microsoft", DeviceType.GAMING),
    "7C:ED:8D": ("Microsoft", DeviceType.GAMING),
    "98:5F:D3": ("Microsoft", DeviceType.GAMING),
    
    # Sony/PlayStation
    "00:04:1F": ("Sony", None),
    "00:13:A9": ("Sony", DeviceType.GAMING),
    "00:1D:0D": ("Sony", DeviceType.GAMING),
    "00:24:8D": ("Sony", DeviceType.GAMING),
    "28:0D:FC": ("Sony", DeviceType.GAMING),
    "70:9E:29": ("Sony", DeviceType.GAMING),
    "A8:E3:EE": ("Sony", DeviceType.GAMING),
    "F8:46:1C": ("Sony", DeviceType.GAMING),
    
    # Nintendo
    "00:09:BF": ("Nintendo", DeviceType.GAMING),
    "00:16:56": ("Nintendo", DeviceType.GAMING),
    "00:17:AB": ("Nintendo", DeviceType.GAMING),
    "00:1B:7A": ("Nintendo", DeviceType.GAMING),
    "00:1E:A9": ("Nintendo", DeviceType.GAMING),
    "00:22:4C": ("Nintendo", DeviceType.GAMING),
    "00:22:AA": ("Nintendo", DeviceType.GAMING),
    "00:23:31": ("Nintendo", DeviceType.GAMING),
    "00:24:F3": ("Nintendo", DeviceType.GAMING),
    "00:25:A0": ("Nintendo", DeviceType.GAMING),
    "34:AF:2C": ("Nintendo", DeviceType.GAMING),
    "7C:BB:8A": ("Nintendo", DeviceType.GAMING),
    "98:41:5C": ("Nintendo", DeviceType.GAMING),
    
    # Roku
    "00:0D:4B": ("Roku", DeviceType.TV),
    "B0:A7:37": ("Roku", DeviceType.TV),
    "B8:3E:59": ("Roku", DeviceType.TV),
    "C8:3A:6B": ("Roku", DeviceType.TV),
    "D4:E2:2F": ("Roku", DeviceType.TV),
    "DC:3A:5E": ("Roku", DeviceType.TV),
    
    # LG
    "00:1C:62": ("LG", DeviceType.TV),
    "00:1E:75": ("LG", DeviceType.TV),
    "00:1F:6B": ("LG", DeviceType.TV),
    "00:22:A9": ("LG", None),
    "10:68:3F": ("LG", DeviceType.TV),
    "20:3D:BD": ("LG", DeviceType.TV),
    "34:4D:F7": ("LG", DeviceType.TV),
    "38:8C:50": ("LG", DeviceType.TV),
    "58:A2:B5": ("LG", DeviceType.TV),
    "64:99:5D": ("LG", DeviceType.TV),
    
    # Philips/Hue
    "00:17:88": ("Philips Hue", DeviceType.IOT),
    "EC:B5:FA": ("Philips Hue", DeviceType.IOT),
    
    # Ring
    "24:43:E9": ("Ring", DeviceType.CAMERA),
    "7C:64:56": ("Ring", DeviceType.CAMERA),
    
    # TP-Link
    "14:CC:20": ("TP-Link", DeviceType.IOT),
    "50:C7:BF": ("TP-Link", DeviceType.IOT),
    "60:32:B1": ("TP-Link", DeviceType.IOT),
    "B0:4E:26": ("TP-Link", DeviceType.ROUTER),
    
    # Sonos
    "00:0E:58": ("Sonos", DeviceType.SPEAKER),
    "34:7E:5C": ("Sonos", DeviceType.SPEAKER),
    "48:A6:B8": ("Sonos", DeviceType.SPEAKER),
    "54:2A:1B": ("Sonos", DeviceType.SPEAKER),
    "78:28:CA": ("Sonos", DeviceType.SPEAKER),
    "94:9F:3E": ("Sonos", DeviceType.SPEAKER),
    "B8:E9:37": ("Sonos", DeviceType.SPEAKER),
    
    # HP Printers
    "00:11:0A": ("HP", DeviceType.PRINTER),
    "00:12:79": ("HP", DeviceType.PRINTER),
    "00:14:38": ("HP", DeviceType.PRINTER),
    "00:17:A4": ("HP", DeviceType.PRINTER),
    "00:18:FE": ("HP", DeviceType.PRINTER),
    "00:1B:78": ("HP", DeviceType.PRINTER),
    "00:1E:0B": ("HP", DeviceType.PRINTER),
    "00:21:5A": ("HP", DeviceType.PRINTER),
    "00:23:7D": ("HP", DeviceType.PRINTER),
    "00:25:B3": ("HP", DeviceType.PRINTER),
    
    # Canon Printers
    "00:00:85": ("Canon", DeviceType.PRINTER),
    "00:1E:8F": ("Canon", DeviceType.PRINTER),
    "18:0C:AC": ("Canon", DeviceType.PRINTER),
    "84:26:15": ("Canon", DeviceType.PRINTER),
    
    # Epson Printers
    "00:26:AB": ("Epson", DeviceType.PRINTER),
    "64:EB:8C": ("Epson", DeviceType.PRINTER),
    "D4:81:D7": ("Epson", DeviceType.PRINTER),
    
    # Raspberry Pi
    "B8:27:EB": ("Raspberry Pi", DeviceType.IOT),
    "DC:A6:32": ("Raspberry Pi", DeviceType.IOT),
    "E4:5F:01": ("Raspberry Pi", DeviceType.IOT),
    
    # Intel
    "00:1B:21": ("Intel", DeviceType.PC),
    "00:1E:67": ("Intel", DeviceType.PC),
    "00:22:FA": ("Intel", DeviceType.PC),
    "00:24:D7": ("Intel", DeviceType.PC),
    
    # Dell
    "00:06:5B": ("Dell", DeviceType.PC),
    "00:08:74": ("Dell", DeviceType.PC),
    "00:0B:DB": ("Dell", DeviceType.PC),
    "00:0D:56": ("Dell", DeviceType.PC),
    "00:0F:1F": ("Dell", DeviceType.PC),
    "00:11:43": ("Dell", DeviceType.PC),
    "00:12:3F": ("Dell", DeviceType.PC),
    "00:13:72": ("Dell", DeviceType.PC),
    "00:14:22": ("Dell", DeviceType.PC),
    
    # Lenovo
    "00:09:2D": ("Lenovo", DeviceType.PC),
    "00:0A:E4": ("Lenovo", DeviceType.PC),
    "00:12:FE": ("Lenovo", DeviceType.PC),
    "00:16:D4": ("Lenovo", DeviceType.PC),
    "00:1A:6B": ("Lenovo", DeviceType.PC),
    "00:1E:4F": ("Lenovo", DeviceType.PC),
}


# ════════════════════════════════════════════════════════════════════════════════
# HOSTNAME PATTERNS
# ════════════════════════════════════════════════════════════════════════════════

HOSTNAME_PATTERNS: list[tuple[re.Pattern, DeviceType, DeviceOS | None]] = [
    # Apple devices
    (re.compile(r'iphone', re.I), DeviceType.PHONE, DeviceOS.IOS),
    (re.compile(r'ipad', re.I), DeviceType.TABLET, DeviceOS.IOS),
    (re.compile(r'macbook', re.I), DeviceType.LAPTOP, DeviceOS.MACOS),
    (re.compile(r'imac', re.I), DeviceType.PC, DeviceOS.MACOS),
    (re.compile(r'mac-?mini', re.I), DeviceType.PC, DeviceOS.MACOS),
    (re.compile(r'mac-?pro', re.I), DeviceType.PC, DeviceOS.MACOS),
    (re.compile(r'apple-?tv', re.I), DeviceType.TV, DeviceOS.TVOS),
    (re.compile(r'homepod', re.I), DeviceType.SPEAKER, DeviceOS.IOS),
    (re.compile(r'apple-?watch', re.I), DeviceType.WEARABLE, DeviceOS.IOS),
    
    # Android devices
    (re.compile(r'android', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'galaxy', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'pixel', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'oneplus', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'xiaomi', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'redmi', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'huawei', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'oppo', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'vivo', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    (re.compile(r'realme', re.I), DeviceType.PHONE, DeviceOS.ANDROID),
    
    # Windows
    (re.compile(r'desktop-[a-z0-9]+', re.I), DeviceType.PC, DeviceOS.WINDOWS),
    (re.compile(r'laptop-[a-z0-9]+', re.I), DeviceType.LAPTOP, DeviceOS.WINDOWS),
    (re.compile(r'surface', re.I), DeviceType.LAPTOP, DeviceOS.WINDOWS),
    (re.compile(r'win(dows)?[-_]?(pc|10|11)?', re.I), DeviceType.PC, DeviceOS.WINDOWS),
    
    # Linux
    (re.compile(r'ubuntu', re.I), DeviceType.PC, DeviceOS.LINUX),
    (re.compile(r'fedora', re.I), DeviceType.PC, DeviceOS.LINUX),
    (re.compile(r'debian', re.I), DeviceType.PC, DeviceOS.LINUX),
    (re.compile(r'arch', re.I), DeviceType.PC, DeviceOS.LINUX),
    (re.compile(r'linux', re.I), DeviceType.PC, DeviceOS.LINUX),
    (re.compile(r'raspberrypi', re.I), DeviceType.IOT, DeviceOS.LINUX),
    
    # Smart TVs
    (re.compile(r'smart-?tv', re.I), DeviceType.TV, None),
    (re.compile(r'roku', re.I), DeviceType.TV, DeviceOS.ROKU),
    (re.compile(r'fire-?tv', re.I), DeviceType.TV, DeviceOS.ANDROID),
    (re.compile(r'chromecast', re.I), DeviceType.TV, DeviceOS.ANDROID),
    (re.compile(r'lg-?tv', re.I), DeviceType.TV, DeviceOS.WEBOS),
    (re.compile(r'samsung-?tv', re.I), DeviceType.TV, DeviceOS.TIZEN),
    (re.compile(r'sony-?tv', re.I), DeviceType.TV, DeviceOS.ANDROID),
    (re.compile(r'shield', re.I), DeviceType.TV, DeviceOS.ANDROID),
    
    # Gaming
    (re.compile(r'playstation|ps[345]', re.I), DeviceType.GAMING, None),
    (re.compile(r'xbox', re.I), DeviceType.GAMING, None),
    (re.compile(r'nintendo|switch', re.I), DeviceType.GAMING, None),
    (re.compile(r'steam-?deck', re.I), DeviceType.GAMING, DeviceOS.LINUX),
    
    # IoT
    (re.compile(r'nest', re.I), DeviceType.IOT, None),
    (re.compile(r'ring', re.I), DeviceType.CAMERA, None),
    (re.compile(r'echo|alexa', re.I), DeviceType.SPEAKER, None),
    (re.compile(r'google-?home', re.I), DeviceType.SPEAKER, None),
    (re.compile(r'sonos', re.I), DeviceType.SPEAKER, None),
    (re.compile(r'hue', re.I), DeviceType.IOT, None),
    (re.compile(r'thermostat', re.I), DeviceType.IOT, None),
    (re.compile(r'camera', re.I), DeviceType.CAMERA, None),
    (re.compile(r'doorbell', re.I), DeviceType.IOT, None),
    
    # Printers
    (re.compile(r'printer', re.I), DeviceType.PRINTER, None),
    (re.compile(r'hp-?(laser|officejet|deskjet|envy)', re.I), DeviceType.PRINTER, None),
    (re.compile(r'epson', re.I), DeviceType.PRINTER, None),
    (re.compile(r'canon', re.I), DeviceType.PRINTER, None),
    (re.compile(r'brother', re.I), DeviceType.PRINTER, None),
    
    # Routers
    (re.compile(r'router', re.I), DeviceType.ROUTER, None),
    (re.compile(r'gateway', re.I), DeviceType.ROUTER, None),
    (re.compile(r'access-?point|ap', re.I), DeviceType.ROUTER, None),
]


# ════════════════════════════════════════════════════════════════════════════════
# DEVICE MODEL
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Device:
    """Устройство в сети."""
    
    id: str  # Уникальный ID (хеш от MAC или IP)
    
    # Идентификация
    mac_address: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    
    # Классификация
    device_type: DeviceType = DeviceType.UNKNOWN
    device_os: DeviceOS = DeviceOS.UNKNOWN
    vendor: str | None = None
    model: str | None = None
    
    # Пользовательские данные
    friendly_name: str | None = None
    icon: str | None = None
    notes: str | None = None
    
    # Shield
    shield_profile_id: str | None = None
    
    # Статус
    status: DeviceStatus = DeviceStatus.OFFLINE
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    
    # Статистика
    total_queries: int = 0
    blocked_queries: int = 0
    
    # Флаги
    is_blocked: bool = False
    is_trusted: bool = False
    
    @property
    def display_name(self) -> str:
        """Имя для отображения."""
        if self.friendly_name:
            return self.friendly_name
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} Device"
        return f"Device {self.id[:8]}"
    
    @property
    def block_rate(self) -> float:
        """Процент заблокированных запросов."""
        if self.total_queries == 0:
            return 0.0
        return round(self.blocked_queries / self.total_queries * 100, 1)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "device_type": self.device_type.value,
            "device_os": self.device_os.value,
            "vendor": self.vendor,
            "model": self.model,
            "friendly_name": self.friendly_name,
            "display_name": self.display_name,
            "icon": self.icon,
            "notes": self.notes,
            "shield_profile_id": self.shield_profile_id,
            "status": self.status.value,
            "last_seen": self.last_seen.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "total_queries": self.total_queries,
            "blocked_queries": self.blocked_queries,
            "block_rate": self.block_rate,
            "is_blocked": self.is_blocked,
            "is_trusted": self.is_trusted,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        """Десериализация из словаря."""
        return cls(
            id=data["id"],
            mac_address=data.get("mac_address"),
            ip_address=data.get("ip_address"),
            hostname=data.get("hostname"),
            device_type=DeviceType(data.get("device_type", "unknown")),
            device_os=DeviceOS(data.get("device_os", "unknown")),
            vendor=data.get("vendor"),
            model=data.get("model"),
            friendly_name=data.get("friendly_name"),
            icon=data.get("icon"),
            notes=data.get("notes"),
            shield_profile_id=data.get("shield_profile_id"),
            status=DeviceStatus(data.get("status", "offline")),
            last_seen=datetime.fromisoformat(data["last_seen"]) if "last_seen" in data else datetime.now(),
            first_seen=datetime.fromisoformat(data["first_seen"]) if "first_seen" in data else datetime.now(),
            total_queries=data.get("total_queries", 0),
            blocked_queries=data.get("blocked_queries", 0),
            is_blocked=data.get("is_blocked", False),
            is_trusted=data.get("is_trusted", False),
        )


# ════════════════════════════════════════════════════════════════════════════════
# DEVICE FINGERPRINTER
# ════════════════════════════════════════════════════════════════════════════════

class DeviceFingerprinter:
    """
    Определение типа устройства по MAC, hostname и traffic patterns.
    """
    
    def __init__(self):
        self._oui_db = MAC_OUI_DATABASE
        self._hostname_patterns = HOSTNAME_PATTERNS
    
    def fingerprint(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
        dns_patterns: list[str] | None = None,
    ) -> tuple[DeviceType, DeviceOS | None, str | None]:
        """
        Определение типа устройства.
        
        Returns:
            (device_type, device_os, vendor)
        """
        device_type = DeviceType.UNKNOWN
        device_os: DeviceOS | None = None
        vendor: str | None = None
        
        # 1. MAC OUI lookup
        if mac_address:
            oui_result = self._lookup_oui(mac_address)
            if oui_result:
                vendor, type_hint = oui_result
                if type_hint:
                    device_type = type_hint
        
        # 2. Hostname pattern matching
        if hostname:
            host_result = self._match_hostname(hostname)
            if host_result:
                h_type, h_os = host_result
                device_type = h_type
                device_os = h_os
        
        # 3. DNS traffic pattern analysis (если hostname не дал результата)
        if device_type == DeviceType.UNKNOWN and dns_patterns:
            pattern_result = self._analyze_dns_patterns(dns_patterns)
            if pattern_result:
                device_type, device_os = pattern_result
        
        return device_type, device_os, vendor
    
    def _lookup_oui(self, mac: str) -> tuple[str, DeviceType | None] | None:
        """Lookup по MAC OUI."""
        # Нормализация MAC
        mac = mac.upper().replace('-', ':')
        oui = mac[:8]  # XX:XX:XX
        
        return self._oui_db.get(oui)
    
    def _match_hostname(self, hostname: str) -> tuple[DeviceType, DeviceOS | None] | None:
        """Матчинг hostname по паттернам."""
        for pattern, device_type, device_os in self._hostname_patterns:
            if pattern.search(hostname):
                return device_type, device_os
        return None
    
    def _analyze_dns_patterns(
        self,
        domains: list[str],
    ) -> tuple[DeviceType, DeviceOS | None] | None:
        """Анализ DNS-запросов для определения типа устройства."""
        
        # Характерные домены для разных ОС
        os_indicators = {
            DeviceOS.IOS: [
                'apple.com', 'icloud.com', 'mzstatic.com',
                'push.apple.com', 'itunes.apple.com',
            ],
            DeviceOS.ANDROID: [
                'googleapis.com', 'google.com', 'gstatic.com',
                'android.clients.google.com', 'play.googleapis.com',
            ],
            DeviceOS.WINDOWS: [
                'microsoft.com', 'windowsupdate.com', 'msftconnecttest.com',
                'login.live.com', 'settings-win.data.microsoft.com',
            ],
            DeviceOS.MACOS: [
                'apple.com', 'icloud.com', 'apple-cloudkit.com',
            ],
        }
        
        # Характерные домены для типов устройств
        type_indicators = {
            DeviceType.TV: [
                'roku.com', 'netflix.com', 'hulu.com', 'youtube.com',
                'amazonvideo.com', 'samsungcloudsolution.com',
            ],
            DeviceType.GAMING: [
                'playstation.net', 'xbox.com', 'xboxlive.com',
                'nintendo.net', 'steampowered.com', 'epicgames.com',
            ],
            DeviceType.SPEAKER: [
                'spotify.com', 'sonos.com', 'amazon.com/alexa',
            ],
            DeviceType.IOT: [
                'nest.com', 'ring.com', 'meethue.com',
                'smartthings.com', 'tuya.com',
            ],
        }
        
        domain_set = set(domains)
        
        # Проверка ОС
        detected_os = None
        for os, indicators in os_indicators.items():
            matches = sum(1 for ind in indicators if any(ind in d for d in domain_set))
            if matches >= 2:
                detected_os = os
                break
        
        # Проверка типа устройства
        detected_type = DeviceType.UNKNOWN
        for dtype, indicators in type_indicators.items():
            matches = sum(1 for ind in indicators if any(ind in d for d in domain_set))
            if matches >= 2:
                detected_type = dtype
                break
        
        # Если определена ОС, но не тип — угадываем по ОС
        if detected_type == DeviceType.UNKNOWN and detected_os:
            if detected_os in (DeviceOS.IOS, DeviceOS.ANDROID):
                detected_type = DeviceType.PHONE
            elif detected_os in (DeviceOS.WINDOWS, DeviceOS.MACOS, DeviceOS.LINUX):
                detected_type = DeviceType.PC
        
        if detected_type != DeviceType.UNKNOWN or detected_os:
            return detected_type, detected_os
        
        return None


# ════════════════════════════════════════════════════════════════════════════════
# DEVICE MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class DeviceManager:
    """
    Менеджер устройств.
    
    Управляет:
    - Обнаружением устройств
    - Классификацией
    - Статистикой
    """
    
    def __init__(self, idle_timeout_minutes: int = 60):
        self._devices: dict[str, Device] = {}
        self._fingerprinter = DeviceFingerprinter()
        self._idle_timeout = timedelta(minutes=idle_timeout_minutes)
        
        logger.info("DeviceManager initialized")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Device Discovery
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_or_create_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> Device:
        """
        Получение или создание устройства.
        
        Устройство идентифицируется по MAC (приоритет) или IP.
        """
        device_id = self._generate_device_id(ip_address, mac_address)
        
        if device_id in self._devices:
            device = self._devices[device_id]
            # Обновляем данные
            device.ip_address = ip_address
            if mac_address and not device.mac_address:
                device.mac_address = mac_address
            if hostname and not device.hostname:
                device.hostname = hostname
                # Пере-fingerprint с hostname
                self._update_fingerprint(device)
            
            device.last_seen = datetime.now()
            device.status = DeviceStatus.ONLINE
            return device
        
        # Создаём новое устройство
        device = Device(
            id=device_id,
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname,
            status=DeviceStatus.ONLINE,
        )
        
        # Fingerprinting
        self._update_fingerprint(device)
        
        self._devices[device_id] = device
        logger.info("New device discovered: %s (%s)", device.display_name, device_id)
        
        return device
    
    def _generate_device_id(
        self,
        ip_address: str,
        mac_address: str | None,
    ) -> str:
        """Генерация уникального ID устройства."""
        if mac_address:
            # Используем MAC как основу (более стабильный)
            source = mac_address.upper().replace(':', '').replace('-', '')
        else:
            # Fallback на IP
            source = ip_address
        
        return hashlib.sha256(source.encode()).hexdigest()[:16]
    
    def _update_fingerprint(self, device: Device) -> None:
        """Обновление fingerprint устройства."""
        device_type, device_os, vendor = self._fingerprinter.fingerprint(
            mac_address=device.mac_address,
            hostname=device.hostname,
        )
        
        device.device_type = device_type
        if device_os:
            device.device_os = device_os
        if vendor:
            device.vendor = vendor
        
        # Устанавливаем иконку по типу
        device.icon = self._get_icon_for_type(device_type)
    
    def _get_icon_for_type(self, device_type: DeviceType) -> str:
        """Иконка для типа устройства."""
        icons = {
            DeviceType.PC: "computer",
            DeviceType.LAPTOP: "laptop",
            DeviceType.PHONE: "smartphone",
            DeviceType.TABLET: "tablet",
            DeviceType.TV: "tv",
            DeviceType.IOT: "cpu",
            DeviceType.GAMING: "gamepad",
            DeviceType.ROUTER: "router",
            DeviceType.PRINTER: "printer",
            DeviceType.CAMERA: "camera",
            DeviceType.SPEAKER: "speaker",
            DeviceType.WEARABLE: "watch",
            DeviceType.UNKNOWN: "help-circle",
        }
        return icons.get(device_type, "help-circle")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Device CRUD
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_device(self, device_id: str) -> Device | None:
        """Получение устройства по ID."""
        return self._devices.get(device_id)
    
    def get_device_by_ip(self, ip_address: str) -> Device | None:
        """Поиск устройства по IP."""
        for device in self._devices.values():
            if device.ip_address == ip_address:
                return device
        return None
    
    def get_all_devices(self) -> list[Device]:
        """Список всех устройств."""
        return list(self._devices.values())
    
    def get_online_devices(self) -> list[Device]:
        """Список онлайн устройств."""
        return [d for d in self._devices.values() if d.status == DeviceStatus.ONLINE]
    
    def update_device(self, device: Device) -> None:
        """Обновление устройства."""
        if device.id not in self._devices:
            raise ValueError(f"Device {device.id} not found")
        self._devices[device.id] = device
    
    def delete_device(self, device_id: str) -> None:
        """Удаление устройства."""
        if device_id in self._devices:
            del self._devices[device_id]
            logger.info("Device deleted: %s", device_id)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Statistics
    # ─────────────────────────────────────────────────────────────────────────
    
    def record_query(self, device_id: str, blocked: bool = False) -> None:
        """Запись DNS-запроса."""
        device = self._devices.get(device_id)
        if device:
            device.total_queries += 1
            if blocked:
                device.blocked_queries += 1
            device.last_seen = datetime.now()
            device.status = DeviceStatus.ONLINE
    
    def update_statuses(self) -> None:
        """Обновление статусов устройств."""
        now = datetime.now()
        
        for device in self._devices.values():
            if device.status == DeviceStatus.ONLINE:
                idle_time = now - device.last_seen
                if idle_time > self._idle_timeout:
                    device.status = DeviceStatus.IDLE
                elif idle_time > timedelta(hours=24):
                    device.status = DeviceStatus.OFFLINE
    
    def get_statistics(self) -> dict[str, Any]:
        """Общая статистика по устройствам."""
        devices = self.get_all_devices()
        
        return {
            "total_devices": len(devices),
            "online_devices": sum(1 for d in devices if d.status == DeviceStatus.ONLINE),
            "idle_devices": sum(1 for d in devices if d.status == DeviceStatus.IDLE),
            "offline_devices": sum(1 for d in devices if d.status == DeviceStatus.OFFLINE),
            "blocked_devices": sum(1 for d in devices if d.is_blocked),
            "trusted_devices": sum(1 for d in devices if d.is_trusted),
            "by_type": {
                dtype.value: sum(1 for d in devices if d.device_type == dtype)
                for dtype in DeviceType
            },
            "total_queries": sum(d.total_queries for d in devices),
            "total_blocked": sum(d.blocked_queries for d in devices),
        }


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def lookup_mac_vendor(mac_address: str) -> str | None:
    """Lookup производителя по MAC."""
    mac = mac_address.upper().replace('-', ':')
    oui = mac[:8]
    result = MAC_OUI_DATABASE.get(oui)
    return result[0] if result else None


def detect_device_type(
    mac_address: str | None = None,
    hostname: str | None = None,
) -> DeviceType:
    """Быстрое определение типа устройства."""
    fingerprinter = DeviceFingerprinter()
    device_type, _, _ = fingerprinter.fingerprint(mac_address, hostname)
    return device_type
