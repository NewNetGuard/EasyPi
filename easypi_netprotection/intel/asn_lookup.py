"""
EasyPi NetProtection — ASN Lookup Intel Module.

Проверка владельца IP-адреса по ASN (Autonomous System Number).
Выявление подозрительных хостинг-провайдеров и CDN трекеров.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..verdict.evidence import Evidence

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# ASN DATABASES
# ════════════════════════════════════════════════════════════════════════════════

# Known advertising/tracking ASNs
ADVERTISING_ASNS: dict[int, str] = {
    # Google Ads
    15169: "Google LLC",
    396982: "Google Cloud",
    # Facebook/Meta
    32934: "Facebook/Meta",
    63293: "Facebook/Meta Ireland",
    # Amazon Advertising
    16509: "Amazon.com",
    14618: "Amazon AWS",
    # Microsoft Advertising
    8075: "Microsoft Corporation",
    # Criteo
    44788: "Criteo SA",
    # The Trade Desk
    40676: "The Trade Desk",
    # Taboola
    206844: "Taboola",
    # Outbrain
    60781: "Outbrain",
    # DoubleVerify
    62904: "DoubleVerify",
    # Oracle/BlueKai
    31898: "Oracle Cloud",
    # Verizon Media (formerly Oath/Yahoo)
    10310: "Yahoo/Verizon Media",
}

# Known CDNs that host tracking pixels
TRACKING_CDN_ASNS: dict[int, str] = {
    13335: "Cloudflare",  # Часто используется трекерами
    20940: "Akamai",
    16625: "Akamai",
    54113: "Fastly",
    209242: "Cloudflare WARP",
}

# Known bulletproof/suspicious hosting
SUSPICIOUS_HOSTING_ASNS: dict[int, str] = {
    # Bulletproof hosting providers (часто используются для malware)
    44477: "Stark Industries",
    213371: "Evgeniy Blinov",
    51852: "Private Layer",
    # Hosting известный спамом/malware
    49981: "WorldStream",
    60781: "LeaseWeb",
    # VPN/Proxy providers (не обязательно плохие, но подозрительные)
    9009: "M247 Ltd",
    212238: "Datacamp Limited",
}

# Known legitimate infrastructure (высокий trust)
TRUSTED_ASNS: dict[int, str] = {
    # Major DNS providers
    19281: "Quad9",
    13335: "Cloudflare DNS",  # 1.1.1.1
    15169: "Google DNS",  # 8.8.8.8
    # Major OS vendors
    8075: "Microsoft",
    714: "Apple",
    # Content delivery (trusted)
    2906: "Netflix",
    46489: "Twitch",
    36459: "GitHub",
}

# ASN to organization mapping for common providers
ASN_ORG_MAP: dict[int, str] = {
    **ADVERTISING_ASNS,
    **TRACKING_CDN_ASNS,
    **SUSPICIOUS_HOSTING_ASNS,
    **TRUSTED_ASNS,
}


# ════════════════════════════════════════════════════════════════════════════════
# BGP PREFIX DATABASE (simplified)
# ════════════════════════════════════════════════════════════════════════════════

# Формат: (network, prefix_len, asn)
# Это упрощённая база для демонстрации — в продакшене используется полная BGP таблица
BGP_PREFIXES: list[tuple[str, int, int]] = [
    # Google
    ("8.8.8.0", 24, 15169),
    ("8.8.4.0", 24, 15169),
    ("142.250.0.0", 15, 15169),
    ("172.217.0.0", 16, 15169),
    ("216.58.192.0", 19, 15169),
    # Cloudflare
    ("1.1.1.0", 24, 13335),
    ("1.0.0.0", 24, 13335),
    ("104.16.0.0", 13, 13335),
    ("172.64.0.0", 13, 13335),
    # Quad9
    ("9.9.9.0", 24, 19281),
    # Facebook/Meta
    ("157.240.0.0", 16, 32934),
    ("31.13.24.0", 21, 32934),
    # Amazon AWS
    ("52.0.0.0", 11, 14618),
    ("54.0.0.0", 9, 14618),
    ("3.0.0.0", 9, 14618),
    # Microsoft
    ("13.64.0.0", 11, 8075),
    ("20.0.0.0", 11, 8075),
    ("40.64.0.0", 10, 8075),
    # Apple
    ("17.0.0.0", 8, 714),
    # Akamai
    ("23.0.0.0", 12, 20940),
    ("104.64.0.0", 10, 20940),
    # Fastly
    ("151.101.0.0", 16, 54113),
]


@dataclass
class ASNInfo:
    """Информация об Autonomous System."""
    
    asn: int
    organization: str
    country: str = "unknown"
    is_advertising: bool = False
    is_tracking_cdn: bool = False
    is_suspicious: bool = False
    is_trusted: bool = False
    
    @property
    def risk_level(self) -> str:
        """Уровень риска: low, medium, high."""
        if self.is_suspicious:
            return "high"
        if self.is_advertising or self.is_tracking_cdn:
            return "medium"
        if self.is_trusted:
            return "low"
        return "medium"  # Unknown = medium risk


@dataclass
class ASNLookupResult:
    """Результат ASN-lookup."""
    
    ip_address: str
    asn_info: ASNInfo | None = None
    lookup_method: str = "local"
    confidence: int = 50
    signals: list[str] = field(default_factory=list)
    cached: bool = False


# ════════════════════════════════════════════════════════════════════════════════
# ASN LOOKUP PROVIDER
# ════════════════════════════════════════════════════════════════════════════════

class IntelProvider(Protocol):
    """Protocol для Intel providers."""
    
    async def analyze(self, domain: str, **context) -> "Evidence": ...


class ASNLookupProvider:
    """
    Провайдер ASN-информации для IP-адресов.
    
    Функции:
    - Локальный lookup по встроенной BGP-таблице
    - Категоризация ASN (advertising, suspicious, trusted)
    - Кеширование результатов
    """
    
    def __init__(self, cache_ttl_hours: int = 24):
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache: dict[str, tuple[ASNLookupResult, datetime]] = {}
        self._bgp_table: list[tuple[ipaddress.IPv4Network, int]] = []
        self._build_bgp_table()
        
        logger.info(
            "ASNLookupProvider initialized with %d prefixes",
            len(self._bgp_table)
        )
    
    def _build_bgp_table(self) -> None:
        """Построение таблицы BGP-префиксов."""
        for prefix, length, asn in BGP_PREFIXES:
            try:
                network = ipaddress.IPv4Network(f"{prefix}/{length}", strict=False)
                self._bgp_table.append((network, asn))
            except ValueError as e:
                logger.warning("Invalid BGP prefix %s/%d: %s", prefix, length, e)
        
        # Сортировка по длине префикса (longest match first)
        self._bgp_table.sort(key=lambda x: x[0].prefixlen, reverse=True)
    
    async def analyze(
        self,
        domain: str,
        ip_addresses: list[str] | None = None,
        **context
    ) -> "Evidence":
        """
        Анализ IP-адресов домена.
        
        Реализует IntelProvider protocol.
        """
        from ..verdict.evidence import Evidence, Signal, EvidenceSource
        
        if not ip_addresses:
            return Evidence(
                source=EvidenceSource.ASN_LOOKUP,
                signals=[],
                confidence=0,
                summary="No IP addresses to analyze"
            )
        
        signals: list[Signal] = []
        total_confidence = 0
        
        for ip in ip_addresses:
            result = await self.lookup(ip)
            
            if result.asn_info:
                info = result.asn_info
                
                # Создаём Signal для каждого IP
                signal = Signal(
                    name=f"asn:{info.asn}",
                    value=info.organization,
                    weight=self._calculate_weight(info),
                    metadata={
                        "ip": ip,
                        "asn": info.asn,
                        "org": info.organization,
                        "risk": info.risk_level,
                        "is_advertising": info.is_advertising,
                        "is_suspicious": info.is_suspicious,
                    }
                )
                signals.append(signal)
                total_confidence = max(total_confidence, result.confidence)
            
            # Добавляем текстовые сигналы
            for sig_text in result.signals:
                signals.append(Signal(
                    name="asn_signal",
                    value=sig_text,
                    weight=0.5
                ))
        
        # Формируем summary
        summary = self._build_summary(signals)
        
        return Evidence(
            source=EvidenceSource.ASN_LOOKUP,
            signals=signals,
            confidence=total_confidence,
            summary=summary
        )
    
    async def lookup(self, ip_address: str) -> ASNLookupResult:
        """
        Lookup ASN для IP-адреса.
        
        Args:
            ip_address: IPv4 или IPv6 адрес
            
        Returns:
            ASNLookupResult с информацией об ASN
        """
        # Проверяем кеш
        if ip_address in self._cache:
            result, timestamp = self._cache[ip_address]
            if datetime.now() - timestamp < self.cache_ttl:
                result.cached = True
                return result
        
        # Выполняем lookup
        result = self._local_lookup(ip_address)
        
        # Кешируем результат
        self._cache[ip_address] = (result, datetime.now())
        
        return result
    
    def _local_lookup(self, ip_address: str) -> ASNLookupResult:
        """Локальный lookup по BGP-таблице."""
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return ASNLookupResult(
                ip_address=ip_address,
                confidence=0,
                signals=["Invalid IP address format"]
            )
        
        # IPv6 — пока только базовая поддержка
        if isinstance(ip, ipaddress.IPv6Address):
            return ASNLookupResult(
                ip_address=ip_address,
                asn_info=None,
                lookup_method="local",
                confidence=30,
                signals=["IPv6 lookup not fully supported"]
            )
        
        # Longest prefix match для IPv4
        for network, asn in self._bgp_table:
            if ip in network:
                asn_info = self._get_asn_info(asn)
                signals = self._generate_signals(asn_info)
                
                return ASNLookupResult(
                    ip_address=ip_address,
                    asn_info=asn_info,
                    lookup_method="local",
                    confidence=self._calculate_confidence(asn_info),
                    signals=signals
                )
        
        # Не найдено в локальной таблице
        return ASNLookupResult(
            ip_address=ip_address,
            asn_info=None,
            lookup_method="local",
            confidence=20,
            signals=["ASN not found in local database"]
        )
    
    def _get_asn_info(self, asn: int) -> ASNInfo:
        """Получение информации об ASN."""
        org = ASN_ORG_MAP.get(asn, f"AS{asn}")
        
        return ASNInfo(
            asn=asn,
            organization=org,
            is_advertising=asn in ADVERTISING_ASNS,
            is_tracking_cdn=asn in TRACKING_CDN_ASNS,
            is_suspicious=asn in SUSPICIOUS_HOSTING_ASNS,
            is_trusted=asn in TRUSTED_ASNS,
        )
    
    def _generate_signals(self, info: ASNInfo) -> list[str]:
        """Генерация сигналов на основе ASN info."""
        signals = []
        
        if info.is_advertising:
            signals.append(f"AS{info.asn} belongs to advertising network ({info.organization})")
        
        if info.is_tracking_cdn:
            signals.append(f"AS{info.asn} is CDN known for hosting trackers ({info.organization})")
        
        if info.is_suspicious:
            signals.append(f"AS{info.asn} is suspicious/bulletproof hosting ({info.organization})")
        
        if info.is_trusted:
            signals.append(f"AS{info.asn} is trusted infrastructure ({info.organization})")
        
        if not signals:
            signals.append(f"AS{info.asn} ({info.organization}) - neutral")
        
        return signals
    
    def _calculate_confidence(self, info: ASNInfo) -> int:
        """Расчёт уверенности в результате."""
        if info.is_suspicious:
            return 90  # Высокая уверенность для suspicious
        if info.is_advertising:
            return 85
        if info.is_trusted:
            return 80
        if info.is_tracking_cdn:
            return 70
        return 50  # Базовая уверенность
    
    def _calculate_weight(self, info: ASNInfo) -> float:
        """Вес сигнала для Evidence."""
        if info.is_suspicious:
            return 0.9
        if info.is_advertising:
            return 0.8
        if info.is_tracking_cdn:
            return 0.6
        if info.is_trusted:
            return -0.3  # Отрицательный вес = в пользу allow
        return 0.3
    
    def _build_summary(self, signals: list) -> str:
        """Построение summary для Evidence."""
        if not signals:
            return "No ASN information available"
        
        advertising = sum(1 for s in signals if hasattr(s, 'metadata') and s.metadata.get('is_advertising'))
        suspicious = sum(1 for s in signals if hasattr(s, 'metadata') and s.metadata.get('is_suspicious'))
        
        parts = []
        if suspicious > 0:
            parts.append(f"{suspicious} suspicious ASN(s)")
        if advertising > 0:
            parts.append(f"{advertising} advertising ASN(s)")
        
        if parts:
            return f"ASN analysis: {', '.join(parts)}"
        return f"ASN analysis: {len(signals)} IP(s) checked"
    
    def clear_cache(self) -> int:
        """Очистка кеша."""
        count = len(self._cache)
        self._cache.clear()
        return count
    
    def get_cache_stats(self) -> dict:
        """Статистика кеша."""
        now = datetime.now()
        valid = sum(1 for _, (_, ts) in self._cache.items() if now - ts < self.cache_ttl)
        
        return {
            "total_entries": len(self._cache),
            "valid_entries": valid,
            "expired_entries": len(self._cache) - valid,
        }


# ════════════════════════════════════════════════════════════════════════════════
# ASN MATCHER
# ════════════════════════════════════════════════════════════════════════════════

class ASNMatcher:
    """
    Matcher для блокировки по ASN.
    
    Позволяет создавать правила типа "блокировать все IP из AS15169".
    """
    
    def __init__(self, blocked_asns: set[int] | None = None):
        self.blocked_asns = blocked_asns or set()
        self._provider = ASNLookupProvider()
    
    def add_blocked_asn(self, asn: int) -> None:
        """Добавить ASN в блоклист."""
        self.blocked_asns.add(asn)
    
    def remove_blocked_asn(self, asn: int) -> None:
        """Удалить ASN из блоклиста."""
        self.blocked_asns.discard(asn)
    
    async def matches(self, ip_addresses: list[str]) -> tuple[bool, str | None]:
        """
        Проверка IP-адресов на принадлежность заблокированным ASN.
        
        Returns:
            (matched, reason)
        """
        for ip in ip_addresses:
            result = await self._provider.lookup(ip)
            
            if result.asn_info and result.asn_info.asn in self.blocked_asns:
                return (
                    True,
                    f"IP {ip} belongs to blocked AS{result.asn_info.asn} "
                    f"({result.asn_info.organization})"
                )
        
        return (False, None)
    
    def get_blocked_asns_info(self) -> list[dict]:
        """Информация о заблокированных ASN."""
        return [
            {
                "asn": asn,
                "organization": ASN_ORG_MAP.get(asn, f"AS{asn}"),
            }
            for asn in sorted(self.blocked_asns)
        ]


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

async def lookup_asn(ip_address: str) -> ASNInfo | None:
    """
    Быстрый lookup ASN для IP.
    
    Convenience function для одиночных запросов.
    """
    provider = ASNLookupProvider()
    result = await provider.lookup(ip_address)
    return result.asn_info


def is_advertising_asn(asn: int) -> bool:
    """Проверка, принадлежит ли ASN рекламной сети."""
    return asn in ADVERTISING_ASNS


def is_suspicious_asn(asn: int) -> bool:
    """Проверка, является ли ASN подозрительным."""
    return asn in SUSPICIOUS_HOSTING_ASNS


def is_trusted_asn(asn: int) -> bool:
    """Проверка, является ли ASN доверенным."""
    return asn in TRUSTED_ASNS
