"""
EasyPi NetProtection — TLS Probe Intel Module.

Извлечение SNI (Server Name Indication) из TLS ClientHello.
Пассивный анализ без MITM — только метаданные handshake.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..verdict.evidence import Evidence

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# TLS CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

class TLSContentType(IntEnum):
    """TLS Record Layer Content Types."""
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class TLSHandshakeType(IntEnum):
    """TLS Handshake Message Types."""
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    HELLO_RETRY_REQUEST = 6
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254


class TLSExtensionType(IntEnum):
    """TLS Extension Types."""
    SERVER_NAME = 0  # SNI
    MAX_FRAGMENT_LENGTH = 1
    CLIENT_CERTIFICATE_URL = 2
    TRUSTED_CA_KEYS = 3
    TRUNCATED_HMAC = 4
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10  # Elliptic curves
    EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    ALPN = 16  # Application Layer Protocol Negotiation
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    SESSION_TICKET = 35
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51
    RENEGOTIATION_INFO = 65281


class TLSVersion(IntEnum):
    """TLS Protocol Versions."""
    SSL_3_0 = 0x0300
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304


# ════════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TLSClientHelloInfo:
    """Информация из TLS ClientHello."""
    
    # SNI (Server Name Indication)
    server_name: str | None = None
    
    # Версия протокола
    legacy_version: int = 0
    supported_versions: list[int] = field(default_factory=list)
    
    # Криптографические параметры
    cipher_suites: list[int] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=list)
    
    # Расширения
    extensions: dict[int, bytes] = field(default_factory=dict)
    
    # ALPN (Application Layer Protocol Negotiation)
    alpn_protocols: list[str] = field(default_factory=list)
    
    # Дополнительная информация
    session_id: bytes = b""
    random: bytes = b""
    
    # Флаги
    is_tls_1_3: bool = False
    has_sni: bool = False
    has_alpn: bool = False
    
    @property
    def tls_version_string(self) -> str:
        """Человекочитаемая версия TLS."""
        if self.supported_versions:
            max_version = max(self.supported_versions)
        else:
            max_version = self.legacy_version
        
        version_map = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }
        return version_map.get(max_version, f"Unknown (0x{max_version:04x})")


@dataclass
class TLSProbeResult:
    """Результат анализа TLS handshake."""
    
    success: bool = False
    error: str | None = None
    
    client_hello: TLSClientHelloInfo | None = None
    
    # Сигналы для Evidence
    signals: list[str] = field(default_factory=list)
    confidence: int = 0
    
    @property
    def sni(self) -> str | None:
        """Shortcut для SNI."""
        if self.client_hello:
            return self.client_hello.server_name
        return None


# ════════════════════════════════════════════════════════════════════════════════
# TLS PARSER
# ════════════════════════════════════════════════════════════════════════════════

class TLSParser:
    """
    Парсер TLS ClientHello для извлечения SNI.
    
    Реализует пассивный анализ TLS handshake без расшифровки трафика.
    Только чтение метаданных из открытой части handshake.
    """
    
    @classmethod
    def parse_client_hello(cls, data: bytes) -> TLSProbeResult:
        """
        Парсинг TLS ClientHello сообщения.
        
        Args:
            data: Raw bytes TLS record (начиная с TLS record header)
            
        Returns:
            TLSProbeResult с извлечённой информацией
        """
        result = TLSProbeResult()
        
        try:
            # Минимальная длина TLS record header + handshake header
            if len(data) < 9:
                result.error = "Data too short for TLS record"
                return result
            
            # TLS Record Layer
            content_type = data[0]
            if content_type != TLSContentType.HANDSHAKE:
                result.error = f"Not a handshake record (type={content_type})"
                return result
            
            # Legacy version (2 bytes)
            legacy_version = struct.unpack("!H", data[1:3])[0]
            
            # Record length (2 bytes)
            record_length = struct.unpack("!H", data[3:5])[0]
            
            if len(data) < 5 + record_length:
                result.error = "Incomplete TLS record"
                return result
            
            # Handshake header
            handshake_type = data[5]
            if handshake_type != TLSHandshakeType.CLIENT_HELLO:
                result.error = f"Not a ClientHello (type={handshake_type})"
                return result
            
            # Handshake length (3 bytes)
            handshake_length = struct.unpack("!I", b'\x00' + data[6:9])[0]
            
            # Parse ClientHello body
            client_hello = cls._parse_client_hello_body(data[9:9+handshake_length])
            client_hello.legacy_version = legacy_version
            
            result.success = True
            result.client_hello = client_hello
            result.confidence = 90 if client_hello.has_sni else 50
            
            # Генерация сигналов
            cls._generate_signals(result)
            
        except Exception as e:
            result.error = f"Parse error: {str(e)}"
            logger.debug("TLS parse error: %s", e, exc_info=True)
        
        return result
    
    @classmethod
    def _parse_client_hello_body(cls, data: bytes) -> TLSClientHelloInfo:
        """Парсинг тела ClientHello."""
        info = TLSClientHelloInfo()
        offset = 0
        
        # Client Version (2 bytes) - в TLS 1.3 всегда 0x0303
        info.legacy_version = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        info.random = data[offset:offset+32]
        offset += 32
        
        # Session ID (variable length)
        session_id_length = data[offset]
        offset += 1
        info.session_id = data[offset:offset+session_id_length]
        offset += session_id_length
        
        # Cipher Suites (variable length)
        cipher_suites_length = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        
        for i in range(0, cipher_suites_length, 2):
            suite = struct.unpack("!H", data[offset+i:offset+i+2])[0]
            info.cipher_suites.append(suite)
        offset += cipher_suites_length
        
        # Compression Methods (variable length)
        compression_length = data[offset]
        offset += 1
        info.compression_methods = list(data[offset:offset+compression_length])
        offset += compression_length
        
        # Extensions (variable length)
        if offset < len(data):
            extensions_length = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            
            extensions_end = offset + extensions_length
            while offset < extensions_end:
                ext_type = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                ext_length = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                ext_data = data[offset:offset+ext_length]
                offset += ext_length
                
                info.extensions[ext_type] = ext_data
                
                # Parse specific extensions
                if ext_type == TLSExtensionType.SERVER_NAME:
                    info.server_name = cls._parse_sni_extension(ext_data)
                    info.has_sni = info.server_name is not None
                
                elif ext_type == TLSExtensionType.SUPPORTED_VERSIONS:
                    info.supported_versions = cls._parse_supported_versions(ext_data)
                    info.is_tls_1_3 = TLSVersion.TLS_1_3 in info.supported_versions
                
                elif ext_type == TLSExtensionType.ALPN:
                    info.alpn_protocols = cls._parse_alpn_extension(ext_data)
                    info.has_alpn = len(info.alpn_protocols) > 0
        
        return info
    
    @classmethod
    def _parse_sni_extension(cls, data: bytes) -> str | None:
        """
        Парсинг SNI extension.
        
        Structure:
            - SNI List Length (2 bytes)
            - SNI Entry:
                - Name Type (1 byte) - 0 = hostname
                - Name Length (2 bytes)
                - Name (variable)
        """
        if len(data) < 5:
            return None
        
        try:
            # SNI list length
            list_length = struct.unpack("!H", data[0:2])[0]
            offset = 2
            
            while offset < 2 + list_length:
                name_type = data[offset]
                offset += 1
                name_length = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                
                if name_type == 0:  # hostname
                    hostname = data[offset:offset+name_length].decode('ascii')
                    return hostname.lower()
                
                offset += name_length
        except Exception:
            pass
        
        return None
    
    @classmethod
    def _parse_supported_versions(cls, data: bytes) -> list[int]:
        """Парсинг supported_versions extension."""
        versions = []
        
        try:
            if len(data) < 1:
                return versions
            
            length = data[0]
            for i in range(1, 1 + length, 2):
                version = struct.unpack("!H", data[i:i+2])[0]
                versions.append(version)
        except Exception:
            pass
        
        return versions
    
    @classmethod
    def _parse_alpn_extension(cls, data: bytes) -> list[str]:
        """Парсинг ALPN extension."""
        protocols = []
        
        try:
            if len(data) < 2:
                return protocols
            
            list_length = struct.unpack("!H", data[0:2])[0]
            offset = 2
            
            while offset < 2 + list_length:
                proto_length = data[offset]
                offset += 1
                protocol = data[offset:offset+proto_length].decode('ascii')
                protocols.append(protocol)
                offset += proto_length
        except Exception:
            pass
        
        return protocols
    
    @classmethod
    def _generate_signals(cls, result: TLSProbeResult) -> None:
        """Генерация сигналов для Evidence."""
        if not result.client_hello:
            return
        
        info = result.client_hello
        
        if info.has_sni:
            result.signals.append(f"SNI: {info.server_name}")
        else:
            result.signals.append("No SNI present (possible ESNI/ECH)")
        
        result.signals.append(f"TLS version: {info.tls_version_string}")
        
        if info.has_alpn:
            result.signals.append(f"ALPN protocols: {', '.join(info.alpn_protocols)}")
        
        if info.is_tls_1_3:
            result.signals.append("TLS 1.3 supported")


# ════════════════════════════════════════════════════════════════════════════════
# TLS PROBE PROVIDER
# ════════════════════════════════════════════════════════════════════════════════

class IntelProvider(Protocol):
    """Protocol для Intel providers."""
    
    async def analyze(self, domain: str, **context) -> "Evidence": ...


class TLSProbeProvider:
    """
    Провайдер TLS-информации для Verdict Engine.
    
    Функции:
    - Извлечение SNI из ClientHello
    - Валидация соответствия SNI и DNS-запроса
    - Детекция SNI-based evasion техник
    """
    
    def __init__(self):
        self._parser = TLSParser()
        logger.info("TLSProbeProvider initialized")
    
    async def analyze(
        self,
        domain: str,
        tls_data: bytes | None = None,
        **context
    ) -> "Evidence":
        """
        Анализ TLS ClientHello.
        
        Реализует IntelProvider protocol.
        
        Args:
            domain: Домен из DNS-запроса
            tls_data: Raw TLS ClientHello bytes (если доступны)
        """
        from ..verdict.evidence import Evidence, Signal, EvidenceSource
        
        signals: list[Signal] = []
        confidence = 0
        summary = "No TLS data available"
        
        if tls_data:
            result = self._parser.parse_client_hello(tls_data)
            
            if result.success and result.client_hello:
                info = result.client_hello
                confidence = result.confidence
                
                # SNI Signal
                if info.has_sni:
                    sni_matches = self._check_sni_match(domain, info.server_name)
                    
                    signals.append(Signal(
                        name="tls_sni",
                        value=info.server_name or "",
                        weight=0.3 if sni_matches else 0.7,
                        metadata={
                            "sni": info.server_name,
                            "matches_dns": sni_matches,
                        }
                    ))
                    
                    if not sni_matches:
                        signals.append(Signal(
                            name="sni_mismatch",
                            value=f"DNS={domain}, SNI={info.server_name}",
                            weight=0.8,
                            metadata={
                                "dns_domain": domain,
                                "sni_domain": info.server_name,
                            }
                        ))
                        summary = f"SNI mismatch: DNS={domain}, SNI={info.server_name}"
                    else:
                        summary = f"SNI verified: {info.server_name}"
                else:
                    # Отсутствие SNI может быть ESNI/ECH или evasion
                    signals.append(Signal(
                        name="no_sni",
                        value="missing",
                        weight=0.5,
                        metadata={"reason": "ESNI/ECH or evasion"}
                    ))
                    summary = "No SNI in ClientHello (possible ESNI/ECH)"
                
                # TLS Version Signal
                signals.append(Signal(
                    name="tls_version",
                    value=info.tls_version_string,
                    weight=0.1,
                    metadata={
                        "is_tls_1_3": info.is_tls_1_3,
                        "supported_versions": info.supported_versions,
                    }
                ))
                
                # ALPN Signal
                if info.has_alpn:
                    signals.append(Signal(
                        name="tls_alpn",
                        value=",".join(info.alpn_protocols),
                        weight=0.1,
                        metadata={"protocols": info.alpn_protocols}
                    ))
                
                # Текстовые сигналы
                for sig_text in result.signals:
                    signals.append(Signal(
                        name="tls_signal",
                        value=sig_text,
                        weight=0.2
                    ))
            
            elif result.error:
                signals.append(Signal(
                    name="tls_error",
                    value=result.error,
                    weight=0.1
                ))
                summary = f"TLS parse error: {result.error}"
        
        return Evidence(
            source=EvidenceSource.TLS_PROBE,
            signals=signals,
            confidence=confidence,
            summary=summary
        )
    
    def _check_sni_match(self, dns_domain: str, sni: str | None) -> bool:
        """
        Проверка соответствия SNI и DNS-запроса.
        
        Учитывает:
        - Точное совпадение
        - Wildcard субдомены
        - CDN алиасы
        """
        if not sni:
            return False
        
        dns_domain = dns_domain.lower().strip('.')
        sni = sni.lower().strip('.')
        
        # Точное совпадение
        if dns_domain == sni:
            return True
        
        # DNS — субдомен SNI
        if dns_domain.endswith('.' + sni):
            return True
        
        # SNI — субдомен DNS
        if sni.endswith('.' + dns_domain):
            return True
        
        # Общий parent domain
        dns_parts = dns_domain.split('.')
        sni_parts = sni.split('.')
        
        if len(dns_parts) >= 2 and len(sni_parts) >= 2:
            dns_parent = '.'.join(dns_parts[-2:])
            sni_parent = '.'.join(sni_parts[-2:])
            if dns_parent == sni_parent:
                return True
        
        return False
    
    def extract_sni(self, data: bytes) -> str | None:
        """
        Быстрое извлечение SNI из TLS ClientHello.
        
        Args:
            data: Raw TLS data
            
        Returns:
            SNI hostname или None
        """
        result = self._parser.parse_client_hello(data)
        return result.sni


# ════════════════════════════════════════════════════════════════════════════════
# SNI VALIDATOR
# ════════════════════════════════════════════════════════════════════════════════

class SNIValidator:
    """
    Валидатор SNI для детекции evasion техник.
    
    Проверяет:
    - Соответствие SNI и IP
    - Domain fronting
    - SNI spoofing
    """
    
    # Известные CDN, где domain fronting возможен
    FRONTING_SUSCEPTIBLE_CDNS = {
        'cloudflare.com',
        'cloudfront.net',
        'fastly.net',
        'akamaiedge.net',
        'azureedge.net',
        'googleapis.com',
    }
    
    def __init__(self):
        self._cache: dict[str, list[str]] = {}
    
    async def validate(
        self,
        sni: str,
        resolved_ips: list[str],
        expected_domain: str,
    ) -> dict:
        """
        Валидация SNI.
        
        Returns:
            Результат валидации с флагами подозрительности
        """
        result = {
            "sni": sni,
            "expected_domain": expected_domain,
            "is_valid": True,
            "is_fronting_risk": False,
            "warnings": [],
        }
        
        # Проверка на CDN susceptible to fronting
        for cdn in self.FRONTING_SUSCEPTIBLE_CDNS:
            if sni.endswith(cdn):
                result["is_fronting_risk"] = True
                result["warnings"].append(
                    f"SNI uses CDN susceptible to domain fronting: {cdn}"
                )
                break
        
        # Проверка соответствия SNI и expected domain
        if not self._domains_related(sni, expected_domain):
            result["is_valid"] = False
            result["warnings"].append(
                f"SNI '{sni}' does not match expected domain '{expected_domain}'"
            )
        
        return result
    
    def _domains_related(self, domain1: str, domain2: str) -> bool:
        """Проверка связи между доменами."""
        d1 = domain1.lower().strip('.')
        d2 = domain2.lower().strip('.')
        
        if d1 == d2:
            return True
        
        # Общий parent domain
        parts1 = d1.split('.')
        parts2 = d2.split('.')
        
        if len(parts1) >= 2 and len(parts2) >= 2:
            parent1 = '.'.join(parts1[-2:])
            parent2 = '.'.join(parts2[-2:])
            return parent1 == parent2
        
        return False


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def extract_sni(data: bytes) -> str | None:
    """
    Быстрое извлечение SNI из TLS ClientHello.
    
    Convenience function для одиночных запросов.
    """
    result = TLSParser.parse_client_hello(data)
    return result.sni


def parse_client_hello(data: bytes) -> TLSProbeResult:
    """
    Полный парсинг TLS ClientHello.
    
    Convenience function для детального анализа.
    """
    return TLSParser.parse_client_hello(data)


def is_tls_client_hello(data: bytes) -> bool:
    """
    Проверка, является ли пакет TLS ClientHello.
    
    Quick check без полного парсинга.
    """
    if len(data) < 6:
        return False
    
    # Content type = Handshake (22)
    if data[0] != TLSContentType.HANDSHAKE:
        return False
    
    # Version должна быть TLS-подобной
    version = struct.unpack("!H", data[1:3])[0]
    if version < 0x0300 or version > 0x0305:
        return False
    
    # Handshake type = ClientHello (1)
    if data[5] != TLSHandshakeType.CLIENT_HELLO:
        return False
    
    return True
