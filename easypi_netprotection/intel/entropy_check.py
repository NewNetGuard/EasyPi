"""
EasyPi NetProtection — Entropy Check Intel Module.

Детекция DNS-туннелирования и DGA через анализ энтропии поддоменов.
Высокая энтропия указывает на закодированные данные в DNS-запросах.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..verdict.evidence import Evidence

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY THRESHOLDS
# ════════════════════════════════════════════════════════════════════════════════

class EntropyThresholds:
    """Пороговые значения энтропии."""
    
    # Энтропия Shannon для случайных данных ≈ log2(charset_size)
    # Для base64 (64 символа) = 6.0
    # Для hex (16 символов) = 4.0
    # Для обычного текста ≈ 3.5-4.5
    
    # Нормальные домены обычно имеют энтропию 2.5-4.0
    NORMAL_MAX = 4.0
    
    # Подозрительно высокая энтропия (возможно закодированные данные)
    SUSPICIOUS_MIN = 4.5
    
    # Явно аномальная энтропия (base64/hex encoded)
    ANOMALOUS_MIN = 5.0
    
    # Критически высокая (почти случайные данные)
    CRITICAL_MIN = 5.5
    
    # Минимальная длина для анализа
    MIN_LABEL_LENGTH = 8
    
    # Максимальная нормальная длина поддомена
    MAX_NORMAL_SUBDOMAIN_LENGTH = 25
    
    # Максимальная нормальная глубина вложенности
    MAX_NORMAL_DEPTH = 4


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY ANALYSIS RESULT
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class EntropyAnalysisResult:
    """Результат анализа энтропии домена."""
    
    domain: str
    entropy: float
    label_entropies: dict[str, float] = field(default_factory=dict)
    max_label_entropy: float = 0.0
    max_label_length: int = 0
    depth: int = 0
    
    # Флаги детекции
    is_suspicious: bool = False
    is_tunneling: bool = False
    is_dga: bool = False
    
    # Дополнительные метрики
    consonant_ratio: float = 0.0
    digit_ratio: float = 0.0
    has_hex_pattern: bool = False
    has_base64_pattern: bool = False
    
    confidence: int = 0
    signals: list[str] = field(default_factory=list)
    
    @property
    def risk_level(self) -> str:
        """Уровень риска: low, medium, high, critical."""
        if self.is_tunneling:
            return "critical"
        if self.is_dga:
            return "high"
        if self.is_suspicious:
            return "medium"
        return "low"


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY CALCULATOR
# ════════════════════════════════════════════════════════════════════════════════

class EntropyCalculator:
    """Калькулятор энтропии Shannon."""
    
    @staticmethod
    def shannon_entropy(text: str) -> float:
        """
        Вычисление энтропии Shannon для строки.
        
        H = -Σ p(x) * log2(p(x))
        
        Где p(x) — вероятность символа x.
        """
        if not text:
            return 0.0
        
        # Подсчёт частот символов
        freq = Counter(text.lower())
        length = len(text)
        
        # Вычисление энтропии
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
        
        return round(entropy, 3)
    
    @staticmethod
    def normalized_entropy(text: str) -> float:
        """
        Нормализованная энтропия (0-1).
        
        Делим на максимально возможную энтропию для данной длины.
        """
        if not text or len(text) <= 1:
            return 0.0
        
        entropy = EntropyCalculator.shannon_entropy(text)
        max_entropy = math.log2(len(set(text.lower())))
        
        if max_entropy == 0:
            return 0.0
        
        return round(entropy / max_entropy, 3)


# ════════════════════════════════════════════════════════════════════════════════
# PATTERN DETECTORS
# ════════════════════════════════════════════════════════════════════════════════

class PatternDetector:
    """Детектор паттернов DNS-туннелирования и DGA."""
    
    # Паттерны hex-encoded данных
    HEX_PATTERN = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
    
    # Паттерны base64-encoded данных (включая URL-safe вариант)
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/\-_]{20,}={0,2}$')
    
    # Паттерны base32-encoded (часто используется в DNS tunneling)
    BASE32_PATTERN = re.compile(r'^[A-Z2-7]{16,}={0,6}$', re.IGNORECASE)
    
    # Известные паттерны DGA
    DGA_PATTERNS = [
        # Случайные consonant+vowel комбинации
        re.compile(r'^([bcdfghjklmnpqrstvwxz][aeiou]){4,}', re.IGNORECASE),
        # Длинные последовательности без гласных
        re.compile(r'[bcdfghjklmnpqrstvwxz]{5,}', re.IGNORECASE),
        # Числа в середине слова
        re.compile(r'[a-z]+\d{3,}[a-z]+', re.IGNORECASE),
    ]
    
    # Известные DNS tunneling tools signatures
    TUNNELING_SIGNATURES = [
        # iodine
        re.compile(r'^[a-z0-9]{52,}\.', re.IGNORECASE),
        # dns2tcp
        re.compile(r'^[a-z]{2}\.[a-z0-9]{30,}\.', re.IGNORECASE),
        # dnscat2
        re.compile(r'^dnscat\.', re.IGNORECASE),
    ]
    
    @classmethod
    def detect_hex(cls, label: str) -> bool:
        """Детекция hex-encoded данных."""
        return bool(cls.HEX_PATTERN.match(label))
    
    @classmethod
    def detect_base64(cls, label: str) -> bool:
        """Детекция base64-encoded данных."""
        return bool(cls.BASE64_PATTERN.match(label))
    
    @classmethod
    def detect_base32(cls, label: str) -> bool:
        """Детекция base32-encoded данных."""
        return bool(cls.BASE32_PATTERN.match(label))
    
    @classmethod
    def detect_dga(cls, domain: str) -> bool:
        """Детекция DGA-паттернов."""
        return any(pattern.search(domain) for pattern in cls.DGA_PATTERNS)
    
    @classmethod
    def detect_tunneling_signature(cls, domain: str) -> bool:
        """Детекция сигнатур известных tunneling tools."""
        return any(sig.match(domain) for sig in cls.TUNNELING_SIGNATURES)
    
    @staticmethod
    def consonant_ratio(text: str) -> float:
        """Соотношение согласных к общему числу букв."""
        if not text:
            return 0.0
        
        letters = [c for c in text.lower() if c.isalpha()]
        if not letters:
            return 0.0
        
        consonants = [c for c in letters if c not in 'aeiou']
        return round(len(consonants) / len(letters), 3)
    
    @staticmethod
    def digit_ratio(text: str) -> float:
        """Соотношение цифр к общей длине."""
        if not text:
            return 0.0
        
        digits = sum(1 for c in text if c.isdigit())
        return round(digits / len(text), 3)


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class IntelProvider(Protocol):
    """Protocol для Intel providers."""
    
    async def analyze(self, domain: str, **context) -> "Evidence": ...


class EntropyAnalyzer:
    """
    Анализатор энтропии DNS-запросов.
    
    Выявляет:
    - DNS Tunneling (высокая энтропия, длинные поддомены)
    - DGA (Domain Generation Algorithm)
    - Закодированные данные (base64, hex, base32)
    """
    
    def __init__(
        self,
        thresholds: EntropyThresholds | None = None,
        whitelist_tlds: set[str] | None = None,
    ):
        self.thresholds = thresholds or EntropyThresholds()
        self.whitelist_tlds = whitelist_tlds or {
            'com', 'org', 'net', 'edu', 'gov',
            'io', 'co', 'me', 'app', 'dev',
        }
        
        logger.info("EntropyAnalyzer initialized")
    
    async def analyze(self, domain: str, context: dict | None = None) -> list["Evidence"]:
        """
        Анализ домена на признаки туннелирования/DGA.
        
        Реализует IntelProvider protocol.
        
        Args:
            domain: Domain to analyze
            context: Optional context dict (unused but required for protocol)
            
        Returns:
            List of Evidence items (empty if no issues detected)
        """
        from ..verdict.evidence import Evidence, EvidenceSource
        
        result = self.analyze_domain(domain)
        evidence_items: list[Evidence] = []
        
        # Only add evidence if suspicious activity detected
        if result.is_tunneling:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_ENTROPY,
                signal=f"DNS tunneling detected: entropy={result.entropy:.2f}, risk={result.risk_level}",
                confidence=result.confidence,
                weight=0.95,
                suggested_action="deny",
                metadata={
                    "entropy": result.entropy,
                    "max_label_entropy": result.max_label_entropy,
                    "risk_level": result.risk_level,
                    "detection_type": "dns_tunneling",
                },
            ))
        
        # NOTE: DGA verdicts are intentionally NOT emitted here. The dedicated
        # heuristics DGA detector (heuristics/dga_detector.py, pipeline stage 2.5)
        # is the single source of truth for DGA, which avoids double-counting and
        # conflicting confidence between two independent detectors. EntropyAnalyzer
        # focuses on DNS tunneling / encoded-data exfiltration below.
        
        if result.has_hex_pattern and result.max_label_entropy > EntropyThresholds.SUSPICIOUS_MIN:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_ENTROPY,
                signal="Hex-encoded data detected in subdomain",
                confidence=70,
                weight=0.7,
                suggested_action="observe",
                metadata={
                    "entropy": result.entropy,
                    "detection_type": "hex_encoding",
                },
            ))
        
        if result.has_base64_pattern and result.max_label_entropy > EntropyThresholds.SUSPICIOUS_MIN:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_ENTROPY,
                signal="Base64-encoded data detected in subdomain",
                confidence=75,
                weight=0.75,
                suggested_action="observe",
                metadata={
                    "entropy": result.entropy,
                    "detection_type": "base64_encoding",
                },
            ))
        
        # Add signals as individual evidence items if critical
        for sig_text in result.signals:
            if "critical" in sig_text.lower() or "tunneling" in sig_text.lower():
                evidence_items.append(Evidence(
                    source=EvidenceSource.INTEL_ENTROPY,
                    signal=sig_text,
                    confidence=60,
                    weight=0.5,
                    suggested_action="observe",
                    metadata={"raw_signal": True},
                ))
        
        return evidence_items
    
    def analyze_domain(self, domain: str) -> EntropyAnalysisResult:
        """
        Полный анализ домена.
        
        Args:
            domain: Полное доменное имя
            
        Returns:
            EntropyAnalysisResult с результатами анализа
        """
        # Нормализация
        domain = domain.lower().strip('.')
        labels = domain.split('.')
        
        result = EntropyAnalysisResult(
            domain=domain,
            entropy=0.0,
            depth=len(labels),
        )
        
        # Исключаем TLD и SLD из анализа
        analysis_labels = labels[:-2] if len(labels) > 2 else labels[:-1]
        
        if not analysis_labels:
            result.confidence = 10
            result.signals.append("Domain too short for entropy analysis")
            return result
        
        # Анализ каждого label
        for label in analysis_labels:
            if len(label) >= self.thresholds.MIN_LABEL_LENGTH:
                entropy = EntropyCalculator.shannon_entropy(label)
                result.label_entropies[label] = entropy
                
                if entropy > result.max_label_entropy:
                    result.max_label_entropy = entropy
                
                if len(label) > result.max_label_length:
                    result.max_label_length = len(label)
        
        # Общая энтропия поддоменов
        subdomain = '.'.join(analysis_labels)
        result.entropy = EntropyCalculator.shannon_entropy(subdomain)
        
        # Дополнительные метрики
        result.consonant_ratio = PatternDetector.consonant_ratio(subdomain)
        result.digit_ratio = PatternDetector.digit_ratio(subdomain)
        
        # Детекция паттернов
        self._detect_patterns(result, analysis_labels, subdomain)
        
        # Вычисление confidence
        result.confidence = self._calculate_confidence(result)
        
        # Генерация сигналов
        self._generate_signals(result)
        
        return result
    
    def _detect_patterns(
        self,
        result: EntropyAnalysisResult,
        labels: list[str],
        subdomain: str
    ) -> None:
        """Детекция подозрительных паттернов."""
        
        # Проверка каждого label на encoded данные
        for label in labels:
            if PatternDetector.detect_hex(label):
                result.has_hex_pattern = True
            if PatternDetector.detect_base64(label):
                result.has_base64_pattern = True
            if PatternDetector.detect_base32(label):
                result.has_base64_pattern = True  # Объединяем с base64
        
        # Проверка на DGA
        if PatternDetector.detect_dga(subdomain):
            result.is_dga = True
        
        # Проверка на tunneling signatures
        if PatternDetector.detect_tunneling_signature(result.domain):
            result.is_tunneling = True
        
        # Эвристики для определения suspicious/tunneling
        self._apply_heuristics(result)
    
    def _apply_heuristics(self, result: EntropyAnalysisResult) -> None:
        """Применение эвристик для классификации."""
        
        # Критерии для suspicious
        suspicious_score = 0
        
        if result.max_label_entropy >= self.thresholds.SUSPICIOUS_MIN:
            suspicious_score += 2
        
        if result.max_label_length > self.thresholds.MAX_NORMAL_SUBDOMAIN_LENGTH:
            suspicious_score += 2
        
        if result.depth > self.thresholds.MAX_NORMAL_DEPTH:
            suspicious_score += 1
        
        if result.consonant_ratio > 0.75:
            suspicious_score += 1
        
        if result.digit_ratio > 0.3:
            suspicious_score += 1
        
        if result.has_hex_pattern or result.has_base64_pattern:
            suspicious_score += 2
        
        result.is_suspicious = suspicious_score >= 3
        
        # Критерии для tunneling (более строгие)
        tunneling_score = 0
        
        if result.max_label_entropy >= self.thresholds.ANOMALOUS_MIN:
            tunneling_score += 3
        
        if result.max_label_length > 40:
            tunneling_score += 3
        
        if result.has_hex_pattern and result.max_label_length > 30:
            tunneling_score += 2
        
        if result.has_base64_pattern and result.max_label_length > 25:
            tunneling_score += 2
        
        if result.depth > 5:
            tunneling_score += 1
        
        if tunneling_score >= 4:
            result.is_tunneling = True
    
    def _calculate_confidence(self, result: EntropyAnalysisResult) -> int:
        """Расчёт уверенности в результате."""
        base_confidence = 50
        
        if result.is_tunneling:
            # Высокая уверенность для tunneling
            confidence = 90
            if result.has_hex_pattern or result.has_base64_pattern:
                confidence = 95
        elif result.is_dga:
            confidence = 80
        elif result.is_suspicious:
            confidence = 70
        else:
            # Нормальный домен
            confidence = base_confidence
            if result.max_label_entropy < self.thresholds.NORMAL_MAX:
                confidence = 30  # Уверены, что нормальный
        
        return confidence
    
    def _entropy_to_weight(self, entropy: float) -> float:
        """Конвертация энтропии в вес сигнала."""
        if entropy >= self.thresholds.CRITICAL_MIN:
            return 0.95
        elif entropy >= self.thresholds.ANOMALOUS_MIN:
            return 0.8
        elif entropy >= self.thresholds.SUSPICIOUS_MIN:
            return 0.6
        elif entropy >= self.thresholds.NORMAL_MAX:
            return 0.4
        else:
            return 0.2  # Нормальная энтропия
    
    def _generate_signals(self, result: EntropyAnalysisResult) -> None:
        """Генерация текстовых сигналов."""
        if result.is_tunneling:
            result.signals.append(
                f"DNS tunneling suspected: entropy={result.max_label_entropy:.2f}, "
                f"max_length={result.max_label_length}"
            )
        
        if result.is_dga:
            result.signals.append(
                "DGA pattern detected in domain"
            )
        
        if result.has_hex_pattern:
            result.signals.append("Hex-encoded data detected in subdomain")
        
        if result.has_base64_pattern:
            result.signals.append("Base64-encoded data detected in subdomain")
        
        if result.max_label_entropy >= self.thresholds.SUSPICIOUS_MIN:
            result.signals.append(
                f"High entropy subdomain: {result.max_label_entropy:.2f} bits/char"
            )
        
        if result.depth > self.thresholds.MAX_NORMAL_DEPTH:
            result.signals.append(
                f"Unusual domain depth: {result.depth} levels"
            )
        
        if not result.signals:
            result.signals.append(
                f"Normal entropy: {result.entropy:.2f} bits/char"
            )
    
    def _build_summary(self, result: EntropyAnalysisResult) -> str:
        """Построение summary для Evidence."""
        if result.is_tunneling:
            return f"DNS tunneling detected (entropy: {result.max_label_entropy:.2f})"
        if result.is_dga:
            return f"DGA domain suspected (entropy: {result.entropy:.2f})"
        if result.is_suspicious:
            return f"Suspicious entropy pattern (entropy: {result.max_label_entropy:.2f})"
        return f"Normal domain entropy: {result.entropy:.2f}"


# ════════════════════════════════════════════════════════════════════════════════
# FREQUENCY ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class FrequencyAnalyzer:
    """
    Анализатор частоты DNS-запросов.
    
    Детектирует аномальную активность, характерную для туннелирования:
    - Высокая частота запросов к одному домену
    - Burst-паттерны (много запросов за короткий период)
    - Регулярные интервалы (beaconing)
    """
    
    def __init__(
        self,
        window_seconds: int = 60,
        max_requests_per_window: int = 100,
        burst_threshold: int = 20,
        burst_window_seconds: int = 5,
    ):
        self.window_seconds = window_seconds
        self.max_requests_per_window = max_requests_per_window
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        
        # Хранилище timestamps по доменам
        self._request_times: dict[str, list[float]] = {}
    
    def record_request(self, domain: str, timestamp: float) -> dict:
        """
        Запись запроса и анализ частоты.
        
        Returns:
            Результат анализа с флагами аномалий
        """
        import time
        
        # Извлекаем base domain (без поддоменов)
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        
        # Инициализация
        if base_domain not in self._request_times:
            self._request_times[base_domain] = []
        
        times = self._request_times[base_domain]
        current_time = timestamp or time.time()
        
        # Добавляем текущий запрос
        times.append(current_time)
        
        # Очищаем старые записи
        cutoff = current_time - self.window_seconds
        self._request_times[base_domain] = [t for t in times if t > cutoff]
        times = self._request_times[base_domain]

        # Bound memory on long-running installs: drop stale domains when the
        # tracking set grows large (entries not seen within the window).
        if len(self._request_times) > 20000:
            stale = [d for d, ts in self._request_times.items() if not ts or ts[-1] <= cutoff]
            for d in stale[:5000]:
                self._request_times.pop(d, None)
        
        # Анализ
        result = {
            "domain": base_domain,
            "requests_in_window": len(times),
            "is_high_frequency": len(times) > self.max_requests_per_window,
            "is_burst": False,
            "is_beaconing": False,
        }
        
        # Детекция burst
        if len(times) >= self.burst_threshold:
            burst_cutoff = current_time - self.burst_window_seconds
            burst_count = sum(1 for t in times if t > burst_cutoff)
            result["is_burst"] = burst_count >= self.burst_threshold
        
        # Детекция beaconing (регулярные интервалы)
        if len(times) >= 5:
            result["is_beaconing"] = self._detect_beaconing(times)
        
        return result
    
    def _detect_beaconing(self, times: list[float]) -> bool:
        """Детекция регулярных интервалов (beaconing)."""
        if len(times) < 5:
            return False
        
        # Вычисляем интервалы между запросами
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]
        
        if not intervals:
            return False
        
        # Среднее и стандартное отклонение
        avg_interval = sum(intervals) / len(intervals)
        
        if avg_interval < 0.5:  # Слишком частые запросы
            return False
        
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Низкое отклонение = регулярные интервалы = beaconing
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 0
        
        return coefficient_of_variation < 0.2  # CV < 20% = подозрительно регулярно
    
    def get_stats(self, domain: str) -> dict:
        """Статистика по домену."""
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        
        times = self._request_times.get(base_domain, [])
        
        return {
            "domain": base_domain,
            "total_requests": len(times),
            "window_seconds": self.window_seconds,
        }
    
    def clear(self) -> None:
        """Очистка данных."""
        self._request_times.clear()


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def calculate_entropy(text: str) -> float:
    """Быстрый расчёт энтропии Shannon."""
    return EntropyCalculator.shannon_entropy(text)


def is_high_entropy(domain: str, threshold: float = 4.5) -> bool:
    """Проверка на высокую энтропию."""
    # Анализируем только поддомены
    parts = domain.split('.')
    if len(parts) <= 2:
        return False
    
    subdomain = '.'.join(parts[:-2])
    entropy = calculate_entropy(subdomain)
    return entropy >= threshold


def detect_dns_tunneling(domain: str) -> bool:
    """Быстрая детекция DNS tunneling."""
    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_domain(domain)
    return result.is_tunneling


def detect_dga(domain: str) -> bool:
    """Быстрая детекция DGA."""
    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_domain(domain)
    return result.is_dga
