"""Domain-agnostic sequence vectors and separation checks for TLS metadata."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping


SEQUENCE_WINDOW_SECONDS = 5.0
TEMPORAL_BIN_SECONDS = 0.25
HASH_BUCKETS = 32
RECORD_TEMPORAL_BIN_SECONDS = 0.05
MIN_SAMPLES_PER_LABEL = 3
MIN_SEPARATION_MARGIN = 0.08
MIN_MOTIF_MARGIN = 0.02
MIN_MOTIF_RATIO = 1.5
MAX_MOTIF_WITHIN_DISTANCE = 0.06
_BIN_FEATURES = 6


@dataclass(frozen=True)
class TlsSequenceVector:
    values: tuple[float, ...]
    exchange_count: int
    flow_count: int
    duration_ms: int

    def distance(self, other: "TlsSequenceVector") -> float:
        if len(self.values) != len(other.values):
            raise ValueError("sequence vectors must have equal dimensions")
        dot = sum(left * right for left, right in zip(self.values, other.values))
        left_norm = math.sqrt(sum(value * value for value in self.values))
        right_norm = math.sqrt(sum(value * value for value in other.values))
        if not left_norm and not right_norm:
            return 0.0
        if not left_norm or not right_norm:
            return 1.0
        similarity = max(-1.0, min(1.0, dot / (left_norm * right_norm)))
        return 1.0 - similarity


@dataclass(frozen=True)
class SequenceSample:
    label: str
    vector: TlsSequenceVector


@dataclass(frozen=True)
class TlsSequenceBag:
    windows: tuple[TlsSequenceVector, ...]
    window_starts_ms: tuple[int, ...]


@dataclass(frozen=True)
class SharedMotifEvaluation:
    positive_bag_count: int
    negative_bag_count: int
    candidate_window_count: int
    max_positive_distance: float
    min_negative_distance: float
    separation_margin: float
    separation_ratio: float
    approved_for_canary: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "event": "tls_shared_motif_evaluation",
            "positive_bag_count": self.positive_bag_count,
            "negative_bag_count": self.negative_bag_count,
            "candidate_window_count": self.candidate_window_count,
            "max_positive_distance": self.max_positive_distance,
            "min_negative_distance": self.min_negative_distance,
            "separation_margin": self.separation_margin,
            "separation_ratio": self.separation_ratio,
            "approved_for_canary": self.approved_for_canary,
            "reasons": list(self.reasons),
            "mode": "shadow",
        }


@dataclass(frozen=True)
class SequenceEvaluation:
    sample_count: int
    label_counts: tuple[tuple[str, int], ...]
    nearest_label_accuracy: float
    max_within_distance: float
    min_between_distance: float
    separation_margin: float
    approved_for_canary: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "event": "tls_sequence_evaluation",
            "sample_count": self.sample_count,
            "label_counts": dict(self.label_counts),
            "nearest_label_accuracy": self.nearest_label_accuracy,
            "max_within_distance": self.max_within_distance,
            "min_between_distance": self.min_between_distance,
            "separation_margin": self.separation_margin,
            "approved_for_canary": self.approved_for_canary,
            "reasons": list(self.reasons),
            "mode": "shadow",
        }


def vectorize_tls_sequence(
    events: Iterable[Mapping[str, object]],
    *,
    anchor_timestamp: float | None = None,
    window_seconds: float = SEQUENCE_WINDOW_SECONDS,
) -> TlsSequenceVector:
    """Project a bounded exchange window without retaining names or payloads."""

    if not 0.5 <= window_seconds <= 30.0:
        raise ValueError("sequence window must be between 0.5s and 30s")
    observations = sorted(
        (
            event
            for event in events
            if event.get("event") == "tls_exchange_observation"
            and _number(event.get("timestamp")) is not None
        ),
        key=lambda event: float(event["timestamp"]),
    )
    temporal_bin_count = math.ceil(window_seconds / TEMPORAL_BIN_SECONDS)
    temporal = [[0.0] * _BIN_FEATURES for _ in range(temporal_bin_count)]
    server_buckets = [0.0] * HASH_BUCKETS
    fingerprint_buckets = [0.0] * HASH_BUCKETS
    if not observations:
        values = tuple(value for bucket in temporal for value in bucket)
        return TlsSequenceVector(
            values=values + tuple(server_buckets) + tuple(fingerprint_buckets),
            exchange_count=0,
            flow_count=0,
            duration_ms=0,
        )

    anchor = (
        float(observations[0]["timestamp"])
        if anchor_timestamp is None
        else anchor_timestamp
    )
    end = anchor + window_seconds
    selected = [
        event
        for event in observations
        if anchor <= float(event["timestamp"]) < end
    ]
    flows: set[str] = set()
    server_names: set[str] = set()
    fingerprints: set[str] = set()
    last_timestamp = anchor

    for event in selected:
        timestamp = float(event["timestamp"])
        index = min(
            temporal_bin_count - 1,
            int((timestamp - anchor) / TEMPORAL_BIN_SECONDS),
        )
        bucket = temporal[index]
        request_bytes = _nonnegative(event.get("request_bytes"))
        response_bytes = _nonnegative(event.get("response_bytes"))
        request_records = _nonnegative(event.get("request_record_count"))
        response_records = _nonnegative(event.get("response_record_count"))
        response_delay = min(
            5_000.0,
            _nonnegative(event.get("first_response_delay_ms")),
        )
        bucket[0] += request_bytes
        bucket[1] += response_bytes
        bucket[2] += request_records
        bucket[3] += response_records
        bucket[4] += response_delay
        bucket[5] += 1.0

        flow = str(event.get("flow") or "")
        server_name = str(event.get("server_name") or "")
        fingerprint = str(event.get("tls_fingerprint") or "")
        if flow:
            flows.add(flow)
        if server_name:
            server_names.add(server_name)
            server_buckets[_hash_bucket(server_name)] += math.log1p(response_bytes)
        if fingerprint:
            fingerprints.add(fingerprint)
            fingerprint_buckets[_hash_bucket(fingerprint)] += 1.0
        last_timestamp = timestamp

    encoded_temporal: list[float] = []
    for bucket in temporal:
        exchanges = bucket[5]
        encoded_temporal.extend(
            (
                math.log1p(bucket[0]),
                math.log1p(bucket[1]),
                math.log1p(bucket[2]),
                math.log1p(bucket[3]),
                (bucket[4] / exchanges / 1_000.0) if exchanges else 0.0,
                math.log1p(exchanges),
            )
        )
    values = (
        tuple(encoded_temporal)
        + tuple(server_buckets)
        + tuple(math.log1p(value) for value in fingerprint_buckets)
        + (
            math.log1p(len(selected)),
            math.log1p(len(flows)),
            math.log1p(len(server_names)),
            math.log1p(len(fingerprints)),
        )
    )
    duration_ms = max(0, round((last_timestamp - anchor) * 1_000)) if selected else 0
    return TlsSequenceVector(
        values=values,
        exchange_count=len(selected),
        flow_count=len(flows),
        duration_ms=duration_ms,
    )


def vectorize_tls_record_sequences(
    events: Iterable[Mapping[str, object]],
    *,
    anchor_timestamp: float | None = None,
    window_seconds: float = SEQUENCE_WINDOW_SECONDS,
) -> TlsSequenceVector:
    """Project bounded TLS record direction, size and timing metadata."""

    if not 0.5 <= window_seconds <= 30.0:
        raise ValueError("sequence window must be between 0.5s and 30s")
    observations = sorted(
        (
            event
            for event in events
            if event.get("event") == "tls_record_sequence_observation"
            and _number(event.get("timestamp")) is not None
        ),
        key=lambda event: float(event["timestamp"]),
    )
    temporal_bin_count = math.ceil(window_seconds / RECORD_TEMPORAL_BIN_SECONDS)
    temporal = [[0.0] * 4 for _ in range(temporal_bin_count)]
    server_buckets = [0.0] * HASH_BUCKETS
    fingerprint_buckets = [0.0] * HASH_BUCKETS
    if not observations:
        values = tuple(value for bucket in temporal for value in bucket)
        return TlsSequenceVector(
            values=values + tuple(server_buckets) + tuple(fingerprint_buckets),
            exchange_count=0,
            flow_count=0,
            duration_ms=0,
        )

    anchor = (
        float(observations[0]["timestamp"])
        if anchor_timestamp is None
        else anchor_timestamp
    )
    end = anchor + window_seconds
    flows: set[str] = set()
    server_names: set[str] = set()
    fingerprints: set[str] = set()
    record_count = 0
    last_timestamp = anchor

    for event in observations:
        started_at = float(event["timestamp"])
        directions = event.get("record_directions")
        lengths = event.get("record_lengths")
        intervals = event.get("interarrival_ms")
        if not (
            isinstance(directions, list)
            and isinstance(lengths, list)
            and isinstance(intervals, list)
        ):
            continue
        point_count = min(len(directions), len(lengths), len(intervals), 96)
        elapsed_ms = 0.0
        server_name = str(event.get("server_name") or "")
        fingerprint = str(event.get("tls_fingerprint") or "")
        flow = str(event.get("flow") or "")
        for index in range(point_count):
            elapsed_ms += _nonnegative(intervals[index])
            timestamp = started_at + (elapsed_ms / 1_000.0)
            if timestamp < anchor or timestamp >= end:
                continue
            length = _nonnegative(lengths[index])
            direction = str(directions[index])
            temporal_index = min(
                temporal_bin_count - 1,
                int((timestamp - anchor) / RECORD_TEMPORAL_BIN_SECONDS),
            )
            bucket = temporal[temporal_index]
            if direction == "client_to_server":
                bucket[0] += length
                bucket[2] += 1.0
            elif direction == "server_to_client":
                bucket[1] += length
                bucket[3] += 1.0
                if server_name:
                    server_buckets[_hash_bucket(server_name)] += math.log1p(length)
            else:
                continue
            if fingerprint:
                fingerprint_buckets[_hash_bucket(fingerprint)] += 1.0
            record_count += 1
            last_timestamp = max(last_timestamp, timestamp)
        if flow:
            flows.add(flow)
        if server_name:
            server_names.add(server_name)
        if fingerprint:
            fingerprints.add(fingerprint)

    encoded_temporal = tuple(
        encoded
        for bucket in temporal
        for encoded in (
            math.log1p(bucket[0]),
            math.log1p(bucket[1]),
            math.log1p(bucket[2]),
            math.log1p(bucket[3]),
        )
    )
    values = (
        encoded_temporal
        + tuple(server_buckets)
        + tuple(math.log1p(value) for value in fingerprint_buckets)
        + (
            math.log1p(record_count),
            math.log1p(len(flows)),
            math.log1p(len(server_names)),
            math.log1p(len(fingerprints)),
        )
    )
    return TlsSequenceVector(
        values=values,
        exchange_count=record_count,
        flow_count=len(flows),
        duration_ms=max(0, round((last_timestamp - anchor) * 1_000)),
    )


def vectorize_tls_record_bag(
    events: Iterable[Mapping[str, object]],
    *,
    anchor_timestamp: float,
    span_seconds: float = 10.0,
    window_seconds: float = 1.0,
    stride_seconds: float = 0.25,
) -> TlsSequenceBag:
    """Build overlapping record windows so delayed motifs remain comparable."""

    if not 1.0 <= span_seconds <= 30.0:
        raise ValueError("bag span must be between 1s and 30s")
    if not 0.5 <= window_seconds <= min(5.0, span_seconds):
        raise ValueError("bag window must be between 0.5s and 5s")
    if not 0.05 <= stride_seconds <= window_seconds:
        raise ValueError("bag stride must be between 50ms and the window size")
    event_list = list(events)
    windows: list[TlsSequenceVector] = []
    starts_ms: list[int] = []
    offset = 0.0
    last_offset = span_seconds - window_seconds
    while offset <= last_offset + 1e-9:
        vector = vectorize_tls_record_sequences(
            event_list,
            anchor_timestamp=anchor_timestamp + offset,
            window_seconds=window_seconds,
        )
        if vector.exchange_count:
            windows.append(vector)
            starts_ms.append(round(offset * 1_000))
        offset += stride_seconds
    return TlsSequenceBag(tuple(windows), tuple(starts_ms))


def evaluate_shared_motif(
    positive_bags: Iterable[TlsSequenceBag],
    negative_bags: Iterable[TlsSequenceBag],
) -> SharedMotifEvaluation:
    """Find a repeated positive subsequence while blocking negative nearest hits."""

    positives = list(positive_bags)
    negatives = list(negative_bags)
    reasons: list[str] = []
    if len(positives) < MIN_SAMPLES_PER_LABEL:
        reasons.append("insufficient_positive_bags")
    if len(negatives) < MIN_SAMPLES_PER_LABEL:
        reasons.append("insufficient_negative_bags")
    if any(not bag.windows for bag in positives):
        reasons.append("empty_positive_bag")
    if any(not bag.windows for bag in negatives):
        reasons.append("empty_negative_bag")

    candidates: list[tuple[float, float, float, float]] = []
    for source_index, source in enumerate(positives):
        for candidate in source.windows:
            positive_distances: list[float] = []
            for target_index, target in enumerate(positives):
                if target_index == source_index:
                    continue
                if target.windows:
                    positive_distances.append(
                        min(candidate.distance(window) for window in target.windows)
                    )
            negative_distances = [
                candidate.distance(window)
                for bag in negatives
                for window in bag.windows
            ]
            if not positive_distances or not negative_distances:
                continue
            max_positive = max(positive_distances)
            min_negative = min(negative_distances)
            margin = min_negative - max_positive
            ratio = min_negative / max(max_positive, 1e-9)
            candidates.append((margin, ratio, max_positive, min_negative))

    if candidates:
        margin, ratio, max_positive, min_negative = max(
            candidates,
            key=lambda item: (item[0], item[1], -item[2]),
        )
    else:
        margin, ratio, max_positive, min_negative = -1.0, 0.0, 1.0, 0.0
        reasons.append("no_shared_positive_motif")
    if max_positive > MAX_MOTIF_WITHIN_DISTANCE:
        reasons.append("no_repeatable_positive_motif")
    if margin < MIN_MOTIF_MARGIN or ratio < MIN_MOTIF_RATIO:
        reasons.append("false_nearest_not_blocked")
    return SharedMotifEvaluation(
        positive_bag_count=len(positives),
        negative_bag_count=len(negatives),
        candidate_window_count=sum(len(bag.windows) for bag in positives),
        max_positive_distance=round(max_positive, 6),
        min_negative_distance=round(min_negative, 6),
        separation_margin=round(margin, 6),
        separation_ratio=round(ratio, 6),
        approved_for_canary=not reasons,
        reasons=tuple(reasons),
    )


def evaluate_sequence_separation(
    samples: Iterable[SequenceSample],
) -> SequenceEvaluation:
    """Require repeatable leave-one-out separation before any canary use."""

    sample_list = list(samples)
    counts = Counter(sample.label for sample in sample_list)
    reasons: list[str] = []
    if len(counts) < 2:
        reasons.append("at_least_two_labels_required")
    for label, count in sorted(counts.items()):
        if count < MIN_SAMPLES_PER_LABEL:
            reasons.append(f"insufficient_samples:{label}")

    within_distances: list[float] = []
    between_distances: list[float] = []
    nearest_correct = 0
    nearest_total = 0
    for index, sample in enumerate(sample_list):
        candidates: list[tuple[float, str]] = []
        for other_index, other in enumerate(sample_list):
            if index == other_index:
                continue
            distance = sample.vector.distance(other.vector)
            candidates.append((distance, other.label))
            if sample.label == other.label:
                within_distances.append(distance)
            else:
                between_distances.append(distance)
        if candidates:
            nearest_total += 1
            nearest_correct += min(candidates)[1] == sample.label

    accuracy = nearest_correct / nearest_total if nearest_total else 0.0
    max_within = max(within_distances, default=1.0)
    min_between = min(between_distances, default=0.0)
    margin = min_between - max_within
    if accuracy < 1.0:
        reasons.append("false_nearest_not_blocked")
    if margin < MIN_SEPARATION_MARGIN:
        reasons.append("insufficient_separation_margin")
    return SequenceEvaluation(
        sample_count=len(sample_list),
        label_counts=tuple(sorted(counts.items())),
        nearest_label_accuracy=round(accuracy, 6),
        max_within_distance=round(max_within, 6),
        min_between_distance=round(min_between, 6),
        separation_margin=round(margin, 6),
        approved_for_canary=not reasons,
        reasons=tuple(reasons),
    )


def _hash_bucket(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", errors="ignore"),
        digest_size=8,
        person=b"prismseq",
    ).digest()
    return int.from_bytes(digest, "big") % HASH_BUCKETS


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def _nonnegative(value: object) -> float:
    number = _number(value)
    return max(0.0, number) if number is not None else 0.0


__all__ = [
    "SequenceEvaluation",
    "SequenceSample",
    "SharedMotifEvaluation",
    "TlsSequenceBag",
    "TlsSequenceVector",
    "evaluate_shared_motif",
    "evaluate_sequence_separation",
    "vectorize_tls_record_bag",
    "vectorize_tls_record_sequences",
    "vectorize_tls_sequence",
]
