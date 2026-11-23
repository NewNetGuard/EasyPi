"""On-device learned model for connection-level ad/tracker behaviour.

The domain language model learns *name shape*.  This second level learns the
shape of the encrypted connections attributed to a domain: flow volume, byte
distribution, beacon/media ratios, transport mix, and upload/download balance.

Training is deliberately conservative.  Callers provide only high-confidence
labels (known ad/tracker infrastructure and protected navigation/allowlisted
traffic).  The model stores aggregate sufficient statistics, never domain names,
client addresses, packet payloads, or DNS history.

Inference is Gaussian naive Bayes with balanced class priors.  Its result is only
an extra ``ad-shaped`` signal for Ad-Genesis; the navigation, cross-site,
co-occurrence, CDN, and allowlist gates remain authoritative.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Iterable, Mapping

MODEL_FILENAME = "ml_flow_behavior_model.json"
MODEL_KIND = "flow_behavior_gaussian_nb"
MODEL_VERSION = 1
MIN_CLASS_SAMPLES = 20
AD_PROBABILITY_THRESHOLD = 0.95

FEATURE_NAMES = (
    "log_flows",
    "log_total_bytes",
    "log_mean_bytes",
    "log_max_bytes",
    "tiny_ratio",
    "media_ratio",
    "client_ratio",
    "udp_ratio",
    "download_ratio",
    "prism_coverage",
    "prism_causal_mean",
    "prism_log_burst_mean",
    "prism_log_session_flow_mean",
    "prism_blocked_dns_ratio",
    "prism_log_response_delay_mean",
    "prism_resumption_ratio",
    "prism_download_ratio",
)

# Features are log-scaled or bounded to [0, 1], so this prevents one nearly
# constant feature from dominating the whole likelihood through tiny variance.
VARIANCE_FLOOR = 0.0025
_lock = threading.Lock()


def _count(value) -> int:
    if isinstance(value, (set, frozenset, list, tuple, dict)):
        return len(value)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def flow_feature_vector(stats: Mapping) -> dict[str, float]:
    """Convert one domain's flow aggregate into stable, bounded features."""
    n_flows = max(1, _count(stats.get("n_flows")))
    total_bytes = max(0, _count(stats.get("total_bytes")))
    max_bytes = max(0, _count(stats.get("max_bytes")))
    n_tiny = min(n_flows, _count(stats.get("n_tiny")))
    n_media = min(n_flows, _count(stats.get("n_media")))
    n_clients = min(n_flows, _count(stats.get("clients")))
    n_udp = min(n_flows, _count(stats.get("n_udp")))
    up_bytes = max(0, _count(stats.get("up_bytes")))
    down_bytes = max(0, _count(stats.get("down_bytes")))
    directional_total = up_bytes + down_bytes
    prism_n = _count(stats.get("prism_n"))
    prism_client_bytes = max(0, _count(stats.get("prism_client_bytes")))
    prism_server_bytes = max(0, _count(stats.get("prism_server_bytes")))
    prism_directional_total = prism_client_bytes + prism_server_bytes

    def prism_mean(name: str) -> float:
        if not prism_n:
            return 0.0
        try:
            return max(0.0, float(stats.get(name, 0.0) or 0.0) / prism_n)
        except (TypeError, ValueError):
            return 0.0

    return {
        "log_flows": math.log1p(n_flows),
        "log_total_bytes": math.log1p(total_bytes),
        "log_mean_bytes": math.log1p(total_bytes / n_flows),
        "log_max_bytes": math.log1p(max_bytes),
        "tiny_ratio": n_tiny / n_flows,
        "media_ratio": n_media / n_flows,
        "client_ratio": n_clients / n_flows,
        "udp_ratio": n_udp / n_flows,
        "download_ratio": (down_bytes / directional_total) if directional_total else 0.5,
        "prism_coverage": min(1.0, prism_n / n_flows),
        "prism_causal_mean": min(1.0, prism_mean("prism_causal_sum")),
        "prism_log_burst_mean": math.log1p(prism_mean("prism_burst_sum")),
        "prism_log_session_flow_mean": math.log1p(prism_mean("prism_session_flow_sum")),
        "prism_blocked_dns_ratio": min(1.0, prism_mean("prism_blocked_dns_hits")),
        "prism_log_response_delay_mean": math.log1p(prism_mean("prism_response_delay_sum")),
        "prism_resumption_ratio": min(1.0, prism_mean("prism_resumption_hits")),
        "prism_download_ratio": (
            prism_server_bytes / prism_directional_total if prism_directional_total else 0.5
        ),
    }


def _empty_class() -> dict:
    return {
        "n": 0,
        "features": {name: {"mean": 0.0, "m2": 0.0} for name in FEATURE_NAMES},
    }


def _empty_model() -> dict:
    return {
        "kind": MODEL_KIND,
        "model_version": MODEL_VERSION,
        "updated_at": None,
        "feature_names": list(FEATURE_NAMES),
        "threshold": AD_PROBABILITY_THRESHOLD,
        "source_watermarks": {"flowgraph_timestamp": 0.0},
        "classes": {"ad": _empty_class(), "clean": _empty_class()},
    }


def _valid_model(data) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("kind") != MODEL_KIND or data.get("model_version") != MODEL_VERSION:
        return False
    if tuple(data.get("feature_names") or ()) != FEATURE_NAMES:
        return False
    classes = data.get("classes")
    if not isinstance(classes, dict):
        return False
    for label in ("ad", "clean"):
        state = classes.get(label)
        if not isinstance(state, dict) or not isinstance(state.get("features"), dict):
            return False
        try:
            if int(state.get("n", -1)) < 0:
                return False
            for name in FEATURE_NAMES:
                feat = state["features"][name]
                float(feat["mean"])
                float(feat["m2"])
        except (KeyError, TypeError, ValueError):
            return False
    return True


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if _valid_model(data):
            return data
    except (FileNotFoundError, OSError, ValueError, TypeError):
        pass
    return _empty_model()


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as output:
            json.dump(data, output, separators=(",", ":"), sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


class FlowBehaviorModel:
    """Immutable view of one learned model generation."""

    def __init__(self, data: dict | None = None):
        self._data = data if _valid_model(data) else _empty_model()

    @classmethod
    def load(cls, data_dir: str | Path) -> "FlowBehaviorModel":
        return cls(_load(Path(data_dir) / MODEL_FILENAME))

    @property
    def available(self) -> bool:
        classes = self._data["classes"]
        return all(int(classes[label]["n"]) >= MIN_CLASS_SAMPLES for label in ("ad", "clean"))

    @property
    def flowgraph_timestamp(self) -> float:
        try:
            return max(
                0.0,
                float((self._data.get("source_watermarks") or {}).get("flowgraph_timestamp", 0.0)),
            )
        except (TypeError, ValueError):
            return 0.0

    def probability(self, stats: Mapping) -> float | None:
        """Return P(ad-shaped) or ``None`` until both classes are mature."""
        if not self.available:
            return None
        vector = flow_feature_vector(stats)
        log_likelihood: dict[str, float] = {}
        for label in ("ad", "clean"):
            state = self._data["classes"][label]
            n = int(state["n"])
            score = 0.0  # balanced priors: behaviour, not class frequency, decides
            for name in FEATURE_NAMES:
                feature = state["features"][name]
                mean = float(feature["mean"])
                variance = max(float(feature["m2"]) / max(1, n - 1), VARIANCE_FLOOR)
                delta = vector[name] - mean
                score += -0.5 * (math.log(2.0 * math.pi * variance) + (delta * delta) / variance)
            log_likelihood[label] = score
        delta = max(-60.0, min(60.0, log_likelihood["clean"] - log_likelihood["ad"]))
        return round(1.0 / (1.0 + math.exp(delta)), 6)

    def is_ad_shaped(self, stats: Mapping, threshold: float = AD_PROBABILITY_THRESHOLD) -> bool:
        probability = self.probability(stats)
        return probability is not None and probability >= threshold

    def snapshot(self) -> dict:
        classes = self._data["classes"]
        return {
            "available": self.available,
            "kind": MODEL_KIND,
            "model_version": MODEL_VERSION,
            "updated_at": self._data.get("updated_at"),
            "ad_samples": int(classes["ad"]["n"]),
            "clean_samples": int(classes["clean"]["n"]),
            "min_class_samples": MIN_CLASS_SAMPLES,
            "threshold": AD_PROBABILITY_THRESHOLD,
            "features": len(FEATURE_NAMES),
            "flowgraph_timestamp": self.flowgraph_timestamp,
        }


def update_on_device(
    data_dir: str | Path,
    examples: Iterable[tuple[str, Mapping]],
    *,
    flowgraph_timestamp: float | None = None,
) -> FlowBehaviorModel:
    """Online-train from high-confidence ``(label, stats)`` observations.

    Only aggregate sufficient statistics are persisted.  Unknown labels are
    rejected instead of silently contaminating either class.
    """
    path = Path(data_dir) / MODEL_FILENAME
    with _lock:
        data = _load(path)
        changed = False
        learned = False
        for label, stats in examples:
            if label not in ("ad", "clean"):
                raise ValueError(f"unsupported flow behaviour label: {label}")
            vector = flow_feature_vector(stats)
            state = data["classes"][label]
            previous_n = int(state["n"])
            next_n = previous_n + 1
            for name, value in vector.items():
                feature = state["features"][name]
                mean = float(feature["mean"])
                delta = value - mean
                next_mean = mean + delta / next_n
                feature["mean"] = next_mean
                feature["m2"] = float(feature["m2"]) + delta * (value - next_mean)
            state["n"] = next_n
            changed = True
            learned = True
        if flowgraph_timestamp is not None:
            watermarks = data.setdefault("source_watermarks", {})
            previous = float(watermarks.get("flowgraph_timestamp", 0.0) or 0.0)
            if float(flowgraph_timestamp) > previous:
                watermarks["flowgraph_timestamp"] = float(flowgraph_timestamp)
                changed = True
        if changed:
            if learned:
                data["updated_at"] = time.time()
            _atomic_write(path, data)
        return FlowBehaviorModel(data)


def model_status(data_dir: str | Path) -> dict:
    """Read-only status suitable for the Guard AI API."""
    path = Path(data_dir) / MODEL_FILENAME
    status = FlowBehaviorModel.load(data_dir).snapshot()
    status["model_bytes"] = path.stat().st_size if path.exists() else 0
    return status
