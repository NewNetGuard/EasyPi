from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Optional

OS_RELEASE_PATH = Path("/etc/os-release")
CPUINFO_PATH = Path("/proc/cpuinfo")
DEVICE_TREE_MODEL = Path("/proc/device-tree/model")


def get_os_release() -> dict[str, str]:
    """Parse /etc/os-release into a dictionary."""
    if not OS_RELEASE_PATH.exists():
        return {}

    data: dict[str, str] = {}
    try:
        for line in OS_RELEASE_PATH.read_text(encoding="utf-8").splitlines():
            if not line or "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"')
    except (OSError, UnicodeDecodeError):
        return {}
    return data


def _cpuinfo_lines() -> Iterator[str]:
    try:
        with CPUINFO_PATH.open("r", encoding="utf-8") as cpuinfo:
            for line in cpuinfo:
                yield line.strip()
    except (OSError, UnicodeDecodeError):
        return


def is_raspberry_pi() -> bool:
    """Best-effort detection of Raspberry Pi hardware."""
    os_release = get_os_release()
    if os_release.get("ID") in {"raspbian", "raspberrypi"}:
        return True
    if "raspbian" in os_release.get("ID_LIKE", ""):
        return True

    for line in _cpuinfo_lines():
        lower = line.lower()
        if lower.startswith("hardware") and "bcm" in lower:
            return True
        if lower.startswith("model") and "raspberry pi" in lower:
            return True

    try:
        model = DEVICE_TREE_MODEL.read_text(encoding="utf-8").strip().lower()
        if "raspberry" in model:
            return True
    except (OSError, UnicodeDecodeError):
        pass

    return False


def get_pi_model() -> Optional[str]:
    """Return Raspberry Pi model name when possible."""
    for line in _cpuinfo_lines():
        lower = line.lower()
        if lower.startswith("model"):
            _, _, value = line.partition(":")
            result = value.strip()
            if result:
                return result

    try:
        model = DEVICE_TREE_MODEL.read_text(encoding="utf-8").strip()
        if model:
            return model
    except (OSError, UnicodeDecodeError):
        pass

    return None


__all__ = ["get_os_release", "is_raspberry_pi", "get_pi_model"]
