from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import psutil


class SystemMonitor:
    """Collects basic system metrics using psutil and /sys data."""

    def __init__(self, net_sample_interval: float = 0.5) -> None:
        self.net_sample_interval = max(0.1, net_sample_interval)
        # Cached previous network counters for non-blocking rate sampling.
        # (monotonic_ts, bytes_recv, bytes_sent). The rate is derived from the
        # delta between successive snapshot() calls instead of sleeping, because
        # snapshot() runs on the asyncio event loop and a time.sleep() here
        # freezes the whole backend for the sample interval.
        self._prev_net: tuple[float, int, int] | None = None
        self._last_net_rate: Dict[str, int] = {"rx": 0, "tx": 0}

    def snapshot(self) -> Dict[str, Any]:
        """Return a point-in-time snapshot of system metrics."""
        cpu_usage = self._cpu_usage()
        ram_stats = self._ram_stats()
        disk_stats = self._disk_stats()
        net_stats = self._net_stats()
        temp_c = self._temperature()

        return {
            "cpu": {"usage": cpu_usage},
            "ram": ram_stats,
            "disk": disk_stats,
            "net": net_stats,
            "temp": {"celsius": temp_c},
            "timestamp": datetime.now(timezone.utc),
        }

    def _cpu_usage(self) -> float:
        try:
            usage = float(psutil.cpu_percent(interval=None))
        except Exception:
            usage = 0.0
        return max(0.0, min(usage, 100.0))

    def _ram_stats(self) -> Dict[str, int]:
        try:
            mem = psutil.virtual_memory()
            return {"used": int(mem.used), "total": int(mem.total)}
        except Exception:
            return {"used": 0, "total": 0}

    def _disk_stats(self) -> List[Dict[str, Any]]:
        disks: List[Dict[str, Any]] = []
        seen_mounts: set[str] = set()
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []

        for part in partitions:
            mount = part.mountpoint
            if mount in seen_mounts:
                continue
            seen_mounts.add(mount)
            try:
                usage = psutil.disk_usage(mount)
                disks.append(
                    {
                        "used": int(usage.used),
                        "total": int(usage.total),
                        "mount": mount,
                    }
                )
            except Exception:
                continue

        if not disks:
            disks.append({"used": 0, "total": 0, "mount": "/"})
        return disks

    def _net_stats(self) -> Dict[str, int]:
        # Non-blocking rate sampling: compute the byte rate from the delta
        # between successive calls instead of sleeping. snapshot() runs on the
        # asyncio loop, so a time.sleep() here would stall every request for the
        # sample interval (and compound across the monitoring WebSocket stream).
        try:
            now = time.monotonic()
            counters = psutil.net_io_counters()
            prev = self._prev_net
            self._prev_net = (now, int(counters.bytes_recv), int(counters.bytes_sent))

            if prev is None:
                # First sample: no baseline yet, report zero until the next call.
                return dict(self._last_net_rate)

            elapsed = now - prev[0]
            if elapsed < 0.05:
                # Calls too close together for a meaningful delta; reuse last rate.
                return dict(self._last_net_rate)

            rx_rate = max(0, int((counters.bytes_recv - prev[1]) / elapsed))
            tx_rate = max(0, int((counters.bytes_sent - prev[2]) / elapsed))
            self._last_net_rate = {"rx": rx_rate, "tx": tx_rate}
            return {"rx": rx_rate, "tx": tx_rate}
        except Exception:
            return dict(self._last_net_rate)

    def _temperature(self) -> float | None:
        temp = self._temperature_psutil()
        if temp is not None:
            return temp
        return self._temperature_sysfs()

    def _temperature_psutil(self) -> float | None:
        try:
            temps = psutil.sensors_temperatures()
        except (AttributeError, NotImplementedError):
            return None
        except Exception:
            return None

        if not temps:
            return None

        readings: List[float] = []
        for readings_list in temps.values():
            for entry in readings_list:
                current = getattr(entry, "current", None)
                if current is not None:
                    readings.append(float(current))

        if readings:
            return sum(readings) / len(readings)
        return None

    def _temperature_sysfs(self) -> float | None:
        thermal_base = Path("/sys/class/thermal")
        if not thermal_base.exists():
            return None

        for temp_file in thermal_base.glob("thermal_zone*/temp"):
            try:
                data = temp_file.read_text().strip()
                if not data:
                    continue
                value = float(data)
                if value > 1000:
                    value /= 1000.0
                return value
            except Exception:
                continue
        return None


__all__ = ["SystemMonitor"]
