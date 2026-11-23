"""Default-off supervisor for nonblocking observation copies; no traffic verdicts."""

import base64
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from .models import Endpoint, Provenance
import json
import math
import os
import signal
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


@dataclass(frozen=True)
class ShadowLimits:
    memory_bytes: int = 512 * 1024 * 1024
    rss_trip_bytes: int = 192 * 1024 * 1024
    cpu_seconds: int = 300
    cpu_percent: int = 25
    heartbeat_seconds: float = 3
    startup_seconds: float = 20
    overload_seconds: float = 2
    max_input: int = 64
    max_events: int = 128

    def __post_init__(self):
        for name in (
            "memory_bytes",
            "rss_trip_bytes",
            "cpu_seconds",
            "cpu_percent",
            "max_input",
            "max_events",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError("invalid integer limit")
        if (
            self.memory_bytes < 128 * 1024 * 1024
            or self.rss_trip_bytes >= self.memory_bytes
            or self.cpu_percent > 100
        ):
            raise ValueError("invalid resource budget")
        for value in (
            self.heartbeat_seconds,
            self.startup_seconds,
            self.overload_seconds,
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("invalid timeout")


class ShadowSupervisor:
    """Callers may ignore a rejected observation copy and always continue traffic.

    Start/restart are explicit administrative operations. No automatic restart
    loop, secret cache, inherited session, or filtering verdict is provided.
    """

    def __init__(self, limits=None, enable_file=None):
        self.limits = limits or ShadowLimits()
        self.enable_file = Path(enable_file) if enable_file else None
        self.lock = threading.RLock()
        self.process = None
        self.enabled = False
        self.reason = "disabled"
        self.events = deque(maxlen=self.limits.max_events)
        self.flows = OrderedDict()
        self.generation = 0
        self.stop_event = threading.Event()
        self.input = None
        self.threads = []
        self.last_heartbeat = 0
        self.last_sample = None
        self.overload_since = None
        self.os_limits = None
        self.event_drops = 0

    def _event(self, kind, **values):
        if len(self.events) == self.events.maxlen:
            self.event_drops += 1
        self.events.append(dict(type=kind, generation=self.generation, **values))

    def start(self):
        with self.lock:
            if self.enabled:
                return False
            if self.enable_file and not self.enable_file.is_file():
                self.reason = "switch_off"
                return False
            if self.process is not None:
                self.close()
            self.generation += 1
            self.flows.clear()
            self.input = queue.Queue(maxsize=self.limits.max_input)
            self.stop_event = threading.Event()
            self.last_sample = None
            self.overload_since = None
            self.os_limits = None
            command = [
                sys.executable,
                "-B",
                "-u",
                "-m",
                "prism_tls_bridge.shadow_child",
                "--memory",
                str(self.limits.memory_bytes),
                "--cpu-seconds",
                str(self.limits.cpu_seconds),
                "--cpu-percent",
                str(self.limits.cpu_percent),
            ]
            if getattr(sys, "frozen", False):
                command = [sys.executable, "--prism-tls-child"] + command[5:]
            environment = os.environ.copy()
            if getattr(sys, "frozen", False):
                environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            try:
                self.process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    start_new_session=os.name == "posix",
                )
            except OSError:
                self.reason = "spawn_failed"
                self._event("disabled", reason=self.reason)
                return False
            self.enabled = True
            self.reason = "starting"
            self.last_heartbeat = time.monotonic()
            generation = self.generation
            process = self.process
            inbox = self.input
            stop = self.stop_event
            self.threads = [
                threading.Thread(
                    target=fn, args=(generation, process, inbox, stop), daemon=True
                )
                for fn in (self._write, self._read, self._monitor)
            ]
            for thread in self.threads:
                thread.start()
            return True

    def _write(self, generation, process, inbox, stop):
        try:
            while not stop.is_set():
                try:
                    raw = inbox.get(timeout=0.05)
                except queue.Empty:
                    continue
                process.stdin.write(raw)
                process.stdin.flush()
        except (OSError, ValueError):
            self.disable("input_channel_failed", generation)

    def _read(self, generation, process, inbox, stop):
        try:
            while not stop.is_set():
                raw = process.stdout.readline(32769)
                if not raw:
                    break
                if len(raw) > 32768:
                    raise ValueError("diagnostic size limit")
                event = json.loads(raw)
                with self.lock:
                    if generation != self.generation or not self.enabled:
                        return
                    kind = event.get("type")
                    if kind == "ready":
                        self.os_limits = event["os_limits"]
                        # Frozen startup can legitimately exceed the running
                        # heartbeat budget. Begin that budget at child ready.
                        self.last_heartbeat = time.monotonic()
                        self.reason = "observing"
                        self._event("ready", os_limits=self.os_limits)
                    elif kind == "heartbeat":
                        self._health(event)
                    elif kind == "headers":
                        flow = event.get("flow")
                        if flow in self.flows and not self.flows[flow].get("lost"):
                            self.flows[flow]["state"] = "Decrypted"
                            self._event(
                                "headers",
                                flow=flow,
                                protocol=event.get("protocol"),
                                state="Decrypted",
                                coverage="request_headers_only",
                            )
                    elif kind == "admission":
                        if event.get("flow") in self.flows and not event.get(
                            "accepted"
                        ):
                            self.flows.pop(event["flow"])
                    elif kind == "unavailable":
                        self.disable("child_unavailable", generation)
            if not stop.is_set():
                self.disable("process_exited", generation)
        except Exception:
            self.disable("invalid_diagnostic", generation)

    def _health(self, event):
        now = time.monotonic()
        self.last_heartbeat = now
        rss = event["rss"]
        cpu = event["cpu"]
        if (
            not isinstance(rss, int)
            or not isinstance(cpu, (float, int))
            or not math.isfinite(cpu)
        ):
            raise ValueError("invalid health sample")
        if rss > self.limits.rss_trip_bytes:
            self.disable("rss_overload")
            return
        if self.last_sample:
            previous_time, previous_cpu = self.last_sample
            rate = (cpu - previous_cpu) / max(0.001, now - previous_time) * 100
            if rate > self.limits.cpu_percent:
                if self.overload_since is None:
                    self.overload_since = now
                elif now - self.overload_since >= self.limits.overload_seconds:
                    self.disable("cpu_overload")
                    return
            else:
                self.overload_since = None
        self.last_sample = (now, cpu)
        for status in event.get("statuses", []):
            flow = status.get("flow")
            if flow in self.flows and not self.flows[flow].get("lost"):
                previous = (self.flows[flow]["state"], self.flows[flow]["reason"])
                self.flows[flow]["state"] = status["state"]
                self.flows[flow]["reason"] = status["reason"]
                if previous != (status["state"], status["reason"]):
                    self._event(
                        "visibility",
                        flow=flow,
                        state=status["state"],
                        reason=status["reason"],
                        diagnostic=status.get("diagnostic", "missing_key"),
                    )
        self._event(
            "health",
            rss=rss,
            cpu=cpu,
            active=event["bridge"]["active"],
            queue_drops=event["worker"]["dropped"],
            key_rejected=event["bridge"].get("key_rejected", 0),
            key_store_full=event["bridge"].get("key_store_full", 0),
            invalid_secret=event["bridge"].get("invalid_secret", 0),
        )

    def _monitor(self, generation, process, inbox, stop):
        while not stop.wait(0.05):
            with self.lock:
                if generation != self.generation:
                    return
                if self.enable_file and not self.enable_file.is_file():
                    self.disable("switch_off", generation)
                    return
                if process.poll() is not None:
                    self.disable("process_exited", generation)
                    return
                timeout = (
                    self.limits.heartbeat_seconds
                    if self.os_limits
                    else self.limits.startup_seconds
                )
                if time.monotonic() - self.last_heartbeat > timeout:
                    self.disable("heartbeat_timeout", generation)
                    return

    def _send(self, value):
        with self.lock:
            if not self.enabled:
                return False
            raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
            if len(raw) > 100000:
                return False
            try:
                self.input.put_nowait(raw)
                return True
            except queue.Full:
                self.disable("input_overflow")
                return False

    def open_flow(
        self, flow, transport, provenance, client, server, key_session_id=None
    ):
        with self.lock:
            if not self.enabled:
                return False
            if (
                not isinstance(flow, str)
                or not 1 <= len(flow) <= 128
                or flow in self.flows
                or len(self.flows) >= 16
            ):
                return False
            if (
                not isinstance(provenance, Provenance)
                or not provenance.opt_in
                or not isinstance(client, Endpoint)
                or not isinstance(server, Endpoint)
                or transport not in {"tcp", "quic"}
            ):
                return False
            self.flows[flow] = dict(
                state="Unknown",
                reason="awaiting_capture",
                capture_point=provenance.capture_point,
                lost=False,
            )
            return self._send(
                dict(
                    type="open",
                    flow=flow,
                    transport=transport,
                    provenance=asdict(provenance),
                    client=asdict(client),
                    server=asdict(server),
                    key_session_id=key_session_id,
                )
            )

    def submit_packet(self, flow, packet, capture_point):
        with self.lock:
            if (
                flow not in self.flows
                or self.flows[flow]["lost"]
                or not isinstance(packet, bytes)
                or len(packet) > 65535
            ):
                return False
            return self._send(
                dict(
                    type="packet",
                    flow=flow,
                    packet=base64.b64encode(packet).decode(),
                    capture_point=capture_point,
                )
            )

    def submit_key(self, flow, line, provenance):
        with self.lock:
            if not isinstance(provenance, Provenance):
                return False
            if (
                flow not in self.flows
                or self.flows[flow]["lost"]
                or not isinstance(line, str)
                or len(line) > 1024
            ):
                return False
            return self._send(
                dict(type="key", flow=flow, line=line, provenance=asdict(provenance))
            )

    def capture_loss(self, capture_point, count=1):
        with self.lock:
            if not self.enabled:
                return
            for flow, status in self.flows.items():
                if status["capture_point"] == capture_point:
                    status.update(state="Unknown", reason="capture_loss", lost=True)
                    self._send(
                        dict(type="loss", flow=flow, capture_point=capture_point)
                    )
            self._event("capture_loss", count=count, state="Unknown")

    def close_flow(self, flow):
        with self.lock:
            if flow in self.flows:
                self._send(dict(type="close", flow=flow))
                self.flows.pop(flow)

    def status(self, flow):
        with self.lock:
            if not self.enabled:
                return dict(
                    state="Unknown", reason=self.reason, generation=self.generation
                )
            return dict(
                self.flows.get(flow, dict(state="Unknown", reason="unregistered")),
                generation=self.generation,
            )

    def disable(self, reason="operator_disabled", generation=None):
        with self.lock:
            if generation is not None and generation != self.generation:
                return
            if not self.enabled:
                return
            self.enabled = False
            self.reason = reason
            self.stop_event.set()
            for status in self.flows.values():
                status.update(state="Unknown", reason=reason, lost=True)
            if self.input:
                while True:
                    try:
                        self.input.get_nowait()
                    except queue.Empty:
                        break
            process = self.process
            if process:
                try:
                    # A one-file bootloader may already have exited while its
                    # decoder is still alive. Kill the group even in that case.
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    elif process.poll() is None:
                        process.kill()
                except OSError:
                    pass
            self._event("disabled", reason=reason, state="Unknown")

    def drain_events(self):
        with self.lock:
            events = list(self.events)
            self.events.clear()
            return events

    def close(self):
        self.disable()
        process = self.process
        if process:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdin, process.stdout):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in self.threads:
            if thread is not threading.current_thread():
                thread.join(timeout=0.2)
