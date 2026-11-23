"""Explicitly opted-in Linux live capture into the independent Shadow supervisor.

Invoke through an authenticated SSH channel or a private local pipe. Never
attach its stdin to an unauthenticated network listener. No production service
is configured or restarted by this command.
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from .channel import KeyReceiver
from .models import Endpoint, Provenance
from .pcap_live import LiveCapture, ShadowCapturePump
from .shadow import ShadowSupervisor


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--interface", required=True)
    p.add_argument("--client-ip", required=True)
    p.add_argument("--client-port", type=int, required=True)
    p.add_argument("--server-ip", required=True)
    p.add_argument("--server-port", type=int, required=True)
    p.add_argument("--transport", choices=("tcp", "quic"), required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--key-session-id")
    p.add_argument("--enable-file", type=Path, required=True)
    p.add_argument("--seconds", type=int, default=300)
    a = p.parse_args()
    if (
        not sys.platform.startswith("linux")
        or not re.fullmatch(r"[0-9a-f]{32}", a.session)
        or (
            a.key_session_id is not None
            and re.fullmatch(r"[0-9a-fA-F]{64}", a.key_session_id) is None
        )
        or not 1 <= a.seconds <= 600
    ):
        p.error("bounded Linux session required")
    if os.geteuid() == 0:
        p.error("run as a dedicated non-root capture-capable account")
    switch = a.enable_file.stat()
    if (
        not a.enable_file.is_file()
        or switch.st_uid != os.getuid()
        or switch.st_mode & 0o077
    ):
        p.error("owner-only enable file required")
    client = Endpoint(a.client_ip, a.client_port)
    server = Endpoint(a.server_ip, a.server_port)
    provenance = Provenance(
        "managed-shadow-client",
        "shadow-pcap",
        "authenticated-collector",
        "endpoint-origin",
        True,
    )
    scope = dict(
        endpoint_id=provenance.endpoint_id,
        capture_point=provenance.capture_point,
        key_source=provenance.key_source,
        tls_leg=provenance.tls_leg,
        opt_in=True,
        transport=a.transport,
        client=client.__dict__,
        server=server.__dict__,
        interface=a.interface,
    )
    if a.key_session_id:
        a.key_session_id = a.key_session_id.lower()
        scope["key_session_id"] = a.key_session_id
    receiver = KeyReceiver(a.session, scope)
    shadow = ShadowSupervisor(enable_file=a.enable_file)
    stop = threading.Event()
    grant = threading.Event()
    output_lock = threading.Lock()

    def emit(value):
        with output_lock:
            print(json.dumps(value, separators=(",", ":")), flush=True)

    def keys():
        try:
            while not stop.is_set():
                raw = sys.stdin.buffer.readline(2049)
                if not raw:
                    break
                line = receiver.receive(raw.decode("ascii"))
                if line is None:
                    grant.set()
                elif not shadow.submit_key(a.session, line, provenance):
                    break
        except Exception:
            shadow.disable("key_channel_rejected")
        finally:
            stop.set()
            receiver.close()

    capture = None
    pump = None
    submitted_packets = 0
    try:
        # Capture opens only with already assigned OS permissions. The program
        # never escalates privileges or grants file capabilities to Python.
        capture = LiveCapture(a.interface, client, server, a.transport)
        if not shadow.start():
            raise RuntimeError("shadow start refused")
        deadline = time.monotonic() + shadow.limits.startup_seconds
        while (
            shadow.os_limits is None and shadow.enabled and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        if shadow.os_limits is None:
            raise RuntimeError("resource isolation failed")
        if not shadow.open_flow(
            a.session,
            a.transport,
            provenance,
            client,
            server,
            key_session_id=a.key_session_id,
        ):
            raise RuntimeError("flow admission failed")
        threading.Thread(target=keys, daemon=True).start()
        emit(dict(type="shadow_ready", session=a.session, os_limits=shadow.os_limits))
        pump = ShadowCapturePump(capture, shadow, a.session, provenance.capture_point)
        deadline = time.monotonic() + a.seconds
        next_capture_health = 0.0
        while not stop.wait(0.01) and time.monotonic() < deadline and shadow.enabled:
            if grant.is_set():
                if time.monotonic() >= receiver.deadline:
                    shadow.disable("authorization_expired")
                    break
                submitted_packets += pump.poll()
            if time.monotonic() >= next_capture_health:
                emit(
                    dict(
                        type="capture_health",
                        authorized=grant.is_set(),
                        received=capture.last_received,
                        dropped=capture.last_drops,
                        interface_dropped=capture.last_ifdrops,
                        submitted_packets=submitted_packets,
                        failed=pump.failed,
                    )
                )
                next_capture_health = time.monotonic() + 1
            for event in shadow.drain_events():
                emit(event)
            if pump.failed:
                break
        if pump.failed:
            shadow.disable("capture_incomplete")
    finally:
        stop.set()
        receiver.close()
        shadow.close()
        if capture:
            # A loss may terminate capture before the next periodic sample.
            # Preserve its cached counters without consuming another delta.
            emit(
                dict(
                    type="capture_health",
                    final=True,
                    received=capture.last_received,
                    dropped=capture.last_drops,
                    interface_dropped=capture.last_ifdrops,
                    submitted_packets=submitted_packets,
                    failed=pump.failed if pump is not None else None,
                )
            )
            capture.close()
        for event in shadow.drain_events():
            emit(event)
        emit(dict(type="shadow_stopped", state="Unknown", reason=shadow.reason))


if __name__ == "__main__":
    main()
