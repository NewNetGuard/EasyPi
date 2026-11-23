"""Bounded stdin command worker. No network sockets or forwarding interfaces."""

import argparse
import base64
import json
import queue
import sys
import threading
import time
from .resource_guard import ProcessGuard, usage


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--memory", type=int, required=True)
    p.add_argument("--cpu-seconds", type=int, required=True)
    p.add_argument("--cpu-percent", type=int, required=True)
    a = p.parse_args()
    guard = ProcessGuard(a.memory, a.cpu_seconds, a.cpu_percent)
    from .bridge import Bridge
    from .worker import BridgeWorker
    from .models import Endpoint, Provenance

    bridge = Bridge()
    worker = BridgeWorker(bridge)
    commands = queue.Queue(maxsize=128)
    failed = threading.Event()
    eof = threading.Event()

    def read():
        try:
            while True:
                raw = sys.stdin.buffer.readline(100001)
                if not raw:
                    break
                if len(raw) > 100000:
                    raise ValueError("command limit")
                commands.put_nowait(json.loads(raw))
        except Exception:
            failed.set()
        finally:
            eof.set()

    def emit(value):
        print(json.dumps(value, separators=(",", ":")), flush=True)

    threading.Thread(target=read, daemon=True).start()
    emit(dict(type="ready", os_limits=guard.mode))
    next_heartbeat = 0
    registered = set()
    try:
        while not failed.is_set():
            if eof.is_set() and commands.empty():
                break
            try:
                command = commands.get(timeout=0.02)
            except queue.Empty:
                command = None
            if command:
                kind = command["type"]
                flow = command.get("flow")
                if kind == "open":
                    accepted = worker.open_flow(
                        flow,
                        command["transport"],
                        Provenance(**command["provenance"]),
                        Endpoint(**command["client"]),
                        Endpoint(**command["server"]),
                        key_session_id=command.get("key_session_id"),
                    )
                    if accepted:
                        registered.add(flow)
                    emit(dict(type="admission", flow=flow, accepted=accepted))
                elif kind == "packet":
                    worker.submit_packet(
                        flow,
                        base64.b64decode(command["packet"], validate=True),
                        command["capture_point"],
                    )
                elif kind == "key":
                    worker.submit_key(
                        flow, command["line"], Provenance(**command["provenance"])
                    )
                elif kind == "loss":
                    bridge.report_loss(flow, command["capture_point"])
                elif kind == "close":
                    bridge.close_flow(flow)
                    registered.discard(flow)
                else:
                    raise ValueError("unsupported command")
            # Shadow diagnostics never expose hostnames, paths, key material or bodies.
            for event in bridge.drain_events():
                emit(
                    dict(
                        type="headers",
                        flow=event["flow_id"],
                        protocol=event["request"]["protocol"],
                        state="Decrypted",
                        coverage="request_headers_only",
                    )
                )
            if time.monotonic() >= next_heartbeat:
                rss, cpu = usage()
                statuses = []
                with bridge.lock:
                    for flow_id in list(registered):
                        status = worker.status(flow_id)
                        if status:
                            statuses.append(
                                dict(
                                    flow=flow_id,
                                    state=status.state.value,
                                    reason=status.reason,
                                    diagnostic=status.diagnostic,
                                )
                            )
                emit(
                    dict(
                        type="heartbeat",
                        rss=rss,
                        cpu=cpu,
                        bridge=bridge.metrics(),
                        worker=worker.metrics(),
                        statuses=statuses,
                    )
                )
                next_heartbeat = time.monotonic() + 0.1
    except Exception:
        emit(dict(type="unavailable", reason="child_input_or_decoder_failure"))
    finally:
        worker.close()


if __name__ == "__main__":
    main()
