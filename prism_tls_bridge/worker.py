"""Bounded input adapter; overflow invalidates coverage and never blocks capture."""

from collections import deque
from dataclasses import replace
import threading
import time
from .models import InspectionState, Provenance


class BridgeWorker:
    def __init__(self, bridge, max_items=128, max_bytes=1024 * 1024, autostart=True):
        if max_items <= 0 or max_bytes <= 0:
            raise ValueError("invalid queue limits")
        self.bridge, self.max_items, self.max_bytes = bridge, max_items, max_bytes
        self.reservation = max_bytes + max_items * 256
        bridge.reserve_external(self.reservation)
        self.condition = threading.Condition()
        self.items = deque()
        self.size = 0
        self.known = set()
        self.lost = set()
        self.stopping = False
        self.closed = False
        self.dropped = 0
        self.processed = 0
        self.queue_wait_total = 0.0
        self.queue_wait_max = 0.0
        self.thread = threading.Thread(
            target=self._run, name="Prism-TLS-Bridge", daemon=True
        )
        if autostart:
            self.thread.start()

    def open_flow(self, *args, **kwargs):
        with self.condition:
            if self.closed:
                raise RuntimeError("worker is closed")
        result = self.bridge.open_flow(*args, **kwargs)
        if result:
            flow_id = args[0] if args else kwargs["flow_id"]
            with self.bridge.lock:
                with self.condition:
                    closed = self.closed
                    self.known.intersection_update(self.bridge.flows)
                    self.lost.intersection_update(self.known)
                    if not closed:
                        self.known.add(flow_id)
            if closed:
                self.bridge.close_flow(flow_id)
                return False
        return result

    def submit_packet(self, flow_id, packet, capture_point):
        if not isinstance(packet, bytes) or len(packet) > 65535:
            return self._reject(flow_id)
        return self._submit("packet", flow_id, packet, capture_point, None)

    def submit_key(self, flow_id, line, provenance):
        if (
            not isinstance(provenance, Provenance)
            or not isinstance(line, str)
            or len(line) > 1024
        ):
            return self._reject(flow_id)
        return self._submit("key", flow_id, line, provenance.capture_point, provenance)

    def _reject(self, flow_id):
        with self.condition:
            self.dropped += 1
            if flow_id in self.known:
                self.lost.add(flow_id)
            self.condition.notify()
        return False

    def _submit(self, kind, flow_id, payload, point, provenance):
        with self.condition:
            if not isinstance(point, str) or len(point) > 64:
                return self._reject(flow_id)
            if self.stopping or flow_id not in self.known:
                return False
            size = len(payload) + len(flow_id) + len(point) + 128
            if len(self.items) >= self.max_items or self.size + size > self.max_bytes:
                return self._reject(flow_id)
            self.items.append(
                (kind, flow_id, payload, point, provenance, time.monotonic(), size)
            )
            self.size += size
            self.condition.notify()
            return True

    def process_one(self):
        with self.condition:
            lost = tuple(self.lost)
            item = self.items.popleft() if self.items else None
            if item:
                self.size -= item[-1]
        for flow_id in lost:
            status = self.bridge.status(flow_id)
            if status:
                self.bridge.report_loss(flow_id, status.provenance.capture_point)
        with self.condition:
            self.lost.difference_update(lost)
        if item:
            kind, flow_id, payload, point, provenance, queued, _ = item
            wait = max(0.0, time.monotonic() - queued)
            with self.condition:
                self.processed += 1
                self.queue_wait_total += wait
                self.queue_wait_max = max(self.queue_wait_max, wait)
            if kind == "packet":
                self.bridge.feed_packet(flow_id, payload, point)
            else:
                self.bridge.add_key(flow_id, payload, provenance)
        self.bridge.poll()
        with self.bridge.lock:
            with self.condition:
                self.known.intersection_update(self.bridge.flows)
        return item is not None

    def _run(self):
        while True:
            with self.condition:
                if self.stopping:
                    return
                if not self.items and not self.lost:
                    self.condition.wait(0.05)
            self.process_one()

    def status(self, flow_id):
        with self.bridge.lock:
            status = self.bridge.status(flow_id)
            with self.condition:
                lost = flow_id in self.lost
        if status and lost:
            return replace(
                status,
                state=InspectionState.UNKNOWN,
                reason="input_queue_overflow",
                request_headers_complete=False,
            )
        return status

    def metrics(self):
        with self.condition:
            return {
                "queued_items": len(self.items),
                "queued_bytes": self.size,
                "dropped": self.dropped,
                "known_flows": len(self.known),
                "processed": self.processed,
                "queue_wait_mean_ms": round(
                    self.queue_wait_total / max(1, self.processed) * 1000, 4
                ),
                "queue_wait_max_ms": round(self.queue_wait_max * 1000, 4),
            }

    def close(self):
        with self.condition:
            if self.closed:
                return
            self.closed = True
            self.stopping = True
            self.items.clear()
            self.size = 0
            self.lost.clear()
            self.known.clear()
            self.condition.notify_all()
        if self.thread.is_alive():
            self.thread.join()
        self.bridge.close()
        self.bridge.release_external(self.reservation)
