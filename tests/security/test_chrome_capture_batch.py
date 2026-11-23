from collections import Counter, deque
from prism_tls_bridge.chrome_agent import capture_batch


class Observer:
    def __init__(self):
        self.counts = Counter()
        self.received = 0
        self.losses = []
        self.ticks = 0

    def packet(self, _):
        self.received += 1

    def loss(self, n):
        self.losses.append(n)

    def tick(self):
        self.ticks += 1


class Capture:
    def __init__(self, size, drops=0):
        self.items = deque([b"synthetic-packet"] * size)
        self.drops = drops

    def counters(self):
        n, self.drops = self.drops, 0
        return n

    def read(self):
        return self.items.popleft() if self.items else None


def test_burst_stays_bounded_but_requests_immediate_next_batch():
    observer, capture = Observer(), Capture(140)
    assert capture_batch(observer, capture)
    assert observer.received == 64 and len(capture.items) == 76
    assert capture_batch(observer, capture)
    assert not capture_batch(observer, capture)
    assert observer.received == 140 and observer.ticks == 3
    assert observer.counts["capture_full_batches"] == 2


def test_real_drop_delta_is_distinct_and_empty_capture_backs_off():
    observer, capture = Observer(), Capture(0, drops=7)
    assert not capture_batch(observer, capture)
    assert not capture_batch(observer, capture)
    assert observer.losses == [7, 0]
    assert observer.counts["capture_dropped_packets"] == 7
    assert observer.counts["capture_packets_read"] == 0
