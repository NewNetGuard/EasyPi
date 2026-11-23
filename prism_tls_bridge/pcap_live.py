"""Linux libpcap collector with a kernel filter and continuous drop counters.

This adapter observes copies. It owns no forwarding socket, route or verdict.
The embedding launcher must open capture with suitable privilege and drop it
before starting decoder processes. No privilege escalation is performed here.
"""

import ctypes as c
import ctypes.util
import ipaddress
import threading


class LiveCapture:
    def __init__(self, interface, client, server, transport, library=None, *, device_destinations=None, immediate_mode=True):
        import sys

        if not sys.platform.startswith("linux"):
            raise RuntimeError("live libpcap adapter requires Linux")
        if type(immediate_mode) is not bool:
            raise ValueError("immediate mode must be boolean")
        if (
            not interface
            or len(interface) > 64
            or any(
                ch
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
                for ch in interface
            )
        ):
            raise ValueError("invalid capture interface")
        if transport not in {"tcp", "quic"}:
            raise ValueError("invalid transport")
        if (
            ipaddress.ip_address(client.address).version
            != ipaddress.ip_address(server.address).version
        ):
            raise ValueError("address family mismatch")
        lib = library or ctypes.util.find_library("pcap")
        if not lib:
            raise RuntimeError("libpcap unavailable")
        self.lib = c.CDLL(lib)
        self.handle = None
        self.last_received = 0
        self.last_drops = 0
        self.last_ifdrops = 0
        self.link = None
        self.lock = threading.Lock()

        class Header(c.Structure):
            _fields_ = [
                ("seconds", c.c_long),
                ("microseconds", c.c_long),
                ("caplen", c.c_uint32),
                ("length", c.c_uint32),
            ]

        class Program(c.Structure):
            _fields_ = [("length", c.c_uint), ("instructions", c.c_void_p)]

        class Stats(c.Structure):
            _fields_ = [
                ("received", c.c_uint),
                ("dropped", c.c_uint),
                ("ifdropped", c.c_uint),
            ]

        self.Header, self.Stats = Header, Stats
        signatures = {
            "pcap_create": ([c.c_char_p, c.c_char_p], c.c_void_p),
            "pcap_activate": ([c.c_void_p], c.c_int),
            "pcap_close": ([c.c_void_p], None),
            "pcap_compile": (
                [c.c_void_p, c.POINTER(Program), c.c_char_p, c.c_int, c.c_uint32],
                c.c_int,
            ),
            "pcap_setfilter": ([c.c_void_p, c.POINTER(Program)], c.c_int),
            "pcap_freecode": ([c.POINTER(Program)], None),
            "pcap_datalink": ([c.c_void_p], c.c_int),
            "pcap_next_ex": (
                [
                    c.c_void_p,
                    c.POINTER(c.POINTER(Header)),
                    c.POINTER(c.POINTER(c.c_ubyte)),
                ],
                c.c_int,
            ),
            "pcap_stats": ([c.c_void_p, c.POINTER(Stats)], c.c_int),
            "pcap_get_selectable_fd": ([c.c_void_p], c.c_int),
            "pcap_setnonblock": ([c.c_void_p, c.c_int, c.c_char_p], c.c_int),
        }
        for name in (
            "pcap_set_snaplen",
            "pcap_set_timeout",
            "pcap_set_buffer_size",
            "pcap_set_promisc",
            "pcap_set_immediate_mode",
        ):
            signatures[name] = ([c.c_void_p, c.c_int], c.c_int)
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes = args
            fn.restype = result
        error = c.create_string_buffer(256)
        self.handle = self.lib.pcap_create(interface.encode(), error)
        if not self.handle:
            raise RuntimeError("capture creation failed")
        try:
            for name, value in (
                ("pcap_set_snaplen", 65575),
                ("pcap_set_timeout", 100),
                ("pcap_set_buffer_size", 4 * 1024 * 1024),
                ("pcap_set_promisc", 0),
                ("pcap_set_immediate_mode", int(immediate_mode)),
            ):
                if getattr(self.lib, name)(self.handle, value) != 0:
                    raise RuntimeError("capture configuration failed")
            if self.lib.pcap_activate(self.handle) < 0:
                raise RuntimeError("capture activation failed")
            protocol = "tcp" if transport == "tcp" else "udp"
            forward = f"src host {client.address} and src port {client.port} and dst host {server.address} and dst port {server.port}"
            reverse = f"src host {server.address} and src port {server.port} and dst host {client.address} and dst port {client.port}"
            expression = f"{protocol} and (({forward}) or ({reverse}))"
            if device_destinations is not None:
                destinations = tuple(str(ipaddress.ip_address(v)) for v in device_destinations)
                if not 1 <= len(destinations) <= 16 or any(
                    ipaddress.ip_address(v).version != ipaddress.ip_address(client.address).version
                    for v in destinations
                ):
                    raise ValueError("invalid device capture scope")
                hosts = " or ".join(f"host {v}" for v in destinations)
                expression = f"host {client.address} and ({hosts}) and (tcp port 443 or udp port 443)"
            program = Program()
            if (
                self.lib.pcap_compile(
                    self.handle, c.byref(program), expression.encode(), 1, 0xFFFFFFFF
                )
                != 0
            ):
                raise RuntimeError("capture filter compilation failed")
            try:
                if self.lib.pcap_setfilter(self.handle, c.byref(program)) != 0:
                    raise RuntimeError("capture filter installation failed")
            finally:
                self.lib.pcap_freecode(c.byref(program))
            self.link = self.lib.pcap_datalink(self.handle)
            if self.link not in (1, 101, 113, 276):
                raise RuntimeError("unsupported capture link")
            if self.lib.pcap_setnonblock(self.handle, 1, error) != 0:
                raise RuntimeError("nonblocking capture unavailable")
        except Exception:
            self.close()
            raise

    def counters(self):
        value = self.Stats()
        if self.lib.pcap_stats(self.handle, c.byref(value)) != 0:
            raise RuntimeError("capture drop statistics unavailable")
        # libpcap counters may wrap at 32 bits.
        count = ((value.dropped - self.last_drops) & 0xFFFFFFFF) + (
            (value.ifdropped - self.last_ifdrops) & 0xFFFFFFFF
        )
        self.last_received = value.received
        self.last_drops, self.last_ifdrops = value.dropped, value.ifdropped
        return count

    def read(self):
        header = c.POINTER(self.Header)()
        data = c.POINTER(c.c_ubyte)()
        result = self.lib.pcap_next_ex(self.handle, c.byref(header), c.byref(data))
        if result == 0:
            return None
        if result != 1:
            raise RuntimeError("capture ended")
        if (
            not 1 <= header.contents.caplen <= 65575
            or header.contents.caplen != header.contents.length
        ):
            raise ValueError("capture truncated")
        frame = c.string_at(data, header.contents.caplen)
        offset = {1: 14, 101: 0, 113: 16, 276: 20}[self.link]
        if len(frame) < offset + 20:
            raise ValueError("truncated packet")
        if self.link == 1:
            protocol = int.from_bytes(frame[12:14], "big")
        elif self.link == 113:
            protocol = int.from_bytes(frame[14:16], "big")
        elif self.link == 276:
            protocol = int.from_bytes(frame[:2], "big")
        else:
            protocol = 0x86DD if frame[0] >> 4 == 6 else 0x800
        if protocol not in (0x800, 0x86DD):
            raise ValueError("unsupported link payload")
        packet = frame[offset:]
        version = packet[0] >> 4
        if version == 4:
            total = int.from_bytes(packet[2:4], "big")
        elif version == 6 and len(packet) >= 40:
            total = 40 + int.from_bytes(packet[4:6], "big")
        else:
            raise ValueError("unsupported IP")
        if not 20 <= total <= len(packet):
            raise ValueError("invalid packet length")
        return packet[:total]

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None


class ShadowCapturePump:
    """One explicitly admitted flow; checks loss before each bounded packet batch.

    Once capture is lost, this flow cannot regain Decrypted. Start a new flow
    with a new handshake and fresh endpoint authorization to restore coverage.
    """

    def __init__(self, capture, supervisor, flow, capture_point):
        self.capture, self.supervisor, self.flow, self.capture_point = (
            capture,
            supervisor,
            flow,
            capture_point,
        )
        self.failed = False

    def poll(self):
        if self.failed or not self.supervisor.enabled:
            return 0
        try:
            drops = self.capture.counters()
            if drops:
                self.supervisor.capture_loss(self.capture_point, drops)
                self.failed = True
                return 0
            count = 0
            for _ in range(64):
                packet = self.capture.read()
                if packet is None:
                    break
                if not self.supervisor.submit_packet(
                    self.flow, packet, self.capture_point
                ):
                    return count
                count += 1
            return count
        except Exception:
            self.supervisor.capture_loss(self.capture_point)
            self.failed = True
            return 0
