"""Read-only, IPv4/UDP integrity checks for the experiment's narrow capture."""

from collections import Counter
import hashlib
import ipaddress
from pathlib import Path
import struct


def inspect_udp_capture(path, pi_ip, client_ip):
    raw = Path(path).read_bytes()
    if len(raw) > 128 * 1024 * 1024 or len(raw) < 24:
        raise ValueError("pcap size limit")
    if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif raw[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("unsupported pcap format")
    link = struct.unpack(endian + "I", raw[20:24])[0]
    offsets = {1: 14, 113: 16, 276: 20}
    if link not in offsets:
        raise ValueError("unsupported pcap link type")
    flows = {
        name: Counter()
        for name in ("pc_to_pi", "pi_to_public", "public_to_pi", "pi_to_pc")
    }
    position, records, fragments = 24, 0, 0
    while position < len(raw):
        if position + 16 > len(raw):
            raise ValueError("truncated pcap record")
        size = struct.unpack(endian + "IIII", raw[position : position + 16])[2]
        position += 16
        if size > 65535 or position + size > len(raw):
            raise ValueError("invalid pcap packet size")
        packet = raw[position : position + size]
        position += size
        records += 1
        if records > 65536:
            raise ValueError("pcap record budget")
        ip = packet[offsets[link] :]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            fragments += 1
            continue
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        if header < 20 or total > len(ip) or total < header + 8:
            raise ValueError("invalid IPv4 packet")
        source = str(ipaddress.ip_address(ip[12:16]))
        destination = str(ipaddress.ip_address(ip[16:20]))
        udp = ip[header:total]
        sport, dport, length = struct.unpack("!HHH", udp[:6])
        if length < 8 or length > len(udp):
            raise ValueError("invalid UDP length")
        payload = udp[8:length]
        if payload.startswith(b"PRISM-UDP-"):
            continue
        flow = None
        if source == client_ip and destination == pi_ip and dport == 443:
            flow = "pc_to_pi"
        elif source == pi_ip and destination == client_ip and sport == 443:
            flow = "pi_to_pc"
        elif dport == 443 and ipaddress.ip_address(destination).is_global:
            flow = "pi_to_public"
        elif sport == 443 and ipaddress.ip_address(source).is_global:
            flow = "public_to_pi"
        if flow:
            flows[flow][hashlib.sha256(payload).digest()] += 1
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "capture_records": records,
        "data_datagrams": {
            name: sum(counts.values()) for name, counts in flows.items()
        },
        "client_payloads_preserved": bool(flows["pc_to_pi"])
        and flows["pc_to_pi"] == flows["pi_to_public"],
        "server_payloads_preserved": bool(flows["public_to_pi"])
        and flows["public_to_pi"] == flows["pi_to_pc"],
        "fragment_packets": fragments,
    }
