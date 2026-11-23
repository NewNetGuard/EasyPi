"""Share of connection openings that CensorLab detectors act on.

usage: evaluate.py <censorlab-binary> <capture.pcap> <client-ip> <config.toml>...

For every detector config the capture is run through CensorLab's pcap mode;
each packet the detector would act on is mapped back to its TCP connection.
Prints, per detector, how many of the connections opened in the capture
(SYN seen) it caught, and the TLS record trace lines it logged.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
ACTION = re.compile(r"^(\d+): Ok\((Drop|Reset)")


def connection_of_packets(path: str):
    """Per packet index: the TCP connection key, plus the set of opened connections."""
    keys, opened = [], set()
    with open(path, "rb") as handle:
        header = handle.read(24)
        endian = "<" if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while True:
            record = handle.read(16)
            if len(record) < 16:
                break
            caplen = struct.unpack(endian + "IIII", record)[2]
            data = handle.read(caplen)
            key = None
            if len(data) >= 54 and data[12:14] == b"\x08\x00" and data[23] == 6:
                ip = data[14:]
                ihl = (ip[0] & 15) * 4
                sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
                key = tuple(sorted([(ip[12:16], sport), (ip[16:20], dport)]))
                flags = ip[ihl + 13]
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    opened.add(key)
            keys.append(key)
    return keys, opened


def main() -> None:
    binary, capture, client = sys.argv[1], sys.argv[2], sys.argv[3]
    keys, opened = connection_of_packets(capture)
    for config in sys.argv[4:]:
        result = subprocess.run([binary, "-c", config, "pcap", capture, client],
                                capture_output=True, text=True, errors="replace")
        output = ANSI.sub("", result.stdout + result.stderr)
        caught = set()
        for line in output.splitlines():
            match = ACTION.match(line)
            if match:
                index = int(match.group(1))
                if index < len(keys) and keys[index] in opened:
                    caught.add(keys[index])
        name = Path(config).stem
        share = 100 * len(caught) / max(1, len(opened))
        print(f"{name:24} caught {len(caught):3} of {len(opened)} openings ({share:.0f}%)")
        for line in output.splitlines():
            if "[trace]" in line:
                print("   ", line[line.index("[trace]"):])


if __name__ == "__main__":
    main()
