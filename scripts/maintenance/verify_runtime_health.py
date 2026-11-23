#!/usr/bin/env python3
"""Read-only post-install/update health gate for EasyPi's network path."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any


PREFIX = Path(os.environ.get("EASYPI_PREFIX", "/opt/EasyPi"))
GATEWAY_STATE = PREFIX / "data/network/gateway_mode.json"
STEALTH_CONFIG = PREFIX / "data/netprotection/stealth_client.conf"
STEALTH_META = PREFIX / "data/netprotection/stealth_meta.json"
STEALTH_POLICY = Path("/var/lib/easypi/stealth-policy/dns-policy.json")
STEALTH_STATUS = Path("/run/easypi-stealth/status/status.json")
IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")
PRE_CHAIN = "EASYPI_STEALTH_PRESTART"
PRE6_CHAIN = "EASYPI_STEALTH6_PRESTART"
DNS_EGRESS_CHAIN = "EASYPI_STEALTH_DNS_EGRESS"
DNS_ROUTE_TABLE = "51823"
DNS_RULE_PREF = "5094"


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )


def read_json(path: Path, *, root_owned: bool = False) -> dict[str, Any] | None:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
            raise ValueError("not a bounded regular file")
        if info.st_mode & 0o022:
            raise ValueError("writable outside owner")
        if root_owned and info.st_uid != 0:
            raise ValueError("not root-owned")
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("not a JSON object")
        return value
    except FileNotFoundError:
        return None


def service_active(name: str) -> bool:
    return run("systemctl", "is-active", "--quiet", name).returncode == 0


def dns_probe(
    timeout: float = 3.0, *, require_upstream: bool = False
) -> tuple[bool, str]:
    """Exercise the real DNS listener; optionally require working upstream."""
    transaction_id = secrets.randbelow(65536)
    if require_upstream:
        labels = "resolver-health.easypi.invalid".split(".")
        question = b"".join(
            bytes((len(label),)) + label.encode("ascii") for label in labels
        )
        packet = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        packet += question + b"\x00" + struct.pack("!HH", 1, 1)
    else:
        # A zero-question packet receives FORMERR locally. This proves that the
        # real UDP listener responds without depending on WAN or an upstream.
        packet = struct.pack("!HHHHHH", transaction_id, 0x0100, 0, 0, 0, 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, ("127.0.0.1", 53))
            response, _ = sock.recvfrom(4096)
    except OSError as exc:
        return False, f"DNS probe failed: {exc}"
    if len(response) < 12:
        return False, "DNS probe returned a truncated header"
    reply_id, flags, questions = struct.unpack("!HHH", response[:6])
    if reply_id != transaction_id or not flags & 0x8000:
        return False, "DNS probe returned an invalid response"
    rcode = flags & 0x000F
    if require_upstream:
        if questions != 1 or rcode not in {0, 3}:
            return False, f"DNS upstream probe returned unexpected RCODE {rcode}"
        if len(response) < len(packet) or response[12 : len(packet)] != packet[12:]:
            return False, "DNS upstream probe did not echo the expected question"
    elif questions != 0 or rcode != 1:
        return False, f"DNS listener probe returned unexpected RCODE {rcode}"
    return True, ""


def command_lines(*command: str) -> list[str]:
    result = run(*command)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(command)}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _guards_are_leading_rules(
    rules: list[str], required_jumps: set[str], builtin_chain: str
) -> bool:
    prefix = f"-a {builtin_chain.lower()} "
    normalized_rules = [
        rule.lower() for rule in rules if rule.lower().startswith(prefix)
    ]
    normalized_jumps = {rule.lower() for rule in required_jumps}
    count = len(normalized_jumps)
    if count == 0 or len(normalized_rules) < count:
        return False
    return set(normalized_rules[:count]) == normalized_jumps


def check_forwarding_guards(policy: dict[str, Any], failures: list[str]) -> None:
    scope = policy.get("scope")
    raw_macs = policy.get("macs", [])
    if scope not in {"all", "selected"} or not isinstance(raw_macs, list):
        failures.append("Chameleon strict policy has invalid forwarding scope")
        return
    macs = [str(value).strip().lower() for value in raw_macs]
    if scope == "selected" and (
        not macs
        or any(not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) for mac in macs)
    ):
        failures.append("Chameleon selected-device policy has invalid MAC coverage")
        return

    forward4 = command_lines("iptables", "-S", "FORWARD")
    forward6 = command_lines("ip6tables", "-S", "FORWARD")
    chain4 = command_lines("iptables", "-S", PRE_CHAIN)
    chain6 = command_lines("ip6tables", "-S", PRE6_CHAIN)

    expected4 = [
        f"-N {PRE_CHAIN}",
        f"-A {PRE_CHAIN} -o cham0 -j RETURN",
        # Covered devices' TCP enters the local stream namespace through this
        # veth; nothing is routed onward from there (stealth_vpn.sh builds the
        # chain in exactly this order).
        f"-A {PRE_CHAIN} -o chtcp0 -j RETURN",
        *(
            f"-A {PRE_CHAIN} -d {network} -j RETURN"
            for network in (
                "10.0.0.0/8",
                "100.64.0.0/10",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
            )
        ),
        f"-A {PRE_CHAIN} -j DROP",
    ]
    if chain4 != expected4:
        failures.append("IPv4 Chameleon guard contents or order are unsafe")
    if chain6 != [f"-N {PRE6_CHAIN}", f"-A {PRE6_CHAIN} -j DROP"]:
        failures.append("IPv6 Chameleon guard is not an unconditional DROP")

    if scope == "all":
        jumps4 = {f"-A FORWARD -j {PRE_CHAIN}"}
        jumps6 = {f"-A FORWARD -j {PRE6_CHAIN}"}
    else:
        jumps4 = {
            f"-A FORWARD -m mac --mac-source {mac} -j {PRE_CHAIN}" for mac in macs
        }
        jumps6 = {
            f"-A FORWARD -m mac --mac-source {mac} -j {PRE6_CHAIN}" for mac in macs
        }
    if not _guards_are_leading_rules(forward4, jumps4, "FORWARD"):
        failures.append("IPv4 Chameleon guards are not the first forwarding rules")
    if not _guards_are_leading_rules(forward6, jumps6, "FORWARD"):
        failures.append("IPv6 Chameleon guards are not the first forwarding rules")


def check_dns_guards(failures: list[str]) -> None:
    uid_result = run("id", "-u", "easypi-stealth-dns")
    if uid_result.returncode != 0 or not uid_result.stdout.strip().isdigit():
        failures.append("protected DNS service account is unavailable")
        return
    uid = uid_result.stdout.strip()
    rules = command_lines("ip", "rule", "show")
    expected_rule = re.compile(
        rf"^{DNS_RULE_PREF}:.*\buidrange {uid}-{uid}\b.*\blookup {DNS_ROUTE_TABLE}(?:\s|$)"
    )
    if not any(expected_rule.search(rule) for rule in rules):
        failures.append("protected DNS uidrange policy rule is missing")

    routes = command_lines("ip", "route", "show", "table", DNS_ROUTE_TABLE)
    if not any(rule.startswith("blackhole default") for rule in routes):
        failures.append("protected DNS route table has no blackhole default")

    output = command_lines("iptables", "-S", "OUTPUT")
    chain = command_lines("iptables", "-S", DNS_EGRESS_CHAIN)
    jump = f"-A OUTPUT -j {DNS_EGRESS_CHAIN}"
    if not _guards_are_leading_rules(output, {jump}, "OUTPUT"):
        failures.append("protected DNS guard is not the first OUTPUT rule")

    chain_rules = [rule for rule in chain if rule.startswith("-A ")]
    accepts = [rule for rule in chain_rules if rule.endswith("-j ACCEPT")]
    rejects = [rule for rule in chain_rules if "-j REJECT" in rule]
    required_rules = (
        ("-m", "owner", "--uid-owner", uid, "-o", "lo", "-j", "ACCEPT"),
        (
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-o",
            "cham0",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ),
        (
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-o",
            "cham0",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ),
        (
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "REJECT",
            "--reject-with",
            "icmp-port-unreachable",
        ),
    )
    required_rules_exist = all(
        run("iptables", "-C", DNS_EGRESS_CHAIN, *rule).returncode == 0
        for rule in required_rules
    )
    if (
        len(chain_rules) != 4
        or len(accepts) != 3
        or len(rejects) != 1
        or not required_rules_exist
    ):
        failures.append("protected DNS OUTPUT chain is incomplete or too permissive")
    elif chain_rules[-1] != rejects[0]:
        failures.append("protected DNS reject is not the terminal rule")


def check_gateway(failures: list[str]) -> None:
    state = read_json(GATEWAY_STATE)
    if not state or state.get("enabled") is not True:
        return
    if IP_FORWARD_PATH.read_text(encoding="ascii").strip() != "1":
        failures.append("gateway mode is enabled but IPv4 forwarding is off")
    wan = str(state.get("wan_iface") or state.get("interface") or "")
    if not wan or run("ip", "link", "show", "dev", wan).returncode != 0:
        failures.append("gateway mode has no valid WAN interface")
    elif run("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", wan, "-j", "MASQUERADE").returncode != 0:
        failures.append(f"gateway NAT is missing on {wan}")
    if not service_active("easypi-ipv6-policy-guard.service"):
        failures.append("IPv6 policy guard is not active")


def check_stealth(failures: list[str], *, require_connectivity: bool) -> None:
    policy = read_json(STEALTH_POLICY, root_owned=True)
    if policy is None:
        return
    if policy.get("version") != 1 or not isinstance(policy.get("enabled"), bool):
        failures.append("Chameleon strict policy has an invalid schema")
        return
    if policy.get("enabled") is not True:
        forward = run("iptables", "-S", "FORWARD")
        forward6 = run("ip6tables", "-S", "FORWARD")
        rules = run("ip", "rule", "show")
        if "EASYPI_STEALTH_PRESTART" in forward.stdout:
            failures.append("disabled Chameleon still has an IPv4 forwarding guard")
        if "EASYPI_STEALTH6_PRESTART" in forward6.stdout:
            failures.append("disabled Chameleon still has an IPv6 forwarding guard")
        if "5093:" in rules.stdout or "5094:" in rules.stdout:
            failures.append("disabled Chameleon still has protected DNS routing")
        return
    config = read_json(STEALTH_CONFIG)
    meta = read_json(STEALTH_META)
    if config is None:
        failures.append("strict Chameleon policy is enabled without a safe client config")
    if not meta or meta.get("enabled") is not True:
        failures.append("Chameleon metadata and strict policy disagree")
    if not service_active("easypi-stealth-dns.service"):
        failures.append("protected DNS service is not active")
    check_forwarding_guards(policy, failures)
    check_dns_guards(failures)
    status = read_json(STEALTH_STATUS)
    connected = bool(status and status.get("connected") is True)
    route = run("ip", "route", "show", "table", "51821")
    dns_route = run("ip", "route", "show", "table", DNS_ROUTE_TABLE)

    if connected:
        link = run("ip", "link", "show", "dev", "cham0")
        if link.returncode != 0 or "UP" not in link.stdout:
            failures.append("Chameleon reports connected but cham0 is absent or down")
        if route.returncode != 0 or "default dev cham0" not in route.stdout:
            failures.append("Chameleon policy table has no tunnel default route")
        if dns_route.returncode != 0 or "default dev cham0" not in dns_route.stdout:
            failures.append("protected DNS has no tunnel route")
    else:
        # A network/VPS outage is not an installation failure when the deep
        # checks above prove that forwarding and protected DNS remain closed.
        if require_connectivity:
            failures.append("Chameleon has not completed its server handshake")


def verify(*, probe_dns: bool = True, require_connectivity: bool = False) -> list[str]:
    failures: list[str] = []
    for service in (
        "easypi-backend.service",
        "easypi-netprotection.service",
        "nginx.service",
    ):
        if not service_active(service):
            failures.append(f"required service is not active: {service}")
    if probe_dns:
        ok, message = dns_probe(require_upstream=require_connectivity)
        if not ok:
            failures.append(message)
    try:
        check_gateway(failures)
        check_stealth(failures, require_connectivity=require_connectivity)
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        failures.append(f"runtime state validation failed: {exc}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-dns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--require-connectivity",
        action="store_true",
        help="also require working DNS upstream and an established Chameleon tunnel",
    )
    args = parser.parse_args()
    failures = verify(
        probe_dns=not args.skip_dns,
        require_connectivity=args.require_connectivity,
    )
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("EasyPi runtime health check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
