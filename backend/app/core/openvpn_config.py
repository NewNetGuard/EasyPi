"""Restricted OpenVPN client profiles, shared by import and the root launcher.

This module intentionally uses only the standard library: the root launcher runs
this file with isolated system Python, without importing the backend application.
Only the returned canonical text may be passed to OpenVPN. Unknown options fail
closed; adding an option requires reviewing all of its arguments for file access.
"""
from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

MAX_CONFIG_BYTES = 1024 * 1024
# OpenVPN 2.6 reads options AND inline material using 256-byte line buffers.
MAX_LINE_BYTES = 254
INLINE_OPTIONS = frozenset({
    "ca", "cert", "key", "pkcs12", "tls-auth", "tls-crypt", "tls-crypt-v2",
    "crl-verify", "auth-user-pass",
})
FLAGS = frozenset({
    "client", "tls-client", "pull", "nobind", "persist-key", "persist-tun",
    "remote-random", "remote-random-hostname", "float", "auth-nocache",
    "auth-user-pass", "mute-replay-warnings", "disable-dco", "fast-io",
    "route-nopull", "route-noexec",
})
ENUMS = {
    "dev": {"tun", "tun0"}, "dev-type": {"tun"},
    "proto": {"udp", "udp4", "udp6", "tcp-client", "tcp4-client", "tcp6-client", "tcp"},
    "remote-cert-tls": {"server"}, "ns-cert-type": {"server"},
    "key-direction": {"0", "1"}, "auth-retry": {"none", "nointeract", "interact"},
    "tls-version-max": {"1.2", "1.3"},
    "topology": {"net30", "p2p", "subnet"},
    "allow-compression": {"no", "asym"},
    "user": {"nobody"}, "group": {"nogroup", "nobody"},
}
NUMBERS = frozenset({
    "port", "rport", "connect-timeout", "connect-retry-max", "ping", "ping-exit",
    "ping-restart", "reneg-sec", "reneg-bytes", "reneg-pkts", "hand-window",
    "tran-window", "tls-timeout", "tun-mtu", "link-mtu", "sndbuf", "rcvbuf",
    "verb", "mute", "route-metric",
})
CRYPTO_NAMES = frozenset({
    "cipher", "auth", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers",
    "tls-cipher", "tls-ciphersuites", "ecdh-curve", "tls-groups", "remote-cert-eku",
})
# These options are removed by the existing routing sanitizer before launch.
ROUTING_ARITY = {
    "route": (1, 4), "route-ipv6": (1, 3), "route-gateway": (1, 1),
    "route-delay": (0, 2), "route-method": (1, 1),
    "redirect-gateway": (0, 8), "redirect-private": (0, 8),
}


def _safe_arguments(option: str, args: list[str]) -> bool:
    if option in FLAGS:
        return not args
    if option in ENUMS:
        return len(args) == 1 and args[0] in ENUMS[option]
    if option in NUMBERS:
        return len(args) == 1 and re.fullmatch(r"[0-9]{1,10}", args[0]) is not None
    if option in CRYPTO_NAMES:
        return len(args) == 1 and re.fullmatch(r"[A-Za-z0-9_.:+@?= -]{1,240}", args[0]) is not None
    if option == "remote":
        return (
            1 <= len(args) <= 3
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", args[0]) is not None
            and (len(args) < 2 or (args[1].isascii() and args[1].isdigit() and 1 <= int(args[1]) <= 65535))
            and (len(args) < 3 or args[2] in ENUMS["proto"])
        )
    if option == "resolv-retry":
        return len(args) == 1 and (args[0] == "infinite" or re.fullmatch(r"[0-9]{1,10}", args[0]) is not None)
    if option in {"connect-retry", "keepalive"}:
        return (len(args) in ({1, 2} if option == "connect-retry" else {2})
                and all(re.fullmatch(r"[0-9]{1,10}", arg) for arg in args))
    if option in {"explicit-exit-notify", "mssfix"}:
        return not args or (len(args) == 1 and re.fullmatch(r"[0-9]{1,5}", args[0]) is not None)
    if option == "tls-version-min":
        return 1 <= len(args) <= 2 and args[0] in {"1.2", "1.3"} and (len(args) == 1 or args[1] == "or-highest")
    if option == "verify-x509-name":
        return (1 <= len(args) <= 2 and re.fullmatch(r"[A-Za-z0-9_.@=, :+-]{1,200}", args[0]) is not None
                and (len(args) == 1 or args[1] in {"subject", "name", "name-prefix"}))
    if option == "remote-cert-ku":
        return 1 <= len(args) <= 8 and all(re.fullmatch(r"[0-9a-fA-F]{2,4}", arg) for arg in args)
    if option == "comp-lzo":
        return not args or args == ["no"]
    if option == "compress":
        return not args or args in (["stub"], ["stub-v2"])
    if option == "pull-filter":
        return len(args) == 2 and args[0] in {"accept", "ignore", "reject"} and re.fullmatch(r"[A-Za-z0-9_.: -]{1,200}", args[1]) is not None
    if option == "dhcp-option":
        return len(args) == 2 and args[0] in {"DNS", "DOMAIN", "DOMAIN-SEARCH"} and re.fullmatch(r"[A-Za-z0-9_.:-]+", args[1]) is not None
    if option in ROUTING_ARITY:
        low, high = ROUTING_ARITY[option]
        if not low <= len(args) <= high:
            return False
        for arg in args:
            if "/" in arg:
                # A CIDR is a network, never a filesystem argument.
                import ipaddress
                try:
                    ipaddress.ip_network(arg, strict=False)
                except ValueError:
                    return False
            elif not re.fullmatch(r"[A-Za-z0-9_.:-]+", arg):
                return False
        return True
    return False


def validate_openvpn_config(text: str) -> str:
    """Return a canonical allowlisted profile, or raise without echoing secrets."""
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("OpenVPN profile exceeds 1 MiB")
    text = text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if any((ord(char) < 32 and char not in "\n\t") or ord(char) == 127 for char in text):
        raise ValueError("OpenVPN profile contains control characters")
    output: list[str] = []
    inline: str | None = None
    seen_inline: set[str] = set()
    has_remote = False
    for line_number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        def reject() -> None:
            raise ValueError(f"OpenVPN line {line_number}: unsupported directive, arguments or inline block; file references are not allowed")

        if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
            reject()
        if inline is not None:
            if line == f"</{inline}>":
                output.append(line)
                inline = None
            elif "<" in line or ">" in line:
                # OpenVPN accepts a closing-tag prefix. Reject trailing text,
                # nested tags and mismatched tags, so no hidden options escape.
                reject()
            else:
                output.append(raw)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if "\\" in line:
            reject()
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            tokens = list(lexer)
        except ValueError:
            reject()
        if not tokens:
            continue
        option = tokens[0].removeprefix("--")
        args = tokens[1:]
        if option.startswith("<"):
            tag = option[1:-1] if option.endswith(">") else ""
            if args or tag not in INLINE_OPTIONS or tag in seen_inline:
                reject()
            inline = tag
            seen_inline.add(tag)
            output.append(f"<{tag}>")
            continue
        if not _safe_arguments(option, args):
            reject()
        has_remote |= option == "remote"
        # Canonical tokens remove --/quotes on option names so the credential
        # broker, endpoint resolver and routing sanitizer see the same options.
        canonical = " ".join([option] + [f'"{arg}"' if " " in arg else arg for arg in args])
        if len(canonical.encode("utf-8")) > MAX_LINE_BYTES:
            reject()
        output.append(canonical)
    if inline is not None:
        raise ValueError("OpenVPN profile has an unclosed inline block")
    if not has_remote:
        raise ValueError("OpenVPN profile requires a remote endpoint")
    return "\n".join(output) + "\n"


def openvpn_option_text(text: str) -> str:
    """Exclude inline payloads when inspecting a canonical profile's options.

    This is for metadata/credential discovery, not a substitute for validation.
    Credentials and PEM comments can themselves look like directive lines.
    """
    output = []
    inline = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("</") and line.endswith(">"):
            inline = False
        elif line.startswith("<") and line.endswith(">"):
            inline = True
        elif not inline:
            output.append(raw)
    return "\n".join(output)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected one OpenVPN profile path")
        with Path(sys.argv[1]).open("rb") as source:
            data = source.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise ValueError("OpenVPN profile exceeds 1 MiB")
        canonical = validate_openvpn_config(data.decode("utf-8"))
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(canonical)
