"""Emit the inline u32 firewall matcher(s) for an app block.

Prism does NOT run in the background. This executes for a fraction of a second at
block-enable time to hand the firewall the exact in-kernel match, and the kernel
does the blocking from then on (dropping the app's first packet before it is
forwarded). One line per port:

    <port>\t<u32-expression>

Used by setup_app_blocking.sh:
    python3 -m prism_dpi.rule whatsapp
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .registry import get_all
from .signatures import AppSignature, HttpHostSignature, TlsClientHelloSignature


@dataclass(frozen=True)
class FirewallRule:
    matcher: str
    port: int
    arguments: tuple[str, ...]

    def fields(self) -> tuple[str, ...]:
        return self.matcher, str(self.port), *self.arguments


def emit(app: str) -> list[FirewallRule]:
    """Return all inline firewall rules for an app's registered transports."""
    rules: list[FirewallRule] = []
    for sig in get_all(app):
        if isinstance(sig, AppSignature):
            rules.extend(
                FirewallRule("u32", port, (sig.u32_expr(),))
                for port in sig.ports
            )
        elif isinstance(sig, HttpHostSignature):
            rules.append(FirewallRule("strings", sig.port, sig.patterns))
        elif isinstance(sig, TlsClientHelloSignature):
            for port in sig.ports:
                rules.extend(
                    FirewallRule(
                        "tls-sni-shadow",
                        port,
                        (
                            sig.u32_expr(),
                            sig.sni_hex_pattern(server_name),
                            server_name,
                        ),
                    )
                    for server_name in sig.server_names
                )
    return rules


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python3 -m prism_dpi.rule <app>", file=sys.stderr)
        return 2
    rules = emit(argv[0])
    if not rules:
        print(f"no Prism signature for '{argv[0]}'", file=sys.stderr)
        return 1
    for rule in rules:
        print("\t".join(rule.fields()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
