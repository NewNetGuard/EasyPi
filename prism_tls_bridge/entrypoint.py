"""Explicit binary modes dispatched before any backend/ASGI initialization."""

import json
import sys


def dispatch(arguments):
    if not arguments or not arguments[0].startswith("--prism-tls-"):
        return None
    mode = arguments[0]
    if mode == "--prism-tls-check":
        if len(arguments) != 1:
            raise SystemExit("--prism-tls-check takes no arguments")
        import ctypes.util
        from . import __version__
        from .bridge import Bridge
        from .quic import AdaptiveQUICSession
        from .shadow import ShadowSupervisor
        import cryptography
        import hpack
        import aioquic
        import pylsqpack
        from .tls import Secrets

        bridge = Bridge()
        bridge.close()
        decoder = AdaptiveQUICSession(Secrets(), lambda event: None)
        supervisor = ShadowSupervisor()
        if decoder.failed or supervisor.enabled:
            raise RuntimeError("invalid shadow default state")
        versions = {
            module.__name__: getattr(module, "__version__", "unknown")
            for module in (cryptography, hpack, aioquic, pylsqpack)
        }
        print(
            json.dumps(
                dict(
                    component="prism_tls_endpoint_bridge",
                    version=__version__,
                    mode="shadow_only",
                    default_enabled=False,
                    protocols=["TLS1.3/HTTP2", "QUICv1/HTTP3"],
                    dependencies=versions,
                    libpcap_available=bool(ctypes.util.find_library("pcap")),
                )
            )
        )
        return 0
    if mode not in {"--prism-tls-shadow", "--prism-tls-child", "--prism-tls-chrome"}:
        raise SystemExit("unknown Prism TLS mode")
    old = sys.argv
    try:
        sys.argv = [old[0]] + list(arguments[1:])
        if mode == "--prism-tls-child":
            from .shadow_child import main
        elif mode == "--prism-tls-chrome":
            from .chrome_agent import main
        else:
            from .shadow_agent import main
        result = main()
        return result if isinstance(result, int) else 0
    finally:
        sys.argv = old


if __name__ == "__main__":
    result = dispatch(sys.argv[1:])
    if result is None:
        raise SystemExit(
            "explicit --prism-tls-check or --prism-tls-shadow mode required"
        )
    raise SystemExit(result)
