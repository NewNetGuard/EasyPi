"""
EasyPi NetProtection — CLI Entry Point.

Standalone DNS server with command-line arguments support.

Usage:
    python -m easypi_netprotection.server [OPTIONS]
    
Options:
    --config PATH       Path to TOML config file
    --port PORT         Override listener port (default: 5454)
    --host HOST         Override listener address (default: 0.0.0.0)
    --debug             Enable debug logging
    --version           Show version and exit
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from easypi_netprotection import __version__
from easypi_netprotection.config import load_config, NetProtectionSettings
from easypi_netprotection.server import NetProtectionServer, setup_signal_handlers

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="easypi-netprotection",
        description="EasyPi NetProtection DNS Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m easypi_netprotection.server
    python -m easypi_netprotection.server --port 5454
    python -m easypi_netprotection.server --config /etc/easypi/netprotection.toml
    python -m easypi_netprotection.server --debug
        """,
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"EasyPi NetProtection v{__version__}",
    )
    
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=None,
        help="Path to TOML configuration file",
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override listener port (default: from config or 5454)",
    )
    
    parser.add_argument(
        "--host", "-H",
        type=str,
        default=None,
        help="Override listener address (default: 0.0.0.0)",
    )
    
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging",
    )
    
    parser.add_argument(
        "--foreground", "-f",
        action="store_true",
        default=True,
        help="Run in foreground (default)",
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show cache/analyzer statistics and exit",
    )
    
    return parser.parse_args()


def setup_logging(debug: bool = False) -> None:
    """Configure logging for systemd/journald."""
    level = logging.DEBUG if debug else logging.INFO
    
    # Check if running under systemd (no TTY)
    if not sys.stdout.isatty():
        # Systemd/journald - simple format without timestamps (journald adds them)
        fmt = "[%(levelname)s] %(name)s: %(message)s"
    else:
        # Terminal - full format
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    logging.basicConfig(
        level=level,
        format=fmt,
        stream=sys.stdout,
    )
    
    # Reduce noise from libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("dns").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def check_port_available(host: str, port: int) -> tuple[bool, str]:
    """
    Check if port is available for binding.
    
    Returns:
        (available, error_message)
    """
    import socket
    
    # Check UDP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.close()
    except OSError as e:
        return False, f"UDP port {port} unavailable: {e}"
    
    # Check TCP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.close()
    except OSError as e:
        return False, f"TCP port {port} unavailable: {e}"
    
    return True, ""


async def run_server_cli(args: argparse.Namespace) -> int:
    """
    Run server with CLI arguments.
    
    Returns:
        Exit code (0 = success, 1 = error, 2 = port unavailable)
    """
    # Load configuration
    if args.config:
        if not args.config.exists():
            logger.error("Config file not found: %s", args.config)
            return 1
        config = NetProtectionSettings.from_toml(args.config)
    else:
        config = load_config()
    
    # Override from CLI args
    if args.port:
        config.listener.port = args.port
    if args.host:
        config.listener.address = args.host
    if args.debug:
        config.debug = True
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PRE-FLIGHT: Check port availability BEFORE starting
    # ═══════════════════════════════════════════════════════════════════════════
    port_available, port_error = check_port_available(
        config.listener.address,
        config.listener.port
    )
    
    if not port_available:
        logger.error("=" * 60)
        logger.error("  FATAL: Cannot bind to port %d", config.listener.port)
        logger.error("  %s", port_error)
        logger.error("=" * 60)
        logger.error("  Possible causes:")
        logger.error("  - Another DNS server is running (NetProtection, dnsmasq, systemd-resolved)")
        logger.error("  - Previous instance didn't shut down cleanly")
        logger.error("  - Port 53 requires root or CAP_NET_BIND_SERVICE capability")
        logger.error("=" * 60)
        logger.error("  Check with: sudo ss -tlnp | grep %d", config.listener.port)
        logger.error("=" * 60)
        return 2  # Special exit code for port conflict
    
    # Log startup info (never log sensitive data like salt)
    logger.info("=" * 60)
    logger.info("  EasyPi NetProtection DNS Server v%s", __version__)
    logger.info("=" * 60)
    logger.info("  Listen: %s:%d", config.listener.address, config.listener.port)
    logger.info("  UDP: %s, TCP: %s", config.listener.enable_udp, config.listener.enable_tcp)
    logger.info("  Config: %s", args.config or "default")
    logger.info("  Salt: loaded from env/file (not logged for security)")
    logger.info("=" * 60)
    
    # Create and run server
    server = NetProtectionServer(config=config)
    setup_signal_handlers(server)
    
    try:
        await server.start()
        logger.info("NetProtection DNS server started successfully")
        await server.wait_for_shutdown()
        return 0
    except OSError as e:
        if "Address already in use" in str(e):
            logger.error("Port %d became unavailable during startup", config.listener.port)
            return 2
        logger.error("Server error: %s", e)
        return 1
    except Exception as e:
        logger.error("Server error: %s", e)
        return 1
    finally:
        await server.stop()
        logger.info("NetProtection DNS server stopped")


def show_stats() -> int:
    """Show cache and analyzer statistics."""
    from datetime import datetime
    from .verdict.engine import VerdictEngine
    from .config import load_config
    
    try:
        config = load_config(None)
        engine = VerdictEngine(config)
        health = engine.get_cache_health()
        
        print("=" * 60)
        print("  EasyPi NetProtection - Cache & Analyzer Statistics")
        print("=" * 60)
        print(f"\n  Status: {health.get('status', 'unknown')}")
        print(f"  Timestamp: {datetime.now().isoformat()}")
        
        # CNAME Cache stats
        cname = health.get('cname_cache', {})
        if cname:
            print("\n  CNAME Cache:")
            if 'error' in cname:
                print(f"    Error: {cname['error']}")
            else:
                print(f"    Size: {cname.get('size', 0)}/{cname.get('max_size', 0)}")
                print(f"    Hit Rate: {cname.get('hit_rate', 0):.1f}%")
        
        # Get more detailed stats from analyzer
        try:
            from .intel.cname_chain import get_cname_analyzer
            analyzer = get_cname_analyzer()
            stats = analyzer.get_stats()
            print("\n  CNAME Analyzer:")
            print(f"    Chains Analyzed: {stats.get('chains_analyzed', 0)}")
            print(f"    Trackers Found: {stats.get('trackers_found', 0)}")
            print(f"    Cycles Detected: {stats.get('cycles_detected', 0)}")
            print(f"    Chain Truncations: {stats.get('truncations', 0)}")
        except ImportError:
            print("\n  CNAME Analyzer: not available")
        
        # Blocklist stats (from filter)
        try:
            domains_count = len(engine._filter._domains) if hasattr(engine._filter, '_domains') else 0
            print("\n  Blocklist:")
            print(f"    Loaded Domains: {domains_count}")
        except Exception:
            pass
        
        # Warnings
        warnings = health.get('warnings', [])
        if warnings:
            print("\n  ⚠️  Warnings:")
            for w in warnings:
                print(f"    - {w}")
        
        print("\n" + "=" * 60)
        return 0
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main() -> None:
    """CLI entry point."""
    args = parse_args()
    setup_logging(args.debug)
    
    # Handle --stats flag
    if args.stats:
        sys.exit(show_stats())
    
    try:
        exit_code = asyncio.run(run_server_cli(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()



