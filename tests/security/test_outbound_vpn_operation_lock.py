from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTBOUND_VPN_SCRIPT = ROOT / "scripts" / "settings" / "outbound_vpn.sh"


def test_openvpn_daemon_does_not_inherit_operation_lock() -> None:
    script = OUTBOUND_VPN_SCRIPT.read_text(encoding="utf-8")

    openvpn_start = script.index('openvpn --config "$OVPN_CONF"')
    readiness_loop = script.index("local i", openvpn_start)
    launch = script[openvpn_start:readiness_loop]

    assert "--daemon easypi-ovpn" in launch
    assert "9>&-" in launch
