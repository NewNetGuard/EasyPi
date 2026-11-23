from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.openvpn_config import validate_openvpn_config
from app.services.vpn_client_service import VpnClientService

ROOT = Path(__file__).resolve().parents[2]
PROFILE = "client\ndev tun\nproto udp\nremote vpn.example.test 1194\n"


@pytest.mark.parametrize("directive", [
    "plugin /tmp/payload.so", "--plugin /tmp/payload.so", '"plugin" /tmp/payload.so',
    "'--plugin' /tmp/payload.so", '"up" /tmp/hook', "--config /tmp/other.conf",
    "management /tmp/socket unix", "providers /tmp/provider.so", "engine /tmp/engine.so",
    "script-security 2", "setenv opt plugin /tmp/payload.so", "ignore-unknown-option plugin",
    "ca /etc/shadow", '"cert" "/etc/shadow"', "key relative.key", "pkcs12 keys.p12",
    "auth-user-pass credentials", "auth-user-pass [inline]", "tls-auth ta.key 1",
    "tls-crypt /etc/shadow", "crl-verify /tmp/crl dir", "dh dh.pem", "capath /tmp/cas",
    "http-proxy proxy.test 80 /etc/shadow", "socks-proxy proxy.test 1080 /etc/shadow",
    "status /tmp/status", "writepid /tmp/pid", "replay-persist /tmp/replay",
    "tls-export-cert /tmp/certs", "askpass password", "dev-node /dev/anything",
    "log log.txt", "unknown-future-option safe-looking", "auth-user-pass extra extra",
    "remote /tmp/socket 1194", "client extra", "<connection>\nplugin /tmp/payload.so\n</connection>",
    "<ca>\nCERT\n</ca>junk\nplugin /tmp/payload.so\n</ca>",
    "<ca>\nCERT\n</key>", "<ca>\nCERT", "<up>\n/tmp/hook\n</up>",
    "<ca>\nCERT\n</ca>\n<ca>\nOTHER\n</ca>",
    "remote vpn.test 443\x00\nplugin /tmp/payload.so", "plu\\gin /tmp/payload.so",
    "#" + "x" * 254 + "\nplugin /tmp/payload.so",
    "<ca>\n" + "x" * 255 + "</ca>\nplugin /tmp/payload.so\n</ca>",
])
def test_unsafe_profiles_fail_at_import_and_standalone_boundary(tmp_path, directive):
    source = PROFILE + directive + "\n"
    with pytest.raises(ValueError):
        validate_openvpn_config(source)
    config = tmp_path / "profile.conf"
    config.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "backend/app/core/openvpn_config.py"), str(config)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert not result.stdout
    assert "payload.so" not in result.stderr


def test_provider_profile_is_canonical_and_preserves_inline_material():
    profile = PROFILE + """--nobind
"persist-key"
'persist-tun'
resolv-retry infinite
auth-user-pass
auth-nocache
remote-cert-tls server
verify-x509-name "Example VPN" name
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
tls-version-min 1.2
key-direction 1
--redirect-gateway def1
"route" 192.0.2.0 255.255.255.0
pull-filter ignore "redirect-gateway"
<ca>
-----BEGIN CERTIFICATE-----
SYNTHETIC/BASE64+DATA=
-----END CERTIFICATE-----
</ca>
<tls-auth>
# synthetic test key
0123456789abcdef
</tls-auth>
"""
    canonical = validate_openvpn_config(profile.replace("\n", "\r\n"))
    assert "--" not in canonical.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
    assert "auth-user-pass\n" in canonical
    assert 'verify-x509-name "Example VPN" name\n' in canonical
    assert "SYNTHETIC/BASE64+DATA=" in canonical
    assert "route 192.0.2.0 255.255.255.0\n" in canonical
    assert validate_openvpn_config(canonical) == canonical


def test_rejected_import_preserves_previous_config_and_metadata(tmp_path):
    service = VpnClientService()
    service._data_dir = tmp_path
    service._conf_path = tmp_path / "outbound_vpn.conf"
    service._meta_path = tmp_path / "outbound_vpn_meta.json"
    service.import_config(PROFILE)
    previous = service._conf_path.read_bytes(), service._meta_path.read_bytes()
    with pytest.raises(ValueError):
        service.import_config(PROFILE + '"--plugin" /tmp/payload.so\n')
    assert (service._conf_path.read_bytes(), service._meta_path.read_bytes()) == previous


def test_import_canonicalizes_quoted_remote_and_broker_credentials(tmp_path, monkeypatch):
    service = VpnClientService()
    service._data_dir = tmp_path
    service._conf_path = tmp_path / "outbound_vpn.conf"
    service._meta_path = tmp_path / "outbound_vpn_meta.json"
    monkeypatch.setattr(service, "_credentials_configured", lambda: False)
    result = service.import_config('client\n"--remote" vpn.example.test 443\n"auth-user-pass"\n')
    assert result["engine"] == "openvpn"
    assert result["requires_credentials"] is True
    assert result["endpoint"] == "vpn.example.test:443"
    assert service._conf_path.read_text() == "client\nremote vpn.example.test 443\nauth-user-pass\n"


INLINE_PROFILE = """<ca>
remote misleading.test 443
proto tcp-client
</ca>
<auth-user-pass>
auth-user-pass
route 192.0.2.0 255.255.255.0
</auth-user-pass>
""" + PROFILE


def test_inline_payloads_are_not_endpoint_or_credential_directives(tmp_path):
    service = VpnClientService()
    service._data_dir = tmp_path
    service._conf_path = tmp_path / "outbound_vpn.conf"
    service._meta_path = tmp_path / "outbound_vpn_meta.json"
    result = service.import_config(INLINE_PROFILE)
    assert result["endpoint"] == "vpn.example.test:1194"
    assert result["transport_protocol"] == "udp"
    assert result["requires_credentials"] is False


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux shell tools")
def test_runtime_helpers_leave_inline_payloads_untouched(tmp_path):
    script = (ROOT / "scripts/settings/outbound_vpn.sh").read_text()
    names = ["openvpn_option_lines", "openvpn_requires_credentials", "ovpn_server_ip", "sanitize_openvpn_routing"]
    functions = "\n".join(re.search(r"^" + name + r"\(\).*?^}\n", script, re.M | re.S).group(0) for name in names)
    # install's ownership change is irrelevant for this content-only test.
    functions = functions.replace("install -o root -g root -m 0600", "install -m 0600")
    config = tmp_path / "profile.conf"
    canonical = validate_openvpn_config(INLINE_PROFILE + "redirect-gateway def1\n")
    config.write_text(canonical)
    harness = f'RUNTIME_DIR="{tmp_path}"\nresolve_host_ip() {{ printf "%s" "$1"; }}\n' + functions + """
if openvpn_requires_credentials "$1"; then exit 91; fi
[[ "$(ovpn_server_ip "$1")" == "vpn.example.test" ]] || exit 92
sanitize_openvpn_routing "$1" || exit 93
"""
    result = subprocess.run(["bash", "-c", harness, "test", str(config)], capture_output=True)
    assert result.returncode == 0, result.stderr
    assert config.read_text() == canonical.replace("redirect-gateway def1\n", "")


@pytest.mark.skipif(sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0,
                    reason="root-owned validator boundary requires isolated Linux root tests")
def test_privileged_shell_rechecks_profiles_and_validator_permissions(tmp_path):
    # Exercise the actual shell function with only its fixed validator path
    # redirected to a root-owned test copy. No VPN daemon or routes are touched.
    validator = tmp_path / "validator.py"
    validator.write_bytes((ROOT / "backend/app/core/openvpn_config.py").read_bytes())
    validator.chmod(0o644)
    script = (ROOT / "scripts/settings/outbound_vpn.sh").read_text()
    function = script.split("validate_openvpn_config() {", 1)[1].split("\nopenvpn_requires_credentials()", 1)[0]
    function = "validate_openvpn_config() {" + function
    function = function.replace("/opt/EasyPi/backend/app/core/openvpn_config.py", str(validator))
    # /tmp has the sticky bit and is intentionally not a production trusted
    # ancestor. Use a private test root for ancestor checks, retaining file and
    # containing-directory ownership/mode checks.
    function = function.replace("(validator, *validator.parents)", "(validator, validator.parent)")
    config = tmp_path / "profile.conf"
    harness = f'RUNTIME_DIR="{tmp_path}"\nerr() {{ echo "$*" >&2; exit 1; }}\n' + function + '\nvalidate_openvpn_config "$1"\n'
    config.write_text(PROFILE + '"persist-tun"\n')
    result = subprocess.run(["bash", "-c", harness, "test", str(config)], capture_output=True)
    assert result.returncode == 0, result.stderr
    assert "persist-tun\n" in config.read_text()
    config.write_text(PROFILE + "--plugin /tmp/payload.so\n")
    result = subprocess.run(["bash", "-c", harness, "test", str(config)], capture_output=True)
    assert result.returncode != 0
    config.write_text(PROFILE)
    validator.chmod(0o666)
    result = subprocess.run(["bash", "-c", harness, "test", str(config)], capture_output=True)
    assert result.returncode != 0
    assert b"trusted OpenVPN validator is unavailable" in result.stderr
