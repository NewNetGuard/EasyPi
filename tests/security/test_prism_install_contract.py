from pathlib import Path


def _text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_clean_install_requires_prism_enforcement() -> None:
    installer = _text("install.sh")
    setup = installer[
        installer.index("setup_prism_flowgraph() {") : installer.index(
            "retire_prism_experiments() {"
        )
    ]

    assert "PRISM FlowGraph and exact-flow enforcement" in setup
    assert "PRISM FlowGraph enforcement could not be established" in setup
    assert "PRISM FlowGraph installation failed" not in setup
    assert "skipping" not in setup.lower()


def test_flowgraph_service_requires_firewall_foundation() -> None:
    setup = _text("scripts/settings/setup_prism_flowgraph.sh")

    assert "verify_shadow_setup" in setup
    assert "Prism shadow setup must be root-owned" in setup
    assert "Prism shadow setup must not be group/other writable" in setup
    assert "Requires=easypi-prism-shadow.service" in setup
    assert "After=network-online.target easypi-prism-shadow.service" in setup
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE" in setup
    assert "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE" in setup
    assert setup.index('write_shadow_unit') < setup.index('write_unit')
    assert setup.index('restart "$SHADOW_SERVICE"') < setup.index(
        'restart "$SERVICE"'
    )
    assert 'is-active --quiet "$SHADOW_SERVICE"' in setup
    assert 'is-active --quiet "$SERVICE"' in setup


def test_prism_enforcer_repairs_only_its_own_missing_runtime_state() -> None:
    shadow = _text("scripts/settings/setup_prism_shadow.sh")

    for module in ("ip_set", "ip_set_hash_ip", "ip_set_hash_ipportip", "xt_set"):
        assert f'"$MODPROBE" {module}' in shadow

    ready = shadow[
        shadow.index("shadow_enforcement_ready() {") : shadow.index(
            "enable_shadow() {"
        )
    ]
    assert '-C FORWARD -j "$CHAIN"' in ready
    assert '"$FLOW_BLOCK_SET"' in ready
    assert '"$FLOW_RESET_SET"' in ready
    assert ready.count(' -j DROP') == 4
    assert ready.count(' --reject-with tcp-reset') == 2

    add_flow = shadow[
        shadow.index("add_candidate_flow() {") : shadow.index(
            "block_candidate_flow() {"
        )
    ]
    stream = shadow[
        shadow.index("flow_block_stream() {") : shadow.index(
            "enable_canary() {"
        )
    ]
    assert "ensure_shadow_enforcement" in add_flow
    assert "ensure_shadow_enforcement" in stream
    assert 'enable_shadow >&2' in shadow
    assert 'echo "Prism enforcement ready"' in shadow


def test_prism_boot_guard_is_removed_by_uninstall() -> None:
    uninstall = _text("uninstall.sh")

    assert "easypi-prism-shadow.service" in uninstall
    assert "scripts/settings/setup_prism_shadow.sh disable" in uninstall
