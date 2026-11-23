from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads(
    (ROOT / "tests" / "acceptance" / "acceptance_manifest.json").read_text(encoding="utf-8")
)


def test_manifest_has_unique_complete_areas() -> None:
    areas = MANIFEST["areas"]
    identifiers = [area["id"] for area in areas]
    assert len(identifiers) == len(set(identifiers))
    assert len(areas) >= 15
    for area in areas:
        assert area["name"]
        assert area["ui_routes"] or area["api_prefixes"]
        assert area["checks"]
        assert area["automation"] in {"automated", "partial", "staged"}
        assert area["risk"]


def test_every_named_frontend_route_is_catalogued() -> None:
    source = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    declared = {
        path if path.startswith("/") else f"/{path}"
        for path in re.findall(r'<Route\s+path="([^"*]+)"', source)
        if path and path != "/"
    }
    catalogued = {route for area in MANIFEST["areas"] for route in area["ui_routes"]}
    assert declared <= catalogued, f"uncatalogued UI routes: {sorted(declared - catalogued)}"


def test_profiles_reference_known_checks() -> None:
    known = {
        "inventory",
        "acceptance-tests",
        "ruff",
        "shell-syntax",
        "security-tests",
        "agent-tests",
        "frontend-lint",
        "frontend-types",
        "browser-test-list",
        "frontend-build",
        "chameleon-tests",
        "live-http",
        "remote-services",
        "browser-public",
        "browser-authenticated",
        "browser-safe-interactions",
        "browser-user-lifecycle",
        "browser-picloud-lifecycle",
        "browser-files-lifecycle",
        "browser-agent-live",
        "browser-network-observe",
        "browser-operations-live",
        "browser-marketplace-help",
        "browser-backup-live",
        "browser-dns-rewrite-live",
        "guard-dns-filter",
        "prism-flow-observe",
        "release-signature-reject",
        "chameleon-reconnect",
        "chameleon-network-recovery",
        "chameleon-runtime-connectivity",
        "wireguard-lifecycle",
        "camera-security-tests",
        "camera-go2rtc-boundary",
        "operations-security-tests",
        "marketplace-help-security-tests",
    }
    for checks in MANIFEST["profiles"].values():
        assert checks
        assert set(checks) <= known


def test_live_profile_is_read_only_by_construction() -> None:
    assert MANIFEST["principles"]["default_live_mode"] == "read_only"
    assert MANIFEST["profiles"]["live-readonly"] == [
        "inventory",
        "live-http",
        "remote-services",
    ]
