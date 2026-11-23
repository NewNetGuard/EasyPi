from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_marketplace_has_no_backend_route_or_install_transport() -> None:
    api_router = _read("backend/app/api/v1/router.py")
    marketplace = _read("frontend/src/components/marketplace/Marketplace.tsx")
    card = _read("frontend/src/components/marketplace/PluginCard.tsx")

    assert "marketplace_router" not in api_router
    assert "/api/v1/marketplace" not in marketplace
    assert "fetch(" not in marketplace
    assert "disabled" in card


def test_marketplace_preview_does_not_publish_fabricated_usage_metrics() -> None:
    marketplace = _read("frontend/src/components/marketplace/Marketplace.tsx")
    card = _read("frontend/src/components/marketplace/PluginCard.tsx")

    assert "rating:" not in marketplace
    assert "downloads:" not in marketplace
    assert "plugin.rating" not in card
    assert "plugin.downloads" not in card


def test_help_keeps_search_and_diagnostics_in_memory_only() -> None:
    store = _read("frontend/src/stores/helpStore.ts")
    help_page = _read("frontend/src/pages/Help.tsx")

    assert "persist(" not in store
    assert "localStorage.setItem" not in store
    assert "lastError" not in store
    assert "recentSearches," not in help_page.split("const diagnosticPayload", 1)[1].split(")", 1)[0]
    assert "navigator.userAgent" not in help_page


def test_help_does_not_claim_that_an_unconnected_form_sent_data() -> None:
    help_page = _read("frontend/src/pages/Help.tsx")
    help_content = _read("frontend/src/data/helpContent.ts")

    assert "Sent!" not in help_page
    assert "handleSupportSubmit" not in help_page
    assert "support@easypi.local" not in help_content
    assert "discord.gg/easypi" not in help_content
    assert 'rel="noopener noreferrer"' in help_page


def test_all_help_navigation_targets_resolve_to_application_routes() -> None:
    app = _read("frontend/src/App.tsx")
    help_content = _read("frontend/src/data/helpContent.ts")
    app_routes = {
        "/" + route
        for route in re.findall(r'<Route\s+path="([^"*]+)"', app)
        if route and route != "/"
    }
    app_routes.update({"/", "*"})

    declared_routes = set(re.findall(r"route:\s*'([^']+)'", help_content))
    related_routes = {
        route
        for block in re.findall(r"related:\s*\[([^]]*)\]", help_content)
        for route in re.findall(r"'([^']+)'", block)
    }

    assert declared_routes | related_routes <= app_routes


def test_help_search_input_is_bounded_and_references_are_described_honestly() -> None:
    help_page = _read("frontend/src/pages/Help.tsx")
    help_content = _read("frontend/src/data/helpContent.ts")

    assert help_page.count("maxLength={96}") == 2
    assert "Help search references" in help_page
    assert "Marketplace service did not start" not in help_content
    assert "Marketplace could not find specified service" not in help_content
