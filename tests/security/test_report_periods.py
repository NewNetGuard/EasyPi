"""Report periods never reach past the 7 days the DNS flow log keeps.

The flow log keeps 7 days of queries, so a 30-day choice would quietly show
the same 7 days. The API accepts only periods the log can actually answer.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.endpoints.netprotection_api import dashboard, policy
from app.api.v1.endpoints import heuristics
from easypi_netprotection.chronicle.flow_log import DEFAULT_RETENTION_DAYS


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(dashboard.router)
    app.include_router(policy.router)
    app.include_router(heuristics.router, prefix="/heuristics")
    for module in (dashboard, policy, heuristics):
        app.dependency_overrides[module.require_admin] = lambda: object()
    return TestClient(app, raise_server_exceptions=False)


PERIOD_ROUTES = [
    "/stats",
    "/analytics",
    "/analytics/device?client_id=abc",
    "/verdicts/stats",
    "/blocked-overview",
]


def test_flow_log_keeps_seven_days() -> None:
    assert DEFAULT_RETENTION_DAYS == 7


@pytest.mark.parametrize("route", PERIOD_ROUTES)
def test_thirty_day_period_is_rejected(client: TestClient, route: str) -> None:
    sep = "&" if "?" in route else "?"
    assert client.get(f"{route}{sep}period=30d").status_code == 422


@pytest.mark.parametrize("route", PERIOD_ROUTES)
@pytest.mark.parametrize("period", ["24h", "7d"])
def test_supported_periods_pass_validation(
    client: TestClient, route: str, period: str
) -> None:
    sep = "&" if "?" in route else "?"
    assert client.get(f"{route}{sep}period={period}").status_code != 422


def test_ad_tracker_month_range_is_rejected(client: TestClient) -> None:
    assert client.get("/heuristics/ad-tracker/stats?range=month").status_code == 422
    for allowed in ("today", "week"):
        response = client.get(f"/heuristics/ad-tracker/stats?range={allowed}")
        assert response.status_code != 422
