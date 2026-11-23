from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import Any

import main


def _flatten_http_routes(item: Any) -> Iterator[tuple[str, frozenset[str], Any]]:
    """Expand FastAPI's lazy included routers in their effective match order."""

    candidates = getattr(item, "effective_candidates", None)
    low_priority = getattr(item, "effective_low_priority_routes", None)
    if callable(candidates) and callable(low_priority):
        for child in candidates():
            yield from _flatten_http_routes(child)
        for child in low_priority():
            yield from _flatten_http_routes(child)
        return

    path = getattr(item, "path", None)
    methods = frozenset(getattr(item, "methods", set()) or set())
    path_regex = getattr(item, "path_regex", None)
    if path and methods and path_regex is not None:
        yield path, methods, path_regex


def _application_http_routes() -> list[tuple[str, frozenset[str], Any]]:
    routes: list[tuple[str, frozenset[str], Any]] = []
    for route in main.app.routes:
        routes.extend(_flatten_http_routes(route))
    return routes


def test_static_api_routes_are_not_shadowed_by_dynamic_routes() -> None:
    routes = _application_http_routes()
    shadows: list[tuple[str, str, tuple[str, ...]]] = []

    for index, (path, methods, path_regex) in enumerate(routes):
        if "{" not in path:
            continue
        for later_path, later_methods, _later_regex in routes[index + 1 :]:
            overlap = methods & later_methods
            if overlap and "{" not in later_path and path_regex.fullmatch(later_path):
                shadows.append((path, later_path, tuple(sorted(overlap))))

    assert shadows == []


def test_application_has_no_duplicate_http_method_and_path_pairs() -> None:
    route_keys = Counter(
        (method, path)
        for path, methods, _path_regex in _application_http_routes()
        for method in methods
    )

    assert {key: count for key, count in route_keys.items() if count > 1} == {}
