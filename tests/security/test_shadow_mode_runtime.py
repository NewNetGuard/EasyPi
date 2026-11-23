from __future__ import annotations

import ast
from importlib.util import resolve_name
from pathlib import Path


def test_policy_checks_resolve_heuristics_from_the_package_root() -> None:
    source = (
        Path(__file__).parents[2]
        / "easypi_netprotection/verdict/engine_components/policy_checks.py"
    ).read_text(encoding="utf-8")
    imports = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("heuristics")
    ]

    assert imports
    assert {
        resolve_name(
            "." * node.level + node.module,
            "easypi_netprotection.verdict.engine_components",
        )
        for node in imports
    } == {
        "easypi_netprotection.heuristics",
        "easypi_netprotection.heuristics.shadow_mode",
    }
