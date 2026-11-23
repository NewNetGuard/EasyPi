from __future__ import annotations

from pathlib import Path

from app.db import init_db


def test_hashed_setup_token_is_single_use(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / ".setup_token"
    monkeypatch.setattr(init_db, "SETUP_TOKEN_FILE", token_file)
    monkeypatch.setattr(
        init_db, "LEGACY_SETUP_TOKEN_FILE", tmp_path / ".legacy_setup_token"
    )
    monkeypatch.setattr(init_db, "_setup_token", None)

    token = "one-time-random-token"
    digest = init_db._token_sha256(token)
    token_file.write_text(
        f"{init_db.SETUP_TOKEN_HASH_PREFIX}{digest}", encoding="utf-8"
    )

    assert token not in token_file.read_text(encoding="utf-8")
    assert init_db.get_setup_token() is None
    assert init_db.ensure_setup_token() is None
    assert init_db.has_setup_token() is True
    assert init_db.verify_setup_token(token) is True
    assert init_db.verify_setup_token("wrong") is False
    assert init_db.verify_recovery_token(token) is False

    assert init_db.promote_setup_token_to_recovery(token) is True
    assert init_db.has_setup_token() is False
    assert init_db.verify_setup_token(token) is False
    assert init_db.verify_recovery_token(token) is True
    assert token not in token_file.read_text(encoding="utf-8")
