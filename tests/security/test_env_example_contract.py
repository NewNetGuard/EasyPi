from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from config import Settings  # noqa: E402


def test_default_installer_environment_is_accepted_by_backend() -> None:
    settings = Settings(_env_file=ROOT / ".env.example")

    assert settings.EASYPI_WEBPUSH_ALLOWED_HOSTS == ""
