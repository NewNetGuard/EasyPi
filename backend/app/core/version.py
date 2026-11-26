"""Single source of truth for the EasyPi product version.

The version lives in the repo-root ``VERSION`` file. The UI (via Vite), the API
(FastAPI ``version`` + ``/health``), the self-updater's downgrade guard and the
NetProtection engine all read that same file, so bumping the release is a
one-line edit to ``VERSION`` and nothing drifts.

If the file is somehow missing we fall back to a baked-in constant rather than
crash a version lookup — keep it in sync with ``VERSION`` as a last resort.
"""
from pathlib import Path

_FALLBACK = "1.1.10"


def _read_version() -> str:
    # version.py -> core -> app -> backend -> <repo root>/VERSION
    version_file = Path(__file__).resolve().parents[3] / "VERSION"
    try:
        value = version_file.read_text(encoding="utf-8").strip()
        return value or _FALLBACK
    except OSError:
        return _FALLBACK


__version__ = _read_version()


def get_version() -> str:
    """Return the EasyPi product version (read once at import time)."""
    return __version__
