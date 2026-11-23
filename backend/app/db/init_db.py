from __future__ import annotations

import json
import hashlib
import logging
import os
import secrets
import shutil
from sqlalchemy.engine import Engine
from sqlalchemy import text, inspect

from app.db.base import Base
from app.core.paths import get_data_dir, get_backend_data_dir

from app.core.security import get_password_hash, verify_password

logger = logging.getLogger(__name__)

# Setup token for first registration - use centralized paths
_setup_token: str | None = None
SETUP_TOKEN_FILE = get_data_dir() / ".setup_token"
LEGACY_SETUP_TOKEN_FILE = get_backend_data_dir() / ".setup_token"
RECOVERY_TOKEN_VERSION = 2
SETUP_TOKEN_HASH_PREFIX = "setup-token-sha256:"
RECOVERY_TOKEN_HASH_PREFIX = "recovery-token-sha256:"


def _read_token_file() -> str | None:
    _migrate_setup_token()
    if not SETUP_TOKEN_FILE.exists():
        return None
    raw = SETUP_TOKEN_FILE.read_text(encoding="utf-8").strip()
    return raw or None


def _parse_recovery_record(raw: str | None) -> dict[str, object] | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("kind") != "recovery_token_hash":
        return None
    return data


def _write_token_file(value: str) -> None:
    global _setup_token
    SETUP_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETUP_TOKEN_FILE.write_text(value, encoding="utf-8")
    try:
        os.chmod(SETUP_TOKEN_FILE, 0o600)
    except Exception:
        pass
    _setup_token = None


def _write_recovery_hash(token: str) -> None:
    payload = {
        "version": RECOVERY_TOKEN_VERSION,
        "kind": "recovery_token_hash",
        "token_hash": get_password_hash(token),
    }
    _write_token_file(json.dumps(payload, separators=(",", ":")))


def _migrate_setup_token() -> None:
    if SETUP_TOKEN_FILE.exists() or not LEGACY_SETUP_TOKEN_FILE.exists():
        return
    SETUP_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(LEGACY_SETUP_TOKEN_FILE, SETUP_TOKEN_FILE)
        try:
            os.chmod(SETUP_TOKEN_FILE, 0o600)
        except Exception:
            # Best-effort: permissions may be constrained on some filesystems.
            pass
        logger.info("Migrated setup token to %s", SETUP_TOKEN_FILE)
    except Exception as exc:
        logger.warning("Failed to migrate setup token: %s", exc)


def get_setup_token() -> str | None:
    """Get current setup token."""
    global _setup_token
    if _setup_token:
        return _setup_token
    raw = _read_token_file()
    if not raw:
        return None
    if _parse_recovery_record(raw) or raw.startswith(
        (SETUP_TOKEN_HASH_PREFIX, RECOVERY_TOKEN_HASH_PREFIX)
    ):
        return None
    return raw


def generate_setup_token() -> str:
    """Generate new setup token and save it."""
    global _setup_token
    token = secrets.token_urlsafe(32)
    _write_token_file(token)
    _setup_token = token
    return token


def ensure_setup_token() -> str | None:
    """Return the canonical first-registration token, creating it only once.

    The legacy backend-data token is deliberately ignored here: deployment
    bundles used to contain that directory, so accepting such a plaintext file
    on a clean installation could make the first-admin credential predictable.
    """
    global _setup_token
    if _setup_token:
        return _setup_token
    if SETUP_TOKEN_FILE.exists():
        raw = SETUP_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if raw.startswith((SETUP_TOKEN_HASH_PREFIX, RECOVERY_TOKEN_HASH_PREFIX)):
            return None
        if raw and not _parse_recovery_record(raw):
            _setup_token = raw
            return raw
    token = generate_setup_token()
    if LEGACY_SETUP_TOKEN_FILE.exists():
        try:
            LEGACY_SETUP_TOKEN_FILE.unlink()
            logger.info("Removed obsolete legacy setup-token file")
        except OSError as exc:
            logger.warning("Could not remove obsolete legacy setup-token file: %s", exc)
    return token


def _token_sha256(candidate: str) -> str:
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def has_setup_token() -> bool:
    raw = _read_token_file()
    if not raw or raw.startswith(RECOVERY_TOKEN_HASH_PREFIX):
        return False
    return not bool(_parse_recovery_record(raw))


def verify_setup_token(candidate: str) -> bool:
    raw = _read_token_file()
    if not raw:
        return False
    if raw.startswith(SETUP_TOKEN_HASH_PREFIX):
        expected = raw.removeprefix(SETUP_TOKEN_HASH_PREFIX)
        return secrets.compare_digest(_token_sha256(candidate), expected)
    if raw.startswith(RECOVERY_TOKEN_HASH_PREFIX) or _parse_recovery_record(raw):
        return False
    return secrets.compare_digest(candidate, raw)


def promote_setup_token_to_recovery(candidate: str) -> bool:
    if not verify_setup_token(candidate):
        return False
    raw = _read_token_file()
    if raw and raw.startswith(SETUP_TOKEN_HASH_PREFIX):
        digest = raw.removeprefix(SETUP_TOKEN_HASH_PREFIX)
        _write_token_file(f"{RECOVERY_TOKEN_HASH_PREFIX}{digest}")
    else:
        _write_recovery_hash(candidate)
    return True


def clear_setup_token() -> None:
    """Remove setup token after first user registration."""
    global _setup_token
    _setup_token = None
    if SETUP_TOKEN_FILE.exists():
        SETUP_TOKEN_FILE.unlink()


def has_recovery_token() -> bool:
    """Check whether a recovery token is configured in any supported format."""
    raw = _read_token_file()
    return bool(raw) and not raw.startswith(SETUP_TOKEN_HASH_PREFIX)


def ensure_recovery_token_hashed() -> bool:
    """
    Convert a legacy plaintext recovery token into a hashed on-disk record.

    Returns True if a legacy plaintext token was migrated.
    """
    raw = _read_token_file()
    if not raw or _parse_recovery_record(raw) or raw.startswith(
        (SETUP_TOKEN_HASH_PREFIX, RECOVERY_TOKEN_HASH_PREFIX)
    ):
        return False
    _write_recovery_hash(raw)
    logger.info("Migrated legacy plaintext recovery token to hashed storage")
    return True


def verify_recovery_token(candidate: str) -> bool:
    """Verify a recovery token against either the new hashed format or legacy plaintext."""
    raw = _read_token_file()
    if not raw:
        return False

    if raw.startswith(SETUP_TOKEN_HASH_PREFIX):
        return False
    if raw.startswith(RECOVERY_TOKEN_HASH_PREFIX):
        expected = raw.removeprefix(RECOVERY_TOKEN_HASH_PREFIX)
        return secrets.compare_digest(_token_sha256(candidate), expected)

    record = _parse_recovery_record(raw)
    if record:
        token_hash = record.get("token_hash")
        if not isinstance(token_hash, str):
            return False
        try:
            return verify_password(candidate, token_hash)
        except Exception:
            logger.warning("Stored recovery token hash is invalid")
            return False

    matched = secrets.compare_digest(candidate, raw)
    if matched:
        # One-time migration path for deployments that still have plaintext recovery tokens.
        _write_recovery_hash(raw)
        logger.warning("Recovered using legacy plaintext recovery token; token was migrated to hashed storage")
    return matched


def ensure_user_columns(engine: Engine, *, strict: bool = False) -> None:
    """Ensure all required columns exist in the users table.
    
    This handles migrations for columns added after initial deployment.
    """
    try:
        inspector = inspect(engine)
        if 'users' not in inspector.get_table_names():
            return  # Table doesn't exist yet, will be created by create_all
        
        existing_columns = {col['name'] for col in inspector.get_columns('users')}
        
        # Columns that might be missing and need to be added
        columns_to_add = [
            ('last_login_ip', 'VARCHAR(45)'),
            ('last_login_user_agent', 'TEXT'),
            ('totp_secret', 'TEXT'),
            ('totp_enabled', 'BOOLEAN DEFAULT 0'),
            ('backup_codes', 'TEXT'),
        ]
        
        with engine.connect() as conn:
            for col_name, col_type in columns_to_add:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(f'ALTER TABLE users ADD COLUMN {col_name} {col_type}'))
                        conn.commit()
                        logger.info(f"Added missing column: users.{col_name}")
                    except Exception as e:
                        # Column might already exist (race condition) or other issue
                        logger.debug(f"Could not add column {col_name}: {e}")
                        if strict:
                            raise
    except Exception as e:
        logger.warning(f"Could not check/add user columns: {e}")
        if strict:
            raise


def ensure_dns_deploy_security_columns(engine: Engine, *, strict: bool = False) -> None:
    """Migrate legacy DNS history without retaining WireGuard private keys."""
    try:
        inspector = inspect(engine)
        if "dns_deploys" not in inspector.get_table_names():
            return

        existing_columns = {
            column["name"] for column in inspector.get_columns("dns_deploys")
        }
        with engine.begin() as conn:
            if "wireguard_installed" not in existing_columns:
                conn.execute(
                    text(
                        "ALTER TABLE dns_deploys ADD COLUMN "
                        "wireguard_installed BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
            if "wireguard_config" in existing_columns:
                conn.execute(
                    text(
                        "UPDATE dns_deploys "
                        "SET wireguard_installed = CASE "
                        "WHEN wireguard_config IS NOT NULL "
                        "AND wireguard_config <> '' THEN 1 ELSE 0 END"
                    )
                )
                conn.execute(
                    text(
                        "UPDATE dns_deploys SET wireguard_config = NULL "
                        "WHERE wireguard_config IS NOT NULL"
                    )
                )
    except Exception as exc:
        logger.warning("Could not secure DNS deployment history: %s", exc)
        if strict:
            raise


def ensure_camera_ptz_columns(engine: Engine, *, strict: bool = False) -> None:
    """Ensure the PTZ columns exist on the ``cameras`` table.

    Production schemas are built by ``create_all`` + these ``ensure_*`` helpers,
    not ``alembic upgrade`` -- and ``create_all`` does NOT add columns to an
    existing table. If the PTZ columns were on the model but missing from the
    physical table, every ``Camera`` query would fail and the whole camera
    section would go down, so this must run before requests are served. All
    columns are nullable/defaulted and additive: existing rows and the RTSP URLs
    are untouched.
    """
    try:
        inspector = inspect(engine)
        if "cameras" not in inspector.get_table_names():
            return  # will be created by create_all with the columns already present

        existing_columns = {col["name"] for col in inspector.get_columns("cameras")}

        columns_to_add = [
            ("ptz_adapter", "VARCHAR(32)"),
            ("ptz_detected", "BOOLEAN DEFAULT 0"),
            ("ptz_capabilities_json", "TEXT"),
            ("ptz_profile_token", "VARCHAR(255)"),
            ("ptz_configuration_token", "VARCHAR(255)"),
            ("ptz_last_probe_at", "DATETIME"),
            ("ptz_probe_error", "VARCHAR(255)"),
            ("ptz_username", "VARCHAR(100)"),
            ("ptz_secret", "VARCHAR(255)"),
            ("onvif_port", "INTEGER"),
        ]

        with engine.connect() as conn:
            for col_name, col_type in columns_to_add:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(f"ALTER TABLE cameras ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                        logger.info(f"Added missing column: cameras.{col_name}")
                    except Exception as e:
                        logger.debug(f"Could not add column {col_name}: {e}")
                        if strict:
                            raise
    except Exception as e:
        logger.warning(f"Could not check/add camera PTZ columns: {e}")
        if strict:
            raise


def ensure_ai_columns(engine: Engine, *, strict: bool = False) -> None:
    """Bring legacy AI tables in line with the current ORM models."""
    additions = {
        "ai_conversations": [
            ("created_at", "DATETIME"),
            ("model", "VARCHAR(50) DEFAULT 'qwen2.5:3b'"),
        ],
        "ai_config": [
            ("installed_at", "DATETIME"),
        ],
    }
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        with engine.connect() as conn:
            for table_name, columns in additions.items():
                if table_name not in tables:
                    continue
                existing = {
                    column["name"] for column in inspector.get_columns(table_name)
                }
                for column_name, column_type in columns:
                    if column_name in existing:
                        continue
                    conn.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {column_name} {column_type}"
                        )
                    )
                    logger.info("Added missing column: %s.%s", table_name, column_name)
            conn.commit()
    except Exception as exc:
        logger.warning("Could not check/add AI columns: %s", exc)
        if strict:
            raise


def ensure_mobile_device_columns(engine: Engine, *, strict: bool = False) -> None:
    """Add mobile-device fields required by newer binaries to existing installs."""
    try:
        inspector = inspect(engine)
        if "mobile_devices" not in inspector.get_table_names():
            return
        existing_columns = {
            column["name"] for column in inspector.get_columns("mobile_devices")
        }
        columns_to_add = {
            "photo_folder": "VARCHAR(100)",
            "protection_client_id": "VARCHAR(16)",
            "chameleon_address": "VARCHAR(64)",
            "home_tunnel_public_key": "VARCHAR(512)",
            "home_tunnel_address": "VARCHAR(64)",
            "home_tunnel_state": "VARCHAR(16) NOT NULL DEFAULT 'inactive'",
            "home_tunnel_credential_epoch": "INTEGER NOT NULL DEFAULT 0",
            "home_tunnel_last_handshake_at": "DATETIME",
        }
        with engine.begin() as conn:
            for column_name, column_type in columns_to_add.items():
                if column_name in existing_columns:
                    continue
                conn.execute(
                    text(
                        "ALTER TABLE mobile_devices "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                logger.info("Added missing column: mobile_devices.%s", column_name)
    except Exception as exc:
        logger.warning("Could not update mobile device columns: %s", exc)
        if strict:
            raise


def validate_runtime_schema(engine: Engine) -> None:
    """Fail when an additive runtime migration left a required column missing."""
    required_columns = {
        "users": {
            "last_login_ip",
            "last_login_user_agent",
            "totp_secret",
            "totp_enabled",
            "backup_codes",
        },
        "dns_deploys": {"wireguard_installed"},
        "cameras": {
            "ptz_adapter",
            "ptz_detected",
            "ptz_capabilities_json",
            "ptz_profile_token",
            "ptz_configuration_token",
            "ptz_last_probe_at",
            "ptz_probe_error",
            "ptz_username",
            "ptz_secret",
            "onvif_port",
        },
        "ai_conversations": {"created_at", "model"},
        "ai_config": {"installed_at"},
        "mobile_devices": {
            "photo_folder",
            "protection_client_id",
            "chameleon_address",
            "home_tunnel_public_key",
            "home_tunnel_address",
            "home_tunnel_state",
            "home_tunnel_credential_epoch",
            "home_tunnel_last_handshake_at",
        },
    }
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    problems: list[str] = []
    for table_name, expected in required_columns.items():
        if table_name not in tables:
            problems.append(f"missing table {table_name}")
            continue
        actual = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        missing = sorted(expected - actual)
        if missing:
            problems.append(f"{table_name}: missing {', '.join(missing)}")
    if problems:
        raise RuntimeError("Runtime schema validation failed: " + "; ".join(problems))


def init_db(engine: Engine = None) -> None:
    """Ensure all tables are created."""
    if engine is None:
        from app.db.session import engine as default_engine
        engine = default_engine
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Ensure all required columns exist (handles migrations)
    ensure_user_columns(engine, strict=True)
    ensure_dns_deploy_security_columns(engine, strict=True)
    ensure_camera_ptz_columns(engine, strict=True)
    ensure_ai_columns(engine, strict=True)
    ensure_mobile_device_columns(engine, strict=True)
    validate_runtime_schema(engine)
    
    # Check and clean up default admin user if exists
    try:
        from sqlalchemy.orm import Session
        with Session(engine) as session:
            from app.models.user import User
            from app.core.security import verify_password
            
            # Find and delete default admin with default password
            default_admin = session.query(User).filter(
                User.username == "admin",
                User.email == "admin@easypi.local"
            ).first()
            
            if default_admin:
                # Check if password is still the default (admin123)
                if verify_password("admin123", default_admin.password_hash):
                    session.delete(default_admin)
                    session.commit()
                    logger.debug("Removed default admin user for security")
    except Exception as e:
        logger.debug(f"Could not check for default admin: {e}")
    
    # Check if there are any users, if not - generate setup token
    try:
        from sqlalchemy.orm import Session
        with Session(engine) as session:
            from app.models.user import User
            user_count = session.query(User).count()
            
            if user_count == 0:
                # Keep the per-install token stable until the first administrator
                # completes registration. The installer reads the root data file
                # once and displays it directly; the backend never logs the secret.
                ensure_setup_token()
                logger.info("First-registration setup token is ready")
                
                logger.info("=" * 60)
                logger.info("NO USERS FOUND - FIRST TIME SETUP")
                logger.info("=" * 60)
                logger.info("Open web panel to register first admin user")
                logger.info("=" * 60)
            else:
                # Users exist - keep the token only as a hashed recovery secret.
                if ensure_recovery_token_hashed():
                    logger.info("Recovery token migrated to hashed storage")
                if not has_recovery_token():
                    logger.warning("No recovery token found (setup token file missing).")
                logger.info(f"Database initialized with {user_count} existing user(s)")
    except Exception as e:
        logger.warning(f"Could not check user count: {e}")
    
    logger.info("Database initialized")


__all__ = [
    "init_db",
    "get_setup_token",
    "ensure_setup_token",
    "has_setup_token",
    "verify_setup_token",
    "promote_setup_token_to_recovery",
    "clear_setup_token",
    "has_recovery_token",
    "ensure_recovery_token_hashed",
    "ensure_dns_deploy_security_columns",
    "ensure_camera_ptz_columns",
    "ensure_ai_columns",
    "ensure_mobile_device_columns",
    "validate_runtime_schema",
    "verify_recovery_token",
]
