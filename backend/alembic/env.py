from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import os
import sys
from pathlib import Path
import pkgutil
import importlib

# === Add project path ( .. = backend/ ) ===
from app.core.paths import get_backend_dir
BASE_DIR = get_backend_dir()
sys.path.append(str(BASE_DIR))

# === Import Base (defined in app/models/base.py) ===
from app.models.base import Base  # noqa: E402

# === Import all models so Alembic can see tables ===
def import_all_models():
    import app.models  # models package
    pkg_path = Path(app.models.__file__).parent
    for m in pkgutil.iter_modules([str(pkg_path)]):
        if not m.ispkg and m.name not in {"base", "__init__"}:
            importlib.import_module(f"app.models.{m.name}")

import_all_models()

# === Alembic config ===
config = context.config

# === Logging (if ini file is set) ===
if config.config_file_name:
    fileConfig(config.config_file_name)

# === Model metadata (for autogeneration) ===
target_metadata = Base.metadata

# === Function to get database URL ===
def get_url():
    return os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url")

# === Offline migrations (without DB connection) ===
def run_migrations_offline():
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

# === Online migrations (with DB connection) ===
def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=get_url(),
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()

# === Run appropriate mode ===
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
