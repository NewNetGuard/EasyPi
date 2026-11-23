"""Synchronize Alembic databases with the runtime schema authority.

Revision ID: 20260828_schema_sync
Revises: 20260806_camera_ptz_creds

EasyPi historically upgraded deployed databases through ``init_db`` rather
than Alembic.  This reconciliation revision deliberately reuses the same
metadata and additive compatibility helpers so a fresh ``alembic upgrade
head`` and the production startup path converge on the same schema.
"""

from alembic import op

from app.db.base import Base
from app.db.init_db import (
    ensure_ai_columns,
    ensure_camera_ptz_columns,
    ensure_dns_deploy_security_columns,
    ensure_user_columns,
    validate_runtime_schema,
)


revision = "20260828_schema_sync"
down_revision = "20260806_camera_ptz_creds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # create_all creates missing tables but intentionally does not alter tables
    # that came from older revisions. Reuse the production-safe additive
    # upgrades for those legacy tables.
    engine = bind.engine
    ensure_user_columns(engine, strict=True)
    ensure_dns_deploy_security_columns(engine, strict=True)
    ensure_camera_ptz_columns(engine, strict=True)
    ensure_ai_columns(engine, strict=True)
    validate_runtime_schema(engine)


def downgrade() -> None:
    # This is a reconciliation migration. Tables may have existed before it,
    # so deleting them (or their columns) would risk user data.
    pass
