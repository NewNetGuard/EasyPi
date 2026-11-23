"""Add PTZ (pan/tilt/zoom) columns to the cameras table.

Revision ID: 20260802_camera_ptz
Revises: 20260726_redact_wg

Additive + nullable only -- existing rows and the cameras' RTSP URLs are
unaffected. On real devices the same columns are also created idempotently by
``app.db.init_db.ensure_camera_ptz_columns`` (production schema is built by
``create_all`` + ``ensure_*`` helpers, not ``alembic upgrade``); this migration
keeps the Alembic history correct and gives a clean, reversible downgrade.
"""
from alembic import op
import sqlalchemy as sa


revision = "20260802_camera_ptz"
down_revision = "20260726_redact_wg"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older Alembic history predates the camera subsystem. Fresh databases are
    # completed by the runtime-schema sync migration, so this incremental step
    # is only applicable when the table already exists.
    if not sa.inspect(op.get_bind()).has_table("cameras"):
        return
    with op.batch_alter_table("cameras", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ptz_adapter", sa.String(length=32), nullable=True))
        batch_op.add_column(
            sa.Column("ptz_detected", sa.Boolean(), nullable=True, server_default=sa.false())
        )
        batch_op.add_column(sa.Column("ptz_capabilities_json", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("ptz_profile_token", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("ptz_configuration_token", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("ptz_last_probe_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("ptz_probe_error", sa.String(length=255), nullable=True))


def downgrade() -> None:
    if not sa.inspect(op.get_bind()).has_table("cameras"):
        return
    with op.batch_alter_table("cameras", schema=None) as batch_op:
        batch_op.drop_column("ptz_probe_error")
        batch_op.drop_column("ptz_last_probe_at")
        batch_op.drop_column("ptz_configuration_token")
        batch_op.drop_column("ptz_profile_token")
        batch_op.drop_column("ptz_capabilities_json")
        batch_op.drop_column("ptz_detected")
        batch_op.drop_column("ptz_adapter")
