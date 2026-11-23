"""Add dedicated PTZ credential columns to the cameras table.

Revision ID: 20260806_camera_ptz_creds
Revises: 20260802_camera_ptz

Additive + nullable: ``ptz_username`` and ``ptz_secret`` (encrypted) hold the
optional ONVIF/PTZ login, separate from the RTSP username/password so adding
them never rewrites the video URL. On devices the same columns are created
idempotently by ``app.db.init_db.ensure_camera_ptz_columns``.
"""
from alembic import op
import sqlalchemy as sa


revision = "20260806_camera_ptz_creds"
down_revision = "20260802_camera_ptz"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not sa.inspect(op.get_bind()).has_table("cameras"):
        return
    with op.batch_alter_table("cameras", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ptz_username", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("ptz_secret", sa.String(length=255), nullable=True))


def downgrade() -> None:
    if not sa.inspect(op.get_bind()).has_table("cameras"):
        return
    with op.batch_alter_table("cameras", schema=None) as batch_op:
        batch_op.drop_column("ptz_secret")
        batch_op.drop_column("ptz_username")
