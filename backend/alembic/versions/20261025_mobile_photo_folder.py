"""Associate every mobile device with its Cloud photo folder.

Revision ID: 20261025_mobile_photo_folder
Revises: 20261023_mobile_devices
"""

from alembic import op
import sqlalchemy as sa


revision = "20261025_mobile_photo_folder"
down_revision = "20261023_mobile_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "photo_folder" not in columns:
        op.add_column("mobile_devices", sa.Column("photo_folder", sa.String(length=100), nullable=True))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "photo_folder" in columns:
        op.drop_column("mobile_devices", "photo_folder")
