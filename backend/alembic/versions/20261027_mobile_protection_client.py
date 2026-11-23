"""Remember the anonymized PRISM client belonging to a linked phone.

Revision ID: 20261027_mobile_prism_client
Revises: 20261025_mobile_photo_folder
"""

from alembic import op
import sqlalchemy as sa


revision = "20261027_mobile_prism_client"
down_revision = "20261025_mobile_photo_folder"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "protection_client_id" not in columns:
        op.add_column(
            "mobile_devices",
            sa.Column("protection_client_id", sa.String(length=16), nullable=True),
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "protection_client_id" in columns:
        op.drop_column("mobile_devices", "protection_client_id")
