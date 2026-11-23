"""Add mobile device pairing tables.

Revision ID: 20261023_mobile_devices
Revises: 20260828_schema_sync
"""

from alembic import op
import sqlalchemy as sa


revision = "20261023_mobile_devices"
down_revision = "20260828_schema_sync"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("mobile_pairing_challenges"):
        op.create_table(
            "mobile_pairing_challenges",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_by", sa.Integer(), nullable=False),
            sa.Column("code_hash", sa.String(length=64), nullable=False),
            sa.Column("tailscale_exit_node", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("code_hash"),
        )
        op.create_index("ix_mobile_pairing_challenges_created_by", "mobile_pairing_challenges", ["created_by"])
        op.create_index("ix_mobile_pairing_challenges_code_hash", "mobile_pairing_challenges", ["code_hash"], unique=True)
        op.create_index("ix_mobile_pairing_challenges_expires_at", "mobile_pairing_challenges", ["expires_at"])

    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("mobile_devices"):
        op.create_table(
            "mobile_devices",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("owner_user_id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("tailscale_exit_node", sa.String(length=255), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("token_hash"),
        )
        op.create_index("ix_mobile_devices_owner_user_id", "mobile_devices", ["owner_user_id"])
        op.create_index("ix_mobile_devices_token_hash", "mobile_devices", ["token_hash"], unique=True)
        op.create_index("ix_mobile_devices_is_active", "mobile_devices", ["is_active"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("mobile_devices"):
        op.drop_table("mobile_devices")
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("mobile_pairing_challenges"):
        op.drop_table("mobile_pairing_challenges")
