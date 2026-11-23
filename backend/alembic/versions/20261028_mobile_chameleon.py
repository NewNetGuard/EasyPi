"""Assign independent Chameleon tunnel addresses to linked phones.

Revision ID: 20261028_mobile_chameleon
Revises: 20261028_mobile_wireguard
"""

from alembic import op
import sqlalchemy as sa


revision = "20261028_mobile_chameleon"
down_revision = "20261028_mobile_wireguard"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "chameleon_address" not in existing:
        op.add_column(
            "mobile_devices",
            sa.Column("chameleon_address", sa.String(length=64), nullable=True),
        )
    obsolete = [
        name
        for name in (
            "wireguard_public_key",
            "wireguard_peer_name",
            "wireguard_address",
            "wireguard_address_v6",
        )
        if name in existing
    ]
    if obsolete:
        with op.batch_alter_table("mobile_devices") as batch_op:
            for name in obsolete:
                batch_op.drop_column(name)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    if "chameleon_address" in existing:
        op.drop_column("mobile_devices", "chameleon_address")
    with op.batch_alter_table("mobile_devices") as batch_op:
        batch_op.add_column(sa.Column("wireguard_public_key", sa.String(length=44), nullable=True))
        batch_op.add_column(sa.Column("wireguard_peer_name", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("wireguard_address", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("wireguard_address_v6", sa.String(length=64), nullable=True))
