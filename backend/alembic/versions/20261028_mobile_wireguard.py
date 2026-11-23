"""Associate linked phones with server-side WireGuard peers.

Revision ID: 20261028_mobile_wireguard
Revises: 20261027_mobile_prism_client
"""

from alembic import op
import sqlalchemy as sa


revision = "20261028_mobile_wireguard"
down_revision = "20261027_mobile_prism_client"
branch_labels = None
depends_on = None


_COLUMNS = {
    "wireguard_public_key": sa.String(length=44),
    "wireguard_peer_name": sa.String(length=32),
    "wireguard_address": sa.String(length=64),
    "wireguard_address_v6": sa.String(length=64),
}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    for name, column_type in _COLUMNS.items():
        if name not in existing:
            op.add_column("mobile_devices", sa.Column(name, column_type, nullable=True))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    for name in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("mobile_devices", name)
