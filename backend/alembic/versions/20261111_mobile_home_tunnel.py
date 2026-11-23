"""Add independent home-tunnel identities for linked phones.

Revision ID: 20261111_mobile_home_tunnel
Revises: 20261028_mobile_chameleon
"""

from alembic import op
import sqlalchemy as sa


revision = "20261111_mobile_home_tunnel"
down_revision = "20261028_mobile_chameleon"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    additions = {
        "home_tunnel_public_key": sa.String(length=512),
        "home_tunnel_address": sa.String(length=64),
        "home_tunnel_state": sa.String(length=16),
        "home_tunnel_credential_epoch": sa.Integer(),
        "home_tunnel_last_handshake_at": sa.DateTime(),
    }
    with op.batch_alter_table("mobile_devices") as batch_op:
        for name, column_type in additions.items():
            if name not in existing:
                if name == "home_tunnel_state":
                    batch_op.add_column(
                        sa.Column(name, column_type, nullable=False, server_default="inactive")
                    )
                elif name == "home_tunnel_credential_epoch":
                    batch_op.add_column(
                        sa.Column(name, column_type, nullable=False, server_default="0")
                    )
                else:
                    batch_op.add_column(sa.Column(name, column_type, nullable=True))
    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"] for index in inspector.get_indexes("mobile_devices")}
    for name in ("home_tunnel_public_key", "home_tunnel_address"):
        index_name = f"ix_mobile_devices_{name}"
        if index_name not in indexes:
            op.create_index(index_name, "mobile_devices", [name], unique=True)
    if "ix_mobile_devices_home_tunnel_state" not in indexes:
        op.create_index(
            "ix_mobile_devices_home_tunnel_state",
            "mobile_devices",
            ["home_tunnel_state"],
            unique=False,
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("mobile_devices")}
    indexes = {index["name"] for index in inspector.get_indexes("mobile_devices")}
    for name in (
        "ix_mobile_devices_home_tunnel_state",
        "ix_mobile_devices_home_tunnel_address",
        "ix_mobile_devices_home_tunnel_public_key",
    ):
        if name in indexes:
            op.drop_index(name, table_name="mobile_devices")
    with op.batch_alter_table("mobile_devices") as batch_op:
        for name in (
            "home_tunnel_last_handshake_at",
            "home_tunnel_credential_epoch",
            "home_tunnel_state",
            "home_tunnel_address",
            "home_tunnel_public_key",
        ):
            if name in existing:
                batch_op.drop_column(name)
