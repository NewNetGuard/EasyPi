"""Remove persisted WireGuard client private keys.

Revision ID: 20260726_redact_wg
Revises: 20260726_encrypt_totp
"""

from alembic import op
import sqlalchemy as sa


revision = "20260726_redact_wg"
down_revision = "20260726_encrypt_totp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("dns_deploys", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "wireguard_installed",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )

    op.execute(
        sa.text(
            "UPDATE dns_deploys "
            "SET wireguard_installed = 1 "
            "WHERE wireguard_config IS NOT NULL AND wireguard_config <> ''"
        )
    )

    with op.batch_alter_table("dns_deploys", schema=None) as batch_op:
        batch_op.drop_column("wireguard_config")


def downgrade() -> None:
    with op.batch_alter_table("dns_deploys", schema=None) as batch_op:
        batch_op.add_column(sa.Column("wireguard_config", sa.Text(), nullable=True))
        batch_op.drop_column("wireguard_installed")
