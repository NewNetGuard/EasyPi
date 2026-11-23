"""Widen TOTP storage for encrypted secrets.

Revision ID: 20260726_encrypt_totp
Revises: 102f19610bfb
"""

from alembic import op
import sqlalchemy as sa

revision = "20260726_encrypt_totp"
down_revision = "102f19610bfb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.String(length=32),
            type_=sa.String(length=512),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "totp_secret",
            existing_type=sa.String(length=512),
            type_=sa.String(length=32),
            existing_nullable=True,
        )
