"""Add 2FA fields to users table

Revision ID: add_2fa_fields
Revises: 20251225_session_info
Create Date: 2025-12-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_2fa_fields'
down_revision: Union[str, None] = '20251225_session_info'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add 2FA columns to users table
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_secret', sa.String(32), nullable=True))
        batch_op.add_column(sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('backup_codes', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('backup_codes')
        batch_op.drop_column('totp_enabled')
        batch_op.drop_column('totp_secret')
