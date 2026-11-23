"""Add session info columns to users table

Revision ID: 20251225_session_info
Revises: 20251117_ai_settings
Create Date: 2025-12-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20251225_session_info'
down_revision: Union[str, None] = '20251117_ai_settings'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add last_login_ip column
    op.add_column('users', sa.Column('last_login_ip', sa.String(length=45), nullable=True))
    # Add last_login_user_agent column
    op.add_column('users', sa.Column('last_login_user_agent', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'last_login_user_agent')
    op.drop_column('users', 'last_login_ip')
