"""Add terminal session and command audit tables

Revision ID: 20251114_222318
Revises: 
Create Date: 2025-11-14 22:23:18.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20251114_222318'
down_revision: Union[str, None] = '1a590ceadea0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create terminal_sessions table
    op.create_table(
        'terminal_sessions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_terminal_sessions_user_id'), 'terminal_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_terminal_sessions_started_at'), 'terminal_sessions', ['started_at'], unique=False)

    # Create terminal_commands table
    op.create_table(
        'terminal_commands',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('executed_at', sa.DateTime(), nullable=False),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('output_length', sa.Integer(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['session_id'], ['terminal_sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_terminal_commands_session_id'), 'terminal_commands', ['session_id'], unique=False)
    op.create_index(op.f('ix_terminal_commands_executed_at'), 'terminal_commands', ['executed_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_terminal_commands_executed_at'), table_name='terminal_commands')
    op.drop_index(op.f('ix_terminal_commands_session_id'), table_name='terminal_commands')
    op.drop_table('terminal_commands')
    
    op.drop_index(op.f('ix_terminal_sessions_started_at'), table_name='terminal_sessions')
    op.drop_index(op.f('ix_terminal_sessions_user_id'), table_name='terminal_sessions')
    op.drop_table('terminal_sessions')
