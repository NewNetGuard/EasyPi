"""Add AI tables

Revision ID: 20251116_ai
Revises: 20251116_security
Create Date: 2025-11-16

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20251116_ai'
down_revision = '20251116_security'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ai_config table
    op.create_table(
        'ai_config',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('is_installed', sa.Boolean(), nullable=True),
        sa.Column('installation_date', sa.DateTime(), nullable=True),
        sa.Column('model_name', sa.String(length=100), nullable=True),
        sa.Column('ollama_url', sa.String(length=255), nullable=True),
        sa.Column('last_health_check', sa.DateTime(), nullable=True),
        sa.Column('is_healthy', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_config_id'), 'ai_config', ['id'], unique=False)

    # Create ai_conversations table
    op.create_table(
        'ai_conversations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=100), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_conversations_id'), 'ai_conversations', ['id'], unique=False)
    op.create_index(op.f('ix_ai_conversations_session_id'), 'ai_conversations', ['session_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ai_conversations_session_id'), table_name='ai_conversations')
    op.drop_index(op.f('ix_ai_conversations_id'), table_name='ai_conversations')
    op.drop_table('ai_conversations')
    op.drop_index(op.f('ix_ai_config_id'), table_name='ai_config')
    op.drop_table('ai_config')
