"""add backup_jobs table

Revision ID: backup_jobs_001
Revises: 
Create Date: 2025-11-16

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'backup_jobs_001'
down_revision = '20251116_ai'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'backup_jobs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=20), nullable=False),  # full, config
        sa.Column('size_bytes', sa.BigInteger(), nullable=True, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),  # running, completed, failed
        sa.Column('file_path', sa.String(length=512), nullable=True),
        sa.Column('error_message', sa.String(length=1024), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_backup_jobs_id'), 'backup_jobs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_backup_jobs_id'), table_name='backup_jobs')
    op.drop_table('backup_jobs')
