"""Add security tables

Revision ID: 20251116_security
Revises: 
Create Date: 2025-11-16

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20251116_security'
down_revision = '20251114_224323'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create security_scans table
    op.create_table(
        'security_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_date', sa.DateTime(), nullable=True),
        sa.Column('critical_count', sa.Integer(), nullable=True),
        sa.Column('warning_count', sa.Integer(), nullable=True),
        sa.Column('passed_count', sa.Integer(), nullable=True),
        sa.Column('scan_data', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_scans_id'), 'security_scans', ['id'], unique=False)

    # Create firewall_rules table
    op.create_table(
        'firewall_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=10), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_firewall_rules_id'), 'firewall_rules', ['id'], unique=False)

    # Create password_change_logs table
    op.create_table(
        'password_change_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('changed_at', sa.DateTime(), nullable=True),
        sa.Column('changed_by', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username')
    )
    op.create_index(op.f('ix_password_change_logs_id'), 'password_change_logs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_password_change_logs_id'), table_name='password_change_logs')
    op.drop_table('password_change_logs')
    op.drop_index(op.f('ix_firewall_rules_id'), table_name='firewall_rules')
    op.drop_table('firewall_rules')
    op.drop_index(op.f('ix_security_scans_id'), table_name='security_scans')
    op.drop_table('security_scans')
