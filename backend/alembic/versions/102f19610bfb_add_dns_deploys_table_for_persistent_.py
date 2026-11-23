"""Add dns_deploys table for persistent deployment storage

Revision ID: 102f19610bfb
Revises: add_user_sessions
Create Date: 2026-01-03 19:46:09.394109
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "102f19610bfb"
down_revision: Union[str, None] = 'add_user_sessions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create only dns_deploys table (other tables already exist)
    op.create_table('dns_deploys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('vps_ip', sa.String(length=45), nullable=False),
    sa.Column('ssh_user', sa.String(length=100), nullable=False),
    sa.Column('ssh_port', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=255), nullable=True),
    sa.Column('dns_ipv4', sa.String(length=45), nullable=True),
    sa.Column('dns_ipv6', sa.String(length=45), nullable=True),
    sa.Column('admin_url', sa.String(length=512), nullable=True),
    sa.Column('doh_url', sa.String(length=512), nullable=True),
    sa.Column('dot_address', sa.String(length=255), nullable=True),
    sa.Column('wireguard_config', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('deployment_date', sa.DateTime(), nullable=False),
    sa.Column('last_check', sa.DateTime(), nullable=True),
    sa.Column('is_online', sa.Boolean(), nullable=True),
    sa.Column('warnings', sa.JSON(), nullable=True),
    sa.Column('recommendations', sa.JSON(), nullable=True),
    sa.Column('deployment_log', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dns_deploys'))
    )
    op.create_index(op.f('ix_dns_deploys_id'), 'dns_deploys', ['id'], unique=False)
    op.create_index(op.f('ix_dns_deploys_user_id'), 'dns_deploys', ['user_id'], unique=False)


def downgrade() -> None:
    # Remove dns_deploys table
    op.drop_index(op.f('ix_dns_deploys_user_id'), table_name='dns_deploys')
    op.drop_index(op.f('ix_dns_deploys_id'), table_name='dns_deploys')
    op.drop_table('dns_deploys')
