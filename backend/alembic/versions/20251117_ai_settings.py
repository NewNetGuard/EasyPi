"""Add AI settings columns for temperature/system prompt/status.

Revision ID: 20251117_ai_settings
Revises: 20251116_ai
Create Date: 2025-11-17
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20251117_ai_settings"
down_revision = 'backup_jobs_001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("ai_config")}

    if "temperature" not in columns:
        op.add_column("ai_config", sa.Column("temperature", sa.Float(), nullable=True))
        op.execute("UPDATE ai_config SET temperature = 0.1 WHERE temperature IS NULL")

    if "system_prompt" not in columns:
        op.add_column("ai_config", sa.Column("system_prompt", sa.Text(), nullable=True))
        op.execute(
            "UPDATE ai_config SET system_prompt = 'You are a friendly and concise DevOps assistant. Follow formatting guidelines and add Shell commands when possible.' WHERE system_prompt IS NULL"
        )

    if "status" not in columns:
        op.add_column(
            "ai_config",
            sa.Column(
                "status", sa.String(length=20), nullable=False, server_default="not_installed"
            ),
        )
        op.execute("UPDATE ai_config SET status = 'not_installed' WHERE status IS NULL")


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("ai_config")}

    if "status" in columns:
        op.drop_column("ai_config", "status")
    if "system_prompt" in columns:
        op.drop_column("ai_config", "system_prompt")
    if "temperature" in columns:
        op.drop_column("ai_config", "temperature")
