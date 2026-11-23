"""
AI Assistant Models

Database models for AI assistant conversations and configuration.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float
from app.utils.time import utc_now

from app.models.base import Base


class AIConversation(Base):
    """AI conversation history model"""
    __tablename__ = "ai_conversations"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    model = Column(String(50), default="qwen2.5:3b")


class AIConfig(Base):
    """AI configuration model"""
    __tablename__ = "ai_config"

    id = Column(Integer, primary_key=True, index=True)
    is_installed = Column(Boolean, default=False)
    model_name = Column(String(100), default="qwen2.5:3b")
    ollama_url = Column(String(200), default="http://127.0.0.1:11434")
    installed_at = Column(DateTime, nullable=True)
    last_health_check = Column(DateTime, nullable=True)
    status = Column(String(20), default="not_installed")  # not_installed, installing, ready, error
    temperature = Column(Float, default=0.1)
    system_prompt = Column(
        Text,
        default="You are a friendly chatbot. "
    )
