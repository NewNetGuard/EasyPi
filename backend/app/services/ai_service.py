"""Stable public facade for the local AI service."""

# ruff: noqa: F401

# ruff: noqa: F401

from app.services.ai_components.context import (
    AIConfig,
    AIConversation,
    AIInstallStatus,
    AIModelInfo,
    AISettingsUpdate,
    AsyncGenerator,
    ChatResponse,
    List,
    Optional,
    Path,
    Session,
    asyncio,
    create_install_job,
    get_installer_log_path,
    get_settings,
    httpx,
    json,
    logger,
    logging,
    os,
    re,
    read_installer_log,
    run_in_threadpool,
    start_install_job,
    subprocess,
    text,
    utc_now,
    uuid,
)

from app.services.ai_components.chat import AIChatMixin
from app.services.ai_components.installation import AIInstallationMixin
from app.services.ai_components.models import AIModelsMixin
from app.services.ai_components.runtime import AIRuntimeMixin


class AIService(AIRuntimeMixin, AIInstallationMixin, AIChatMixin, AIModelsMixin):
    """Service for AI assistant operations."""

    DEFAULT_SYSTEM_PROMPT = (
        "You are EasyPi's local assistant. Be accurate, concise, and helpful."
    )

    AVAILABLE_MODELS: List[dict] = [
        {
            "name": "qwen2.5:3b",
            "display_name": "Qwen 2.5 3B",
            "description": "Fast local model balanced for Raspberry Pi.",
            "size_gb": 1.9,
            "tags": ["recommended", "raspberry-pi", "balanced"],
            "recommended": True,
            "notes": "Recommended EasyPi default for responsive local chat.",
        },
        {
            "name": "llama3.1:8b",
            "display_name": "Llama 3.1 8B",
            "description": "Meta Llama with high speed and quality.",
            "size_gb": 4.3,
            "tags": ["meta", "speed"],
            "recommended": True,
            "notes": "Faster than Qwen, good for diagnostics.",
        },
        {
            "name": "qwen2.5:14b",
            "display_name": "Qwen 2.5 14B",
            "description": "Higher quality but requires more memory.",
            "size_gb": 8.6,
            "tags": ["quality", "large-context"],
            "recommended": False,
            "notes": "Requires 24+ GB RAM or swap file.",
        },
        {
            "name": "deepseek-r1:14b",
            "display_name": "DeepSeek-R1 14B",
            "description": "Model focused on reasoning and step-by-step execution.",
            "size_gb": 9.2,
            "tags": ["reasoning"],
            "recommended": False,
            "notes": "Detailed responses, useful for diagnostics.",
        },
    ]

    def __init__(self):
        settings = get_settings()
        self.ollama_url = settings.OLLAMA_URL
        self.install_script = str(settings.SCRIPTS_ROOT / "services" / "ai.sh")
        self._install_lock_path = (
            settings.SCRIPTS_ROOT.parent / "data" / "ai_install.lock"
        )
        self.active_installation = False
        # Clear any stale lock file on startup
        self._clear_install_lock()
