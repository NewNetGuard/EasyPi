from config import get_settings

# Export settings instance for backward compatibility
settings = get_settings()


def api_prefix() -> str:
    return get_settings().API_BASE


def cors_origins() -> list[str]:
    return list(get_settings().CORS_ORIGINS)


def is_prod() -> bool:
    return get_settings().ENV.lower() == "production"


def ports() -> tuple[int, int]:
    settings = get_settings()
    return settings.API_PORT, settings.FRONTEND_PORT
