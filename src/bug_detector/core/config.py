"""Application configuration management using Pydantic Settings."""

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General App Config
    app_name: str = Field(default="AI-Powered Bug Detection System", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    environment: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Server Config
    host: str = Field(default="127.0.0.1", description="FastAPI host")
    port: int = Field(default=8000, description="FastAPI port")
    cors_origins: List[str] = Field(
        default=["*"], description="Allowed CORS origins"
    )

    # Database Config
    database_url: str = Field(
        default="sqlite:///./data/bug_detector.db",
        description="SQLite database file URL",
    )

    # Security & Guardrails
    max_code_size_bytes: int = Field(
        default=100 * 1024,  # 100 KB
        description="Maximum allowed source code size in bytes (protects against DoS)",
    )
    max_code_lines: int = Field(
        default=2000,
        description="Maximum allowed source code line count",
    )
    demo_mode: bool = Field(
        default=False,
        description="Public demo mode flag (disables paid AI, enforces strict rate limits)",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        description="Maximum analysis requests permitted per minute per IP",
    )

    # OpenAI Integration Config (Optional)
    openai_api_key: str | None = Field(
        default=None,
        description="Optional OpenAI API key for AI-assisted review",
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model identifier for code review",
    )
    openai_timeout_seconds: float = Field(
        default=30.0,
        description="Timeout in seconds for external OpenAI requests",
    )

    @property
    def is_ai_available(self) -> bool:
        """Return True if an OpenAI API key is configured and demo mode is not active."""
        return bool(self.openai_api_key and self.openai_api_key.strip() and not self.demo_mode)


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
