"""Health check API routes."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from bug_detector.api.dependencies import get_api_settings
from bug_detector.core.config import Settings

router = APIRouter(prefix="/api", tags=["Health"])


class HealthResponse(BaseModel):
    """Health check response payload."""

    status: str = Field(default="healthy", description="Application health status")
    version: str = Field(description="Active application version")
    environment: str = Field(description="Runtime environment name")
    demo_mode: bool = Field(description="Whether application is in public demo mode")
    ai_configured: bool = Field(
        description="Whether server has OpenAI configured (never reveals keys)"
    )


@router.get("/health", response_model=HealthResponse)
def get_health(settings: Settings = Depends(get_api_settings)) -> HealthResponse:
    """Return application operational status without exposing secrets."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        environment=settings.environment,
        demo_mode=settings.demo_mode,
        ai_configured=settings.is_ai_available,
    )
