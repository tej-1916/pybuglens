"""FastAPI dependency injection providers."""

from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.api.limiter import global_rate_limiter
from bug_detector.core.config import Settings, get_settings
from bug_detector.storage.database import DatabaseManager
from bug_detector.storage.repository import ReviewRepository


def get_api_settings() -> Settings:
    """Retrieve active application settings."""
    return get_settings()


@lru_cache()
def _get_cached_repository(db_url: str) -> ReviewRepository:
    """Cached singleton repository for a specific database URL."""
    db = DatabaseManager(db_path=db_url)
    return ReviewRepository(db=db)


def get_repository(
    settings: Settings = Depends(get_api_settings),
) -> Optional[ReviewRepository]:
    """Provide ReviewRepository configured with active database URL."""
    return _get_cached_repository(settings.database_url)


def get_engine(
    settings: Settings = Depends(get_api_settings),
    repository: Optional[ReviewRepository] = Depends(get_repository),
) -> AnalysisEngine:
    """Provide configured AnalysisEngine instance."""
    return AnalysisEngine(
        repository=repository,
        settings=settings,
    )


def check_rate_limit(
    request: Request,
    settings: Settings = Depends(get_api_settings),
) -> None:
    """Enforce request rate limiting based on client IP."""
    client_ip = (
        request.client.host
        if request.client and request.client.host
        else "127.0.0.1"
    )
    if not global_rate_limiter.is_allowed(
        client_ip=client_ip,
        max_requests=settings.rate_limit_per_minute,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before submitting more analysis requests.",
        )
