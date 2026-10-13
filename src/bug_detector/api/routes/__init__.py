"""API router definitions."""

from bug_detector.api.routes.analysis import router as analysis_router
from bug_detector.api.routes.health import router as health_router
from bug_detector.api.routes.history import router as history_router

__all__ = ["analysis_router", "health_router", "history_router"]
