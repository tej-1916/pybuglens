"""FastAPI application factory and server configuration."""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from bug_detector.api.dependencies import get_api_settings
from bug_detector.api.routes import analysis_router, health_router, history_router
from bug_detector.core.config import Settings


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    active_settings = settings or get_api_settings()

    app = FastAPI(
        title=active_settings.app_name,
        version=active_settings.app_version,
        docs_url="/docs",
        redoc_url=None,
    )

    # Dependency override if custom settings were provided
    if settings is not None:
        app.dependency_overrides[get_api_settings] = lambda: active_settings

    # Secure CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register API routers
    app.include_router(health_router)
    app.include_router(analysis_router)
    app.include_router(history_router)

    # Static assets and Web Dashboard
    static_dir = Path(__file__).resolve().parent.parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_dashboard() -> Response:
            index_path = static_dir / "index.html"
            if index_path.is_file():
                return FileResponse(str(index_path))
            return PlainTextResponse("Bug Detector API is operational. Static index missing.")
    else:
        @app.get("/", include_in_schema=False)
        async def serve_root_fallback() -> Response:
            return PlainTextResponse("Bug Detector API is operational.")

    return app


app = create_app()
