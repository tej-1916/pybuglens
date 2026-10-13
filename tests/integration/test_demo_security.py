"""Security boundary tests verifying DEMO_MODE isolation across API and storage."""

from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.api.app import create_app
from bug_detector.api.dependencies import get_api_settings, get_engine, get_repository
from bug_detector.core.config import Settings
from bug_detector.storage.database import DatabaseManager
from bug_detector.storage.repository import ReviewRepository


@pytest.fixture
def demo_client(tmp_path) -> Generator[TestClient, None, None]:
    """Fixture providing TestClient configured in strict DEMO_MODE."""
    db_path = tmp_path / "demo_test.db"
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        demo_mode=True,
        openai_api_key="sk-mock-key-in-demo",
    )

    app = create_app(settings=settings)

    db = DatabaseManager(db_path=settings.database_url)
    repo = ReviewRepository(db)

    # Engine with repository, but demo_mode active
    engine = AnalysisEngine(repository=repo, settings=settings)

    app.dependency_overrides[get_api_settings] = lambda: settings
    app.dependency_overrides[get_repository] = lambda: repo
    app.dependency_overrides[get_engine] = lambda: engine

    client = TestClient(app)
    yield client
    db.close()


class TestDemoModeSecurity:
    """Validate strict security policies when DEMO_MODE is active."""

    def test_health_reports_demo_mode_true(self, demo_client: TestClient) -> None:
        """Health endpoint indicates demo mode is active."""
        res = demo_client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["demo_mode"] is True
        # In demo mode, ai_configured should report False
        assert res.json()["ai_configured"] is False

    def test_demo_mode_prevents_code_persistence(self, demo_client: TestClient) -> None:
        """Visitor code analysis must never be written to repository in demo mode."""
        res = demo_client.post(
            "/api/analyze",
            json={
                "source_code": "def visitor_code(): return 'secret'",
                "filename": "visitor.py",
            },
        )
        assert res.status_code == 200
        review_id = res.json()["review_id"]

        # Directly inspect the underlying database
        assert isinstance(demo_client.app, FastAPI)
        repo = demo_client.app.dependency_overrides[get_repository]()
        stored_item = repo.get_review_by_id(review_id)
        assert stored_item is None
        assert repo.count_reviews() == 0

    def test_demo_mode_disables_paid_ai_review(self, demo_client: TestClient) -> None:
        """AI review requests are gracefully blocked without making external calls."""
        res = demo_client.post(
            "/api/analyze",
            json={
                "source_code": "x = 10",
                "filename": "demo.py",
                "enable_ai": True,
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["ai_review"] is not None
        assert data["ai_review"]["enabled"] is False
        assert "disabled in public demo mode" in data["ai_review"]["error_message"].lower()

    def test_demo_mode_blocks_history_listing(self, demo_client: TestClient) -> None:
        """GET /api/history returns 403 Forbidden in demo mode."""
        res = demo_client.get("/api/history")
        assert res.status_code == 403
        assert "disabled in public demo mode" in res.json()["detail"].lower()

    def test_demo_mode_blocks_history_detail(self, demo_client: TestClient) -> None:
        """GET /api/history/{id} returns 403 Forbidden in demo mode."""
        res = demo_client.get("/api/history/some-random-id")
        assert res.status_code == 403
        assert "disabled in public demo mode" in res.json()["detail"].lower()

    def test_demo_mode_blocks_history_delete(self, demo_client: TestClient) -> None:
        """DELETE /api/history/{id} returns 403 Forbidden in demo mode."""
        res = demo_client.delete("/api/history/some-random-id")
        assert res.status_code == 403
        assert "disabled in public demo mode" in res.json()["detail"].lower()

    def test_demo_mode_blocks_history_clear(self, demo_client: TestClient) -> None:
        """POST /api/history/clear returns 403 Forbidden in demo mode."""
        res = demo_client.post("/api/history/clear")
        assert res.status_code == 403
        assert "disabled in public demo mode" in res.json()["detail"].lower()
