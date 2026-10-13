"""Integration tests for FastAPI REST API endpoints and static assets."""

from typing import Generator

import pytest
from fastapi.testclient import TestClient

from bug_detector.api.app import create_app
from bug_detector.api.dependencies import get_api_settings, get_repository
from bug_detector.api.limiter import global_rate_limiter
from bug_detector.core.config import Settings
from bug_detector.storage.database import DatabaseManager
from bug_detector.storage.repository import ReviewRepository


@pytest.fixture
def client(tmp_path) -> Generator[TestClient, None, None]:
    """Provide a TestClient with an isolated SQLite database and reset rate limiter."""
    global_rate_limiter.reset()

    db_path = tmp_path / "test_api.db"
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        demo_mode=False,
        max_code_size_bytes=10 * 1024,
        max_code_lines=50,
        rate_limit_per_minute=20,
    )

    app = create_app(settings=settings)

    # Isolated repository
    db = DatabaseManager(db_path=settings.database_url)
    repo = ReviewRepository(db)
    app.dependency_overrides[get_api_settings] = lambda: settings
    app.dependency_overrides[get_repository] = lambda: repo

    test_client = TestClient(app)
    yield test_client
    db.close()


class TestAPIEndpoints:
    """Verify REST API routes, validation, and static asset serving."""

    def test_health_check_endpoint(self, client: TestClient) -> None:
        """GET /api/health returns system status without secret exposure."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert data["version"] == "0.1.0"
        assert data["demo_mode"] is False
        assert "ai_configured" in data
        # Ensure no sensitive keys leaked in response payload
        assert "openai_api_key" not in data
        assert "api_key" not in data

    def test_analyze_clean_code(self, client: TestClient) -> None:
        """POST /api/analyze succeeds with 0 findings for clean code."""
        payload = {
            "source_code": "def add(a: int, b: int) -> int:\n    return a + b\n",
            "filename": "calc.py",
            "enable_ai": False,
        }
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["filename"] == "calc.py"
        assert data["syntax"]["is_valid"] is True
        assert data["summary"]["total_findings"] == 0
        assert len(data["findings"]) == 0
        assert "review_id" in data

    def test_analyze_buggy_code(self, client: TestClient) -> None:
        """POST /api/analyze accurately returns AST bug findings."""
        payload = {
            "source_code": (
                "def append(item, target=[]):\n"
                "    target.append(item)\n"
                "    return target\n"
            ),
            "filename": "cache.py",
            "enable_ai": False,
        }
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["syntax"]["is_valid"] is True
        assert data["summary"]["total_findings"] >= 1
        assert data["findings"][0]["rule_id"] == "CORR001"
        assert data["findings"][0]["severity"] == "error"

    def test_analyze_syntax_error_code(self, client: TestClient) -> None:
        """POST /api/analyze reports syntax errors cleanly without crashing."""
        payload = {
            "source_code": "def broken_func(\n    pass\n",
            "filename": "syntax_err.py",
            "enable_ai": False,
        }
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["syntax"]["is_valid"] is False
        assert data["syntax"]["line"] is not None
        assert data["summary"]["total_findings"] == 1
        assert data["findings"][0]["rule_id"] == "SYNTAX001"

    def test_analyze_empty_code_rejected(self, client: TestClient) -> None:
        """POST /api/analyze rejects empty source code."""
        response = client.post("/api/analyze", json={"source_code": "   "})
        assert response.status_code == 422

    def test_analyze_oversized_code_rejected(self, client: TestClient) -> None:
        """POST /api/analyze rejects code exceeding max_code_size_bytes."""
        huge_code = "# " + ("x" * 15000)
        response = client.post("/api/analyze", json={"source_code": huge_code})
        assert response.status_code == 413
        assert "exceeds maximum allowed limit" in response.json()["detail"]

    def test_analyze_excessive_lines_rejected(self, client: TestClient) -> None:
        """POST /api/analyze rejects code exceeding max_code_lines."""
        many_lines = "\n".join([f"x_{i} = {i}" for i in range(100)])
        response = client.post("/api/analyze", json={"source_code": many_lines})
        assert response.status_code == 400
        assert "line count" in response.json()["detail"]

    def test_history_crud_flow(self, client: TestClient) -> None:
        """Test listing, reading, deleting, and clearing review history."""
        # 1. Submit an analysis
        res1 = client.post(
            "/api/analyze",
            json={"source_code": "x = 10 / 0", "filename": "div.py"},
        )
        assert res1.status_code == 200
        review_id = res1.json()["review_id"]

        # 2. List history
        hist_res = client.get("/api/history")
        assert hist_res.status_code == 200
        items = hist_res.json()
        assert len(items) >= 1
        assert any(item["review_id"] == review_id for item in items)

        # 3. Get history by ID
        detail_res = client.get(f"/api/history/{review_id}")
        assert detail_res.status_code == 200
        assert detail_res.json()["review_id"] == review_id
        assert detail_res.json()["filename"] == "div.py"

        # 4. Get nonexistent ID -> 404
        assert client.get("/api/history/non-existent-uuid").status_code == 404

        # 5. Delete specific history item
        del_res = client.delete(f"/api/history/{review_id}")
        assert del_res.status_code == 200
        assert del_res.json() == {"deleted": True, "review_id": review_id}
        assert client.get(f"/api/history/{review_id}").status_code == 404

        # 6. Delete nonexistent item -> 404
        assert client.delete("/api/history/non-existent-uuid").status_code == 404

        # 7. Add another and clear all history
        client.post("/api/analyze", json={"source_code": "y = 1"})
        clear_res = client.post("/api/history/clear")
        assert clear_res.status_code == 200
        assert clear_res.json()["cleared_count"] >= 1
        assert len(client.get("/api/history").json()) == 0

    def test_rate_limiting_enforcement(self, client: TestClient) -> None:
        """Client exceeding rate limit receives HTTP 429."""
        global_rate_limiter.reset()
        # Settings configured with rate_limit_per_minute=20
        for _ in range(20):
            res = client.post("/api/analyze", json={"source_code": "x = 1"})
            assert res.status_code == 200

        # 21st request should be rejected with 429
        rejected = client.post("/api/analyze", json={"source_code": "x = 1"})
        assert rejected.status_code == 429
        assert "Rate limit exceeded" in rejected.json()["detail"]

    def test_static_assets_and_dashboard(self, client: TestClient) -> None:
        """Ensure static HTML, CSS, and JS assets are served correctly."""
        # Root index.html
        root_res = client.get("/")
        assert root_res.status_code == 200
        assert "AI Bug Detector" in root_res.text

        # CSS styles
        css_res = client.get("/static/styles.css")
        assert css_res.status_code == 200
        assert "--bg-primary" in css_res.text

        # JS application
        js_res = client.get("/static/app.js")
        assert js_res.status_code == 200
        assert "renderAnalysisResults" in js_text if (js_text := js_res.text) else True
