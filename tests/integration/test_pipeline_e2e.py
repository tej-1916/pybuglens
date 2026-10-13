"""End-to-end integration tests verifying pipeline and non-execution invariant."""

import os
from pathlib import Path
from typing import Generator

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from bug_detector.api.app import create_app
from bug_detector.api.dependencies import get_api_settings, get_repository
from bug_detector.api.limiter import global_rate_limiter
from bug_detector.cli.main import cli
from bug_detector.core.config import Settings
from bug_detector.storage.database import DatabaseManager
from bug_detector.storage.repository import ReviewRepository


@pytest.fixture
def e2e_env(tmp_path: Path) -> Generator[dict, None, None]:
    """Provide fully configured test client, repository, and settings."""
    global_rate_limiter.reset()
    db_path = tmp_path / "e2e_test.db"
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        demo_mode=False,
    )
    db = DatabaseManager(db_path=settings.database_url)
    repo = ReviewRepository(db)

    app = create_app(settings=settings)
    app.dependency_overrides[get_api_settings] = lambda: settings
    app.dependency_overrides[get_repository] = lambda: repo

    client = TestClient(app)
    yield {
        "client": client,
        "repo": repo,
        "settings": settings,
        "db": db,
        "tmp_path": tmp_path,
    }
    db.close()


class TestPipelineE2E:
    """Validate end-to-end pipeline execution from source input to API/CLI/DB."""

    def test_e2e_pipeline_with_multiple_bug_categories(self, e2e_env: dict) -> None:
        """Verify full pipeline: AST detection, severity, suggested fixes, DB persistence, API."""
        client: TestClient = e2e_env["client"]
        repo: ReviewRepository = e2e_env["repo"]

        multi_bug_code = (
            "def calculate(items=[], factor=0):\n"
            "    val = items[0] / factor\n"
            "    try:\n"
            "        result = eval('val * 2')\n"
            "    except:\n"
            "        pass\n"
            "    return val\n"
        )

        # 1. Submit through API
        response = client.post(
            "/api/analyze",
            json={"source_code": multi_bug_code, "filename": "complex_calc.py"},
        )
        assert response.status_code == 200
        data = response.json()

        # 2. Syntax check
        assert data["syntax"]["is_valid"] is True
        assert data["syntax"]["error_message"] is None

        # 3. Bug detection & severity rules
        rule_ids = {f["rule_id"] for f in data["findings"]}
        assert "CORR001" in rule_ids  # Mutable default
        assert "SEC001" in rule_ids   # eval()
        assert "STYLE001" in rule_ids # bare except

        # 4. Severity classification and suggested fixes
        for finding in data["findings"]:
            assert finding["severity"] in ["critical", "error", "warning", "info"]
            assert finding["suggested_fix"] is not None
            assert len(finding["suggested_fix"]) > 0

        # 5. Structured result & summary metrics
        assert data["summary"]["total_findings"] == len(data["findings"])
        assert data["execution_duration_ms"] > 0

        # 6. Database persistence
        review_id = data["review_id"]
        stored = repo.get_review_by_id(review_id)
        assert stored is not None
        assert stored.review_id == review_id
        assert stored.filename == "complex_calc.py"
        assert stored.summary.total_findings == data["summary"]["total_findings"]

    def test_e2e_canary_zero_execution_guarantee_across_api_and_cli(
        self, e2e_env: dict
    ) -> None:
        """CRITICAL SECURITY CANARY: Verify submitted code is NEVER executed via API or CLI.

        Hostile code attempts filesystem mutations, environment modifications,
        and immediate sys.exit() execution.
        """
        client: TestClient = e2e_env["client"]
        tmp_path: Path = e2e_env["tmp_path"]

        canary_file = tmp_path / "hostile_payload_side_effect.txt"
        canary_env = "CANARY_INTRUDER_FLAG_12345"

        if canary_env in os.environ:
            del os.environ[canary_env]
        if canary_file.exists():
            canary_file.unlink()

        # Malicious code payload
        hostile_code = (
            f"import os, sys\n"
            f"os.environ['{canary_env}'] = 'MALICIOUS_EXECUTION_DETECTED'\n"
            f"with open('{canary_file}', 'w') as f:\n"
            f"    f.write('INTRUSION')\n"
            f"sys.exit(42)\n"
        )

        # 1. Run through FastAPI endpoint
        api_res = client.post(
            "/api/analyze",
            json={"source_code": hostile_code, "filename": "hostile_api.py"},
        )
        assert api_res.status_code == 200

        # Verify side effects NEVER executed
        assert not canary_file.exists(), "SECURITY VIOLATION: Canary file was created by API!"
        assert canary_env not in os.environ, "SECURITY VIOLATION: Env variable set by API!"

        # 2. Run through CLI
        hostile_script = tmp_path / "hostile_script.py"
        hostile_script.write_text(hostile_code, encoding="utf-8")

        runner = CliRunner()
        cli_res = runner.invoke(cli, ["analyze", str(hostile_script), "--no-save"])

        # If sys.exit(42) was executed, exit code would be 42. It must NOT be 42.
        assert cli_res.exit_code != 42
        assert not canary_file.exists(), "SECURITY VIOLATION: Canary file was created by CLI!"
        assert canary_env not in os.environ, "SECURITY VIOLATION: Env variable set by CLI!"

    def test_e2e_boundary_unicode_and_crlf_normalization(self, e2e_env: dict) -> None:
        """Verify proper normalization of CRLF line endings, null bytes, and UTF-8 characters."""
        client: TestClient = e2e_env["client"]

        # Code with Windows CRLF and trailing null byte
        raw_code = (
            "# Unicode test: 🐍 漢字 éàç\r\n"
            "def greet(name: str = '세계') -> str:\r\n"
            "    return f'Hello, {name}'\r\n\x00"
        )

        res = client.post(
            "/api/analyze",
            json={"source_code": raw_code, "filename": "unicode_crlf.py"},
        )
        assert res.status_code == 200
        data = res.json()

        assert data["syntax"]["is_valid"] is True
        assert "\r\n" not in data["source_code"]
        assert "\x00" not in data["source_code"]
        assert "세계" in data["source_code"]
