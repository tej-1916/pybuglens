"""Unit tests for the Click CLI."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from bug_detector.cli.main import cli
from bug_detector.core.config import Settings


@pytest.fixture
def runner() -> CliRunner:
    """Fixture providing Click CliRunner."""
    return CliRunner()


class TestCLI:
    """Verify CLI commands, options, outputs, and exit codes."""

    def test_cli_version(self, runner: CliRunner) -> None:
        """--version flag prints version and exits cleanly."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_cli_help(self, runner: CliRunner) -> None:
        """--help displays usage information."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "AI-Powered Bug Detection System CLI" in result.output
        assert "analyze" in result.output
        assert "history" in result.output

    def test_analyze_clean_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Clean Python code exits with code 0."""
        code_file = tmp_path / "clean.py"
        code_file.write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n",
            encoding="utf-8",
        )

        result = runner.invoke(cli, ["analyze", str(code_file), "--no-save"])
        assert result.exit_code == 0
        assert "Python AST Syntax: Valid" in result.output
        assert "No static rule violations detected" in result.output

    def test_analyze_buggy_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Python code with detected bugs exits with code 1."""
        code_file = tmp_path / "buggy.py"
        code_file.write_text(
            "def append(item, target=[]):\n    target.append(item)\n    return target\n",
            encoding="utf-8",
        )

        result = runner.invoke(cli, ["analyze", str(code_file), "--no-save"])
        assert result.exit_code == 1
        assert "CORR001" in result.output
        assert "mutable default argument" in result.output.lower()

    def test_analyze_syntax_error_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Python code with syntax errors exits with code 2."""
        code_file = tmp_path / "broken.py"
        code_file.write_text("def broken(\n    pass\n", encoding="utf-8")

        result = runner.invoke(cli, ["analyze", str(code_file), "--no-save"])
        assert result.exit_code == 2
        assert "Syntax Error" in result.output

    def test_analyze_json_output(self, runner: CliRunner, tmp_path: Path) -> None:
        """--json flag outputs valid structured JSON."""
        code_file = tmp_path / "div.py"
        code_file.write_text("x = 10 / 0\n", encoding="utf-8")

        result = runner.invoke(cli, ["analyze", str(code_file), "--json", "--no-save"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["filename"] == "div.py"
        assert data["summary"]["total_findings"] >= 1
        assert data["findings"][0]["rule_id"] == "CORR002"

    def test_analyze_nonexistent_file(self, runner: CliRunner) -> None:
        """Analyzing a missing file returns exit code 2."""
        result = runner.invoke(cli, ["analyze", "/nonexistent/path/file.py"])
        assert result.exit_code == 2
        assert "does not exist" in result.output

    def test_analyze_empty_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Analyzing an empty file returns exit code 2."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("   \n", encoding="utf-8")

        result = runner.invoke(cli, ["analyze", str(empty_file)])
        assert result.exit_code == 2
        assert "cannot be empty" in result.output

    def test_history_and_view_workflow(self, runner: CliRunner, tmp_path: Path) -> None:
        """Test persisting review, listing via history, and inspecting via view."""
        db_path = tmp_path / "cli_test.db"
        custom_settings = Settings(
            database_url=f"sqlite:///{db_path}",
            demo_mode=False,
        )

        code_file = tmp_path / "test_target.py"
        code_file.write_text("x = 10 / 0\n", encoding="utf-8")

        with patch("bug_detector.cli.main.get_settings", return_value=custom_settings):
            # Run analyze with persistence
            analyze_res = runner.invoke(cli, ["analyze", str(code_file), "--json"])
            assert analyze_res.exit_code == 1
            review_id = json.loads(analyze_res.output)["review_id"]

            # Query history
            hist_res = runner.invoke(cli, ["history"])
            assert hist_res.exit_code == 0
            assert review_id in hist_res.output

            # View specific record
            view_res = runner.invoke(cli, ["view", review_id])
            assert view_res.exit_code == 0
            assert "Historical Review:" in view_res.output
            assert "test_target.py" in view_res.output

            # View specific record with JSON output
            view_json_res = runner.invoke(cli, ["view", review_id, "--json"])
            assert view_json_res.exit_code == 0
            view_data = json.loads(view_json_res.output)
            assert view_data["review_id"] == review_id

            # View nonexistent record
            view_missing = runner.invoke(cli, ["view", "missing-uuid"])
            assert view_missing.exit_code == 1
            assert "not found" in view_missing.output

    def test_history_blocked_in_demo_mode(self, runner: CliRunner) -> None:
        """History commands fail gracefully in demo mode."""
        demo_settings = Settings(demo_mode=True)
        with patch("bug_detector.cli.main.get_settings", return_value=demo_settings):
            hist_res = runner.invoke(cli, ["history"])
            assert hist_res.exit_code == 1
            assert "disabled in public demo mode" in hist_res.output

            view_res = runner.invoke(cli, ["view", "some-uuid"])
            assert view_res.exit_code == 1
            assert "disabled in public demo mode" in view_res.output
