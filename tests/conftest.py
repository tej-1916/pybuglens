"""Global pytest fixtures and test configuration."""

import pytest

from bug_detector.core.config import Settings
from bug_detector.core.models import (
    AnalysisRequest,
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
    SyntaxValidationResult,
)


@pytest.fixture
def sample_valid_code() -> str:
    """Provide a simple, valid Python code sample."""
    return (
        "def add_numbers(a: int, b: int) -> int:\n"
        "    \"\"\"Add two numbers and return result.\"\"\"\n"
        "    return a + b\n"
    )


@pytest.fixture
def sample_syntax_error_code() -> str:
    """Provide a Python code sample with an explicit syntax error."""
    return "def broken_func(:\n    pass\n"


@pytest.fixture
def sample_finding() -> BugFinding:
    """Provide a sample BugFinding model instance."""
    return BugFinding(
        rule_id="TEST001",
        category=BugCategory.CORRECTNESS,
        severity=Severity.WARNING,
        message="Test warning message",
        explanation="This is a test warning explanation.",
        suggested_fix="Fix by removing unused code.",
        location=CodeLocation(line=1, column=0, end_line=1, end_column=10),
        code_snippet="x = 10",
    )


@pytest.fixture
def sample_syntax_valid() -> SyntaxValidationResult:
    """Provide a valid syntax validation result."""
    return SyntaxValidationResult(
        is_valid=True,
        error_message=None,
        line=None,
        column=None,
        text=None,
    )


@pytest.fixture
def sample_analysis_request() -> AnalysisRequest:
    """Provide a standard AnalysisRequest."""
    return AnalysisRequest(
        source_code="x = 1 + 2\nprint(x)\n",
        filename="test_script.py",
        enable_ai=False,
    )


@pytest.fixture
def custom_settings() -> Settings:
    """Provide isolated Settings instance for testing."""
    return Settings(
        app_name="Test Bug Detector",
        environment="test",
        debug=True,
        max_code_size_bytes=1024,
        max_code_lines=50,
        demo_mode=False,
        openai_api_key=None,
    )
