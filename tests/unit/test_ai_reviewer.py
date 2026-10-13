"""Unit tests for the AIReviewer component."""

from unittest.mock import MagicMock

from openai import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    RateLimitError,
)

from bug_detector.ai.reviewer import AIReviewer
from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.core.config import Settings
from bug_detector.core.models import (
    AIReviewResult,
    AnalysisRequest,
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
    SyntaxValidationResult,
)


class TestAIReviewer:
    """Test suite verifying AIReviewer safety, fallbacks, and mocked completions."""

    def test_ai_review_disabled_in_demo_mode(self) -> None:
        """When DEMO_MODE is active, AI review requests must be unconditionally blocked."""
        settings = Settings(demo_mode=True, openai_api_key="sk-mock-key-12345")
        mock_client = MagicMock()
        reviewer = AIReviewer(settings=settings, client=mock_client)

        result = reviewer.review("def foo(): pass")

        assert result.enabled is False
        assert result.success is False
        assert "disabled in public demo mode" in (result.error_message or "")
        mock_client.chat.completions.create.assert_not_called()

    def test_ai_review_disabled_when_api_key_missing(self) -> None:
        """When OPENAI_API_KEY is None or empty, return disabled result without failing."""
        settings = Settings(demo_mode=False, openai_api_key=None)
        mock_client = MagicMock()
        reviewer = AIReviewer(settings=settings, client=mock_client)

        result = reviewer.review("def foo(): pass")

        assert result.enabled is False
        assert result.success is False
        assert "not configured" in (result.error_message or "")
        mock_client.chat.completions.create.assert_not_called()

    def test_ai_review_success_mocked(self) -> None:
        """Successful mock completion returns structured AIReviewResult."""
        settings = Settings(
            demo_mode=False,
            openai_api_key="sk-valid-key",
            openai_model="gpt-4o-mini",
        )
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Executive Summary: Code looks generally sound."
        mock_response.choices = [mock_choice]
        mock_response.usage.total_tokens = 85
        mock_client.chat.completions.create.return_value = mock_response

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1", filename="test.py")

        assert result.enabled is True
        assert result.success is True
        assert result.review_text == "Executive Summary: Code looks generally sound."
        assert result.model_used == "gpt-4o-mini"
        assert result.tokens_used == 85
        assert result.error_message is None

    def test_ai_review_authentication_error_mocked(self) -> None:
        """Authentication error from OpenAI degrades to friendly structured error."""
        settings = Settings(demo_mode=False, openai_api_key="sk-invalid")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = AuthenticationError(
            message="Incorrect API key",
            response=MagicMock(status_code=401),
            body=None,
        )

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1")

        assert result.enabled is True
        assert result.success is False
        assert "authentication failed" in (result.error_message or "").lower()

    def test_ai_review_rate_limit_error_mocked(self) -> None:
        """Rate limit error degrades safely to structured message."""
        settings = Settings(demo_mode=False, openai_api_key="sk-valid")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RateLimitError(
            message="Rate limit reached",
            response=MagicMock(status_code=429),
            body=None,
        )

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1")

        assert result.enabled is True
        assert result.success is False
        assert "rate limit reached" in (result.error_message or "").lower()

    def test_ai_review_timeout_error_mocked(self) -> None:
        """Timeout error degrades safely without crashing."""
        settings = Settings(demo_mode=False, openai_api_key="sk-valid")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APITimeoutError(
            request=MagicMock()
        )

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1")

        assert result.enabled is True
        assert result.success is False
        assert "timed out" in (result.error_message or "").lower()

    def test_ai_review_connection_error_mocked(self) -> None:
        """Network connection error degrades cleanly."""
        settings = Settings(demo_mode=False, openai_api_key="sk-valid")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = APIConnectionError(
            request=MagicMock()
        )

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1")

        assert result.enabled is True
        assert result.success is False
        assert "connect" in (result.error_message or "").lower()

    def test_ai_review_generic_exception_mocked(self) -> None:
        """Unexpected internal exceptions are caught defensively."""
        settings = Settings(demo_mode=False, openai_api_key="sk-valid")
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = RuntimeError("Service fault")

        reviewer = AIReviewer(settings=settings, client=mock_client)
        result = reviewer.review("x = 1")

        assert result.enabled is True
        assert result.success is False
        assert "unexpected" in (result.error_message or "").lower()

    def test_prompt_builder_includes_findings_and_syntax_error(self) -> None:
        """Prompt builder constructs complete context without code execution."""
        reviewer = AIReviewer(settings=Settings(demo_mode=False, openai_api_key="sk-valid"))

        syntax_error = SyntaxValidationResult(
            is_valid=False,
            error_message="invalid syntax",
            line=3,
            column=7,
        )
        finding = BugFinding(
            rule_id="CORR001",
            category=BugCategory.CORRECTNESS,
            severity=Severity.WARNING,
            message="Mutable default argument",
            explanation="Default list argument is shared",
            location=CodeLocation(line=1, column=0),
        )

        prompt = reviewer.build_user_prompt(
            source_code="def fn(items=[]):\n    pass",
            findings=[finding],
            filename="example.py",
            syntax_result=syntax_error,
        )

        assert "Target File: example.py" in prompt
        assert "Syntax Validation Notice" in prompt
        assert "Line 3, Column 7" in prompt
        assert "[CORR001] Line 1: Mutable default argument" in prompt
        assert "def fn(items=[]):" in prompt

    def test_engine_integration_calls_ai_reviewer_only_when_requested(self) -> None:
        """AnalysisEngine calls AIReviewer if and only if enable_ai is requested."""
        mock_reviewer = MagicMock()
        engine = AnalysisEngine(
            settings=Settings(demo_mode=False, openai_api_key="sk-valid"),
            ai_reviewer=mock_reviewer,
        )

        # 1. enable_ai=False
        res_no_ai = engine.analyze(
            AnalysisRequest(source_code="x = 10", enable_ai=False),
            save=False,
        )
        assert res_no_ai.ai_review is None
        mock_reviewer.review.assert_not_called()

        # 2. enable_ai=True
        mock_reviewer.review.return_value = AIReviewResult(
            enabled=True, success=True, review_text="Review text"
        )
        res_with_ai = engine.analyze(
            AnalysisRequest(source_code="x = 10", enable_ai=True),
            save=False,
        )
        assert res_with_ai.ai_review is not None
        assert res_with_ai.ai_review.review_text == "Review text"
        mock_reviewer.review.assert_called_once()
