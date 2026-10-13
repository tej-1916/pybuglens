"""Unit tests for Pydantic models and schemas."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from bug_detector.core.models import (
    AIReviewResult,
    AnalysisHistoryItem,
    AnalysisRequest,
    AnalysisResult,
    AnalysisSummary,
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
    SyntaxValidationResult,
)


class TestModels:
    """Test suite for core data models."""

    def test_enums(self) -> None:
        """Verify enum values and members."""
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"
        assert Severity.CRITICAL.value == "critical"

        assert BugCategory.SYNTAX.value == "syntax"
        assert BugCategory.CORRECTNESS.value == "correctness"
        assert BugCategory.SECURITY.value == "security"
        assert BugCategory.STYLE.value == "style"
        assert BugCategory.PERFORMANCE.value == "performance"

    def test_code_location(self) -> None:
        """Verify CodeLocation coordinate model."""
        loc = CodeLocation(line=5, column=12, end_line=5, end_column=20)
        assert loc.line == 5
        assert loc.column == 12
        assert loc.end_line == 5
        assert loc.end_column == 20

        # line must be >= 1
        with pytest.raises(ValidationError):
            CodeLocation(line=0, column=0)

    def test_bug_finding_defaults_and_validation(self) -> None:
        """Verify BugFinding auto-generated ID and fields."""
        finding = BugFinding(
            rule_id="CORR001",
            category=BugCategory.CORRECTNESS,
            severity=Severity.ERROR,
            message="Possible division by zero",
            explanation="Denominator could evaluate to zero.",
            location=CodeLocation(line=10, column=4),
        )
        assert finding.id is not None
        assert len(finding.id) > 10
        assert finding.rule_id == "CORR001"
        assert finding.suggested_fix is None

    def test_analysis_request_validation(self) -> None:
        """Verify AnalysisRequest accepts valid code and rejects empty input."""
        req = AnalysisRequest(source_code="a = 1", filename="main.py")
        assert req.source_code == "a = 1"
        assert req.filename == "main.py"
        assert req.enable_ai is False

        # Reject empty code
        with pytest.raises(ValidationError):
            AnalysisRequest(source_code="")

        # Reject whitespace-only code
        with pytest.raises(ValidationError):
            AnalysisRequest(source_code="   \n\t  ")

    def test_analysis_summary_from_findings(self) -> None:
        """Verify AnalysisSummary correctly aggregates finding severities."""
        findings = [
            BugFinding(
                rule_id="R1",
                category=BugCategory.SECURITY,
                severity=Severity.CRITICAL,
                message="Critical issue",
                explanation="Expl",
                location=CodeLocation(line=1, column=0),
            ),
            BugFinding(
                rule_id="R2",
                category=BugCategory.CORRECTNESS,
                severity=Severity.ERROR,
                message="Error issue",
                explanation="Expl",
                location=CodeLocation(line=2, column=0),
            ),
            BugFinding(
                rule_id="R3",
                category=BugCategory.STYLE,
                severity=Severity.WARNING,
                message="Warning issue 1",
                explanation="Expl",
                location=CodeLocation(line=3, column=0),
            ),
            BugFinding(
                rule_id="R4",
                category=BugCategory.STYLE,
                severity=Severity.WARNING,
                message="Warning issue 2",
                explanation="Expl",
                location=CodeLocation(line=4, column=0),
            ),
            BugFinding(
                rule_id="R5",
                category=BugCategory.PERFORMANCE,
                severity=Severity.INFO,
                message="Info issue",
                explanation="Expl",
                location=CodeLocation(line=5, column=0),
            ),
        ]
        summary = AnalysisSummary.from_findings(findings)
        assert summary.total_findings == 5
        assert summary.critical_count == 1
        assert summary.error_count == 1
        assert summary.warning_count == 2
        assert summary.info_count == 1

    def test_ai_review_result(self) -> None:
        """Verify AIReviewResult schema."""
        ai = AIReviewResult(
            enabled=True,
            success=True,
            review_text="Looks good with minor suggestions.",
            model_used="gpt-4o-mini",
            tokens_used=120,
        )
        assert ai.enabled is True
        assert ai.success is True
        assert ai.model_used == "gpt-4o-mini"
        assert ai.tokens_used == 120

    def test_analysis_result_structure(
        self, sample_finding: BugFinding, sample_syntax_valid: SyntaxValidationResult
    ) -> None:
        """Verify full AnalysisResult model construction."""
        summary = AnalysisSummary.from_findings([sample_finding])
        res = AnalysisResult(
            filename="demo.py",
            source_code="x = 10\n",
            code_hash="abcdef1234567890",
            line_count=1,
            char_count=7,
            syntax=sample_syntax_valid,
            findings=[sample_finding],
            summary=summary,
            execution_duration_ms=12.5,
        )
        assert res.review_id is not None
        assert res.filename == "demo.py"
        assert res.summary.total_findings == 1
        assert res.execution_duration_ms == 12.5
        assert res.ai_review is None

    def test_history_item_model(self) -> None:
        """Verify AnalysisHistoryItem serialization."""
        item = AnalysisHistoryItem(
            review_id="rev-1234",
            timestamp=datetime.now(timezone.utc),
            filename="app.py",
            code_hash="hash123",
            total_findings=2,
            is_valid_syntax=True,
            execution_duration_ms=4.8,
        )
        assert item.review_id == "rev-1234"
        assert item.total_findings == 2
        assert item.is_valid_syntax is True
