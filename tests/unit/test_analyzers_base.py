"""Unit tests for the BaseAnalyzer interface."""

from typing import List

import pytest

from bug_detector.analyzers.base import BaseAnalyzer
from bug_detector.core.models import (
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
)


class DummyAnalyzer(BaseAnalyzer):
    """Concrete test implementation of BaseAnalyzer."""

    @property
    def name(self) -> str:
        return "DummyAnalyzer"

    @property
    def description(self) -> str:
        return "Mock analyzer for testing abstract interface contract."

    def analyze(self, source_code: str, filename: str = "snippet.py") -> List[BugFinding]:
        if "test_bug" in source_code:
            return [
                BugFinding(
                    rule_id="DUMMY001",
                    category=BugCategory.CORRECTNESS,
                    severity=Severity.INFO,
                    message="Dummy bug found",
                    explanation="Found dummy bug token.",
                    location=CodeLocation(line=1, column=0),
                )
            ]
        return []


class TestBaseAnalyzer:
    """Test suite for BaseAnalyzer abstract contract."""

    def test_cannot_instantiate_abstract_base(self) -> None:
        """Verify that BaseAnalyzer cannot be instantiated directly without implementations."""
        with pytest.raises(TypeError):
            BaseAnalyzer()  # type: ignore

    def test_dummy_analyzer_implementation(self) -> None:
        """Verify concrete subclass satisfies contract and analyzes source."""
        analyzer = DummyAnalyzer()
        assert analyzer.name == "DummyAnalyzer"
        assert "Mock analyzer" in analyzer.description

        findings = analyzer.analyze("test_bug = 1", filename="test.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "DUMMY001"
        assert findings[0].severity == Severity.INFO

        clean_findings = analyzer.analyze("clean_code = 1", filename="test.py")
        assert len(clean_findings) == 0
