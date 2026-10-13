"""Unit and integration tests for the AnalysisEngine and ASTScanner."""

import os
import tempfile

import pytest

from bug_detector.analyzers.ast_scanner import ASTScanner
from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.core.models import (
    AnalysisRequest,
    BugCategory,
    Severity,
)
from bug_detector.utils.sanitizer import CodeSanitizer


class TestAnalysisEngine:
    """Comprehensive test suite for AnalysisEngine."""

    def test_clean_valid_python_code(self) -> None:
        """Verify completely clean Python code returns 0 findings and valid syntax."""
        engine = AnalysisEngine()
        code = (
            "def add(a: int, b: int) -> int:\n"
            "    \"\"\"Add two numbers safely.\"\"\"\n"
            "    return a + b\n"
        )
        req = AnalysisRequest(source_code=code, filename="math_utils.py")
        result = engine.analyze(req)

        assert result.syntax.is_valid is True
        assert len(result.findings) == 0
        assert result.summary.total_findings == 0
        assert result.summary.critical_count == 0
        assert result.summary.error_count == 0
        assert result.summary.warning_count == 0
        assert result.line_count == 3
        assert result.execution_duration_ms >= 0.0

    def test_syntax_error_reported_as_finding(self) -> None:
        """Verify syntax error in source returns is_valid=False and critical SYNTAX001 finding."""
        engine = AnalysisEngine()
        broken_code = "def invalid_syntax(:\n    pass\n"
        req = AnalysisRequest(source_code=broken_code, filename="broken.py")
        result = engine.analyze(req)

        assert result.syntax.is_valid is False
        assert result.syntax.line == 1
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_id == "SYNTAX001"
        assert finding.category == BugCategory.SYNTAX
        assert finding.severity == Severity.CRITICAL
        assert finding.location.line == 1
        assert result.summary.total_findings == 1
        assert result.summary.critical_count == 1

    def test_multiple_findings_in_single_file(self) -> None:
        """Verify multiple distinct bugs in one file are all detected and categorized."""
        engine = AnalysisEngine()
        compound_code = (
            "def problematic(items=[]):\n"  # CORR001 (ERROR)
            "    try:\n"
            "        x = 10 / 0\n"  # CORR002 (CRITICAL)
            "    except:\n"  # STYLE001 (WARNING)
            "        pass\n"
            "    eval('1 + 1')\n"  # SEC001 (CRITICAL)
            "    return items\n"
        )
        req = AnalysisRequest(source_code=compound_code, filename="compound.py")
        result = engine.analyze(req)

        assert result.syntax.is_valid is True
        assert len(result.findings) >= 4
        rule_ids = {f.rule_id for f in result.findings}
        assert "CORR001" in rule_ids
        assert "CORR002" in rule_ids
        assert "STYLE001" in rule_ids
        assert "SEC001" in rule_ids

        # Check severity counts aggregation
        assert result.summary.critical_count >= 2  # Div by zero + eval
        assert result.summary.error_count >= 1  # Mutable default
        assert result.summary.warning_count >= 1  # Bare except

    def test_accurate_line_and_column_numbers(self) -> None:
        """Verify findings accurately report line and column coordinates."""
        engine = AnalysisEngine()
        code = (
            "# Line 1: Comment\n"
            "# Line 2: Comment\n"
            "def worker(cfg={}):\n"  # Line 3, col 11
            "    return cfg\n"
        )
        req = AnalysisRequest(source_code=code, filename="coords.py")
        result = engine.analyze(req)

        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.location.line == 3
        assert f.location.column >= 10

    def test_empty_or_whitespace_code_rejected(self) -> None:
        """Verify empty and whitespace-only code raises ValueError."""
        with pytest.raises(ValueError):
            AnalysisRequest(source_code="")

        with pytest.raises(ValueError):
            AnalysisRequest(source_code="   \n\t  ")

    def test_oversized_code_rejected(self) -> None:
        """Verify code exceeding maximum configured bytes or lines raises ValueError."""
        sanitizer = CodeSanitizer(max_bytes=200, max_lines=10)
        engine = AnalysisEngine(sanitizer=sanitizer)

        oversized_code = "# " + ("A" * 500) + "\n"
        req = AnalysisRequest(source_code=oversized_code)
        with pytest.raises(ValueError, match="exceeds maximum limit"):
            engine.analyze(req)

    def test_unicode_and_emojis_handled_safely(self) -> None:
        """Verify unicode characters, emojis, and non-ASCII text parse safely."""
        engine = AnalysisEngine()
        unicode_code = (
            "# 🚀 Unicode commentary with accented characters: café, naïve, résumé\n"
            "def привет_мир() -> str:\n"
            "    message = '🌟 Привет, мир! 日本語 🐍'\n"
            "    return message\n"
        )
        req = AnalysisRequest(source_code=unicode_code, filename="unicode_test.py")
        result = engine.analyze(req)

        assert result.syntax.is_valid is True
        assert len(result.findings) == 0

    def test_zero_execution_guarantee(self) -> None:
        """CRITICAL SECURITY TEST: Ensure submitted code is NEVER executed or evaluated.

        We submit code that would write a sentinel file or set an environment variable
        if it were ever executed via exec/eval/import/subprocess.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            sentinel_file = os.path.join(tmp_dir, "malicious_canary.txt")
            sentinel_env_var = "BUG_DETECTOR_CANARY_ACTIVE"

            if sentinel_env_var in os.environ:
                del os.environ[sentinel_env_var]

            # Code with active side effects if executed
            hostile_code = (
                f"import os\n"
                f"os.environ['{sentinel_env_var}'] = 'HACKED'\n"
                f"with open('{sentinel_file}', 'w') as f:\n"
                f"    f.write('INTRUDER_EXECUTED')\n"
            )

            engine = AnalysisEngine()
            req = AnalysisRequest(source_code=hostile_code, filename="hostile.py")
            result = engine.analyze(req)

            # Verification:
            # 1. The canary file must NOT exist
            assert not os.path.exists(sentinel_file), (
                "SECURITY BREACH: Submitted source code was executed on host filesystem!"
            )
            # 2. The environment variable must NOT have been set
            assert sentinel_env_var not in os.environ, (
                "SECURITY BREACH: Submitted source code mutated host process environment!"
            )
            # 3. Analysis completed normally via static inspection
            assert result.syntax.is_valid is True

    def test_ast_scanner_custom_rules_and_error_isolation(self) -> None:
        """Verify ASTScanner isolates exceptions raised inside a malfunctioning rule."""
        from bug_detector.analyzers.rules.base import BaseRule

        class BrokenRule(BaseRule):
            @property
            def rule_id(self) -> str:
                return "ERR999"

            @property
            def name(self) -> str:
                return "Faulty Rule"

            @property
            def category(self) -> BugCategory:
                return BugCategory.CORRECTNESS

            @property
            def severity(self) -> Severity:
                return Severity.ERROR

            @property
            def description(self) -> str:
                return "Exploding rule"

            def check(self, tree, lines, filename):
                raise RuntimeError("Intentional test crash in rule!")

        scanner = ASTScanner(rules=[BrokenRule()])
        findings, syntax = scanner.analyze_with_syntax("x = 1\n")
        assert syntax.is_valid is True
        assert len(findings) == 1
        assert findings[0].rule_id == "ERR999_ERR"
        assert "Intentional test crash" in findings[0].message
