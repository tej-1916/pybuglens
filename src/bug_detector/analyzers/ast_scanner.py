"""AST Scanner implementing BaseAnalyzer to orchestrate modular static analysis rules.

CRITICAL SECURITY GUARDRAIL:
This module NEVER executes, evaluates, or imports submitted code.
All checks are performed by static AST tree inspection and pattern matching.
"""

import ast
from typing import List, Optional

from bug_detector.analyzers.base import BaseAnalyzer
from bug_detector.analyzers.rules.base import BaseRule
from bug_detector.analyzers.rules.correctness import (
    DivisionByZeroRule,
    IneffectiveComparisonRule,
    MutableDefaultArgRule,
    UnreachableCodeRule,
)
from bug_detector.analyzers.rules.security import (
    DangerousDynamicExecRule,
    HardcodedSecretsRule,
    InsecureTempFileRule,
)
from bug_detector.analyzers.rules.style import (
    BareExceptRule,
    DuplicateBranchRule,
    UnusedLocalVariableRule,
)
from bug_detector.analyzers.syntax import SyntaxChecker
from bug_detector.core.models import (
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
    SyntaxValidationResult,
)


class ASTScanner(BaseAnalyzer):
    """Deterministic AST-based static code analyzer."""

    def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
        self.syntax_checker = SyntaxChecker()
        if rules is not None:
            self._rules = list(rules)
        else:
            self._rules = [
                # Correctness
                MutableDefaultArgRule(),
                DivisionByZeroRule(),
                IneffectiveComparisonRule(),
                UnreachableCodeRule(),
                # Security
                DangerousDynamicExecRule(),
                HardcodedSecretsRule(),
                InsecureTempFileRule(),
                # Style and Maintainability
                BareExceptRule(),
                UnusedLocalVariableRule(),
                DuplicateBranchRule(),
            ]

    @property
    def name(self) -> str:
        return "Python AST Static Scanner"

    @property
    def description(self) -> str:
        return (
            "Performs deep deterministic static code analysis using Python Abstract Syntax Trees "
            "(AST), detecting syntax errors, correctness bugs, dangerous security patterns, "
            "and code maintenance defects without executing source code."
        )

    @property
    def registered_rules(self) -> List[BaseRule]:
        """Return a copy of currently registered inspection rules."""
        return list(self._rules)

    def register_rule(self, rule: BaseRule) -> None:
        """Register a new static analysis rule."""
        self._rules.append(rule)

    def analyze(self, source_code: str, filename: str = "snippet.py") -> List[BugFinding]:
        """Analyze source code and return all detected bug findings.

        If the source code contains a Python syntax error, returns a single
        critical SYNTAX001 finding detailing the syntax failure coordinates.
        """
        findings, _ = self.analyze_with_syntax(source_code, filename=filename)
        return findings

    def analyze_with_syntax(
        self, source_code: str, filename: str = "snippet.py"
    ) -> tuple[List[BugFinding], SyntaxValidationResult]:
        """Analyze source code and return both findings and the syntax check outcome."""
        syntax_res = self.syntax_checker.check(source_code, filename=filename)

        lines = source_code.splitlines()

        if not syntax_res.is_valid:
            syntax_finding = BugFinding(
                rule_id="SYNTAX001",
                category=BugCategory.SYNTAX,
                severity=Severity.CRITICAL,
                message=syntax_res.error_message or "Python syntax compilation error.",
                explanation=(
                    "The submitted Python source code violates Python syntax grammar and cannot be "
                    "parsed into an abstract syntax tree."
                ),
                suggested_fix="Correct the syntax error at the indicated line and column.",
                location=CodeLocation(
                    line=syntax_res.line or 1,
                    column=syntax_res.column or 0,
                ),
                code_snippet=syntax_res.text,
            )
            return [syntax_finding], syntax_res

        try:
            tree = ast.parse(source_code, filename=filename)
        except Exception:
            # Fallback in case of unexpected AST parse error
            return [], syntax_res

        findings: List[BugFinding] = []
        for rule in self._rules:
            try:
                rule_findings = rule.check(tree, lines, filename=filename)
                findings.extend(rule_findings)
            except Exception as rule_err:
                # Isolate rule failure to prevent cascading analyzer crash
                findings.append(
                    BugFinding(
                        rule_id=f"{rule.rule_id}_ERR",
                        category=BugCategory.CORRECTNESS,
                        severity=Severity.INFO,
                        message=f"Rule '{rule.name}' encountered an error: {str(rule_err)}",
                        explanation="Internal exception caught while executing rule AST visitor.",
                        location=CodeLocation(line=1, column=0),
                    )
                )

        # Sort findings deterministically by line number, then column
        findings.sort(key=lambda f: (f.location.line, f.location.column))
        return findings, syntax_res
