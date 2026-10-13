"""Unit tests for AST analysis rules (positive and negative cases)."""

import ast
from typing import List

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
from bug_detector.core.models import BugCategory, BugFinding, Severity


def run_rule(rule: BaseRule, code: str) -> List[BugFinding]:
    """Helper to run a single rule on a code snippet."""
    tree = ast.parse(code)
    lines = code.splitlines()
    return rule.check(tree, lines, filename="test_snippet.py")


class TestCorrectnessRules:
    """Test suite for correctness AST rules."""

    def test_mutable_default_args_positive(self) -> None:
        """Verify CORR001 flags lists, dicts, sets, comprehensions, and constructor calls."""
        rule = MutableDefaultArgRule()
        code = (
            "def fn1(items=[]):\n"
            "    pass\n"
            "def fn2(config={}):\n"
            "    pass\n"
            "def fn3(tags=set()):\n"
            "    pass\n"
            "def fn4(*, kw_items=list()):\n"
            "    pass\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 4
        for f in findings:
            assert f.rule_id == "CORR001"
            assert f.category == BugCategory.CORRECTNESS
            assert f.severity == Severity.ERROR
            assert "mutable default" in f.message.lower()

    def test_mutable_default_args_negative(self) -> None:
        """Verify CORR001 does not flag None, tuples, numbers, or strings."""
        rule = MutableDefaultArgRule()
        code = (
            "def safe_fn(a=None, b=1, c='hello', d=(1, 2)):\n"
            "    if a is None:\n"
            "        a = []\n"
            "    return a\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_division_by_zero_positive(self) -> None:
        """Verify CORR002 flags literal zero in /, //, and % operators."""
        rule = DivisionByZeroRule()
        code = (
            "a = 10 / 0\n"
            "b = 10 // 0\n"
            "c = 10 % 0\n"
            "d = 10 / 0.0\n"
            "e = 10 / -0\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 5
        for f in findings:
            assert f.rule_id == "CORR002"
            assert f.category == BugCategory.CORRECTNESS
            assert f.severity == Severity.CRITICAL

    def test_division_by_zero_negative(self) -> None:
        """Verify CORR002 does not flag valid non-zero divisors or variable divisors."""
        rule = DivisionByZeroRule()
        code = (
            "x = 10 / 2\n"
            "y = 10 // 3\n"
            "z = 10 % 4\n"
            "w = 10 / divisor\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_ineffective_comparison_positive(self) -> None:
        """Verify CORR003 flags standalone comparison statements."""
        rule = IneffectiveComparisonRule()
        code = (
            "def check(x, y):\n"
            "    x == y\n"
            "    x != 10\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "CORR003"
            assert f.severity == Severity.WARNING

    def test_ineffective_comparison_negative(self) -> None:
        """Verify CORR003 does not flag comparisons in conditions, assignments, or returns."""
        rule = IneffectiveComparisonRule()
        code = (
            "def check(x, y):\n"
            "    if x == y:\n"
            "        return True\n"
            "    res = x != 10\n"
            "    return x > 0\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_unreachable_code_positive(self) -> None:
        """Verify CORR004 flags statements after return, raise, break, continue."""
        rule = UnreachableCodeRule()
        code = (
            "def test_ret():\n"
            "    return 1\n"
            "    print('dead')\n"
            "def test_raise():\n"
            "    raise ValueError('fail')\n"
            "    x = 2\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 2
        assert findings[0].rule_id == "CORR004"
        assert findings[0].location.line == 3
        assert findings[1].location.line == 6

    def test_unreachable_code_negative(self) -> None:
        """Verify CORR004 does not flag properly reachable conditional returns."""
        rule = UnreachableCodeRule()
        code = (
            "def test_branches(x):\n"
            "    if x > 0:\n"
            "        return 1\n"
            "    else:\n"
            "        return 0\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0


class TestSecurityRules:
    """Test suite for security AST rules."""

    def test_dangerous_eval_exec_positive(self) -> None:
        """Verify SEC001 flags eval and exec calls."""
        rule = DangerousDynamicExecRule()
        code = (
            "eval('2 + 2')\n"
            "exec('import os')\n"
            "builtins.eval('1')\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 3
        for f in findings:
            assert f.rule_id == "SEC001"
            assert f.severity == Severity.CRITICAL

    def test_dangerous_eval_exec_negative(self) -> None:
        """Verify SEC001 does not flag ast.literal_eval or unrelated method calls."""
        rule = DangerousDynamicExecRule()
        code = (
            "import ast\n"
            "ast.literal_eval('[1, 2, 3]')\n"
            "my_evaluator.evaluate()\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_hardcoded_secrets_positive(self) -> None:
        """Verify SEC002 flags probable API keys and credentials."""
        rule = HardcodedSecretsRule()
        code = (
            "api_key = 'sk-abcdef1234567890abcdef1234567890'\n"
            "gh_token = 'ghp_1234567890abcdef1234567890'\n"
            "db_password = 'SuperSecretDbPassword2026!'\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) >= 2
        for f in findings:
            assert f.rule_id == "SEC002"
            assert f.severity == Severity.CRITICAL
            # Verify secret value is redacted and not exposed
            assert "sk-abcdef" not in f.message
            if f.code_snippet:
                assert "sk-abcdef" not in f.code_snippet

    def test_hardcoded_secrets_negative(self) -> None:
        """Verify SEC002 ignores placeholders and environment variables."""
        rule = HardcodedSecretsRule()
        code = (
            "api_key = os.getenv('API_KEY')\n"
            "api_key_placeholder = 'your-api-key'\n"
            "password = 'test'\n"
            "short = '123'\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_insecure_tempfile_positive(self) -> None:
        """Verify SEC003 flags tempfile.mktemp usage."""
        rule = InsecureTempFileRule()
        code = (
            "import tempfile\n"
            "tmp = tempfile.mktemp()\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC003"
        assert findings[0].severity == Severity.ERROR

    def test_insecure_tempfile_negative(self) -> None:
        """Verify SEC003 allows NamedTemporaryFile and TemporaryDirectory."""
        rule = InsecureTempFileRule()
        code = (
            "import tempfile\n"
            "with tempfile.NamedTemporaryFile() as tmp:\n"
            "    pass\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0


class TestStyleRules:
    """Test suite for style and maintainability AST rules."""

    def test_bare_except_positive(self) -> None:
        """Verify STYLE001 flags bare except: clauses."""
        rule = BareExceptRule()
        code = (
            "try:\n"
            "    do_something()\n"
            "except:\n"
            "    pass\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 1
        assert findings[0].rule_id == "STYLE001"
        assert findings[0].location.line == 3

    def test_bare_except_negative(self) -> None:
        """Verify STYLE001 allows specific and Exception catches."""
        rule = BareExceptRule()
        code = (
            "try:\n"
            "    do_something()\n"
            "except Exception:\n"
            "    pass\n"
            "except (ValueError, KeyError):\n"
            "    pass\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_unused_local_variable_positive(self) -> None:
        """Verify STYLE002 flags unused local variables in function scope."""
        rule = UnusedLocalVariableRule()
        code = (
            "def calculate(a, b):\n"
            "    unused_result = a + b\n"
            "    return a\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 1
        assert findings[0].rule_id == "STYLE002"
        assert "unused_result" in findings[0].message

    def test_unused_local_variable_negative(self) -> None:
        """Verify STYLE002 does not flag parameters, underscores, or read variables."""
        rule = UnusedLocalVariableRule()
        code = (
            "def calculate(a, b):\n"
            "    used_result = a + b\n"
            "    _ignored = 10\n"
            "    return used_result\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0

    def test_duplicate_branch_positive(self) -> None:
        """Verify STYLE003 flags if/else branches with identical non-trivial bodies."""
        rule = DuplicateBranchRule()
        code = (
            "if condition:\n"
            "    do_action(1)\n"
            "    do_action(2)\n"
            "else:\n"
            "    do_action(1)\n"
            "    do_action(2)\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 1
        assert findings[0].rule_id == "STYLE003"

    def test_duplicate_branch_negative(self) -> None:
        """Verify STYLE003 does not flag distinct branches or simple pass."""
        rule = DuplicateBranchRule()
        code = (
            "if condition:\n"
            "    do_action(1)\n"
            "else:\n"
            "    do_action(2)\n"
        )
        findings = run_rule(rule, code)
        assert len(findings) == 0
