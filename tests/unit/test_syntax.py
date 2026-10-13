"""Unit tests for the SyntaxChecker component."""

from bug_detector.analyzers.syntax import SyntaxChecker


class TestSyntaxChecker:
    """Test suite for Python AST syntax verification."""

    def test_valid_python_syntax(self) -> None:
        """Verify valid Python syntax returns valid result with no errors."""
        checker = SyntaxChecker()
        code = "def greet(name: str) -> str:\n    return f'Hello, {name}!'\n"
        res = checker.check(code)
        assert res.is_valid is True
        assert res.error_message is None
        assert res.line is None
        assert res.column is None

    def test_syntax_error_missing_colon(self) -> None:
        """Verify syntax error detection on missing colon in function header."""
        checker = SyntaxChecker()
        code = "def broken()\n    pass\n"
        res = checker.check(code)
        assert res.is_valid is False
        assert res.line == 1
        assert res.column is not None
        assert res.error_message is not None
        assert "expected ':'" in res.error_message.lower() or "syntax" in res.error_message.lower()

    def test_syntax_error_indentation(self) -> None:
        """Verify syntax error detection on bad indentation."""
        checker = SyntaxChecker()
        code = "def func():\npass\n"
        res = checker.check(code)
        assert res.is_valid is False
        assert res.line == 2
        assert res.error_message is not None
        assert "indent" in res.error_message.lower() or "expected" in res.error_message.lower()

    def test_syntax_error_incomplete_expression(self) -> None:
        """Verify syntax error on incomplete expression."""
        checker = SyntaxChecker()
        code = "x = 10 +\n"
        res = checker.check(code)
        assert res.is_valid is False
        assert res.line == 1

    def test_syntax_error_extracts_clean_text(self) -> None:
        """Verify syntax checker extracts line excerpt text when available."""
        checker = SyntaxChecker()
        code = "y = (1, 2,\n"
        res = checker.check(code)
        assert res.is_valid is False
        assert res.line is not None
