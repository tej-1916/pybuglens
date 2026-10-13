"""Unit tests for code input sanitization and validation."""

import hashlib

import pytest

from bug_detector.utils.sanitizer import CodeSanitizer


class TestCodeSanitizer:
    """Test suite for CodeSanitizer."""

    def test_sanitize_valid_code(self) -> None:
        """Verify normal code is properly sanitized and hashed."""
        sanitizer = CodeSanitizer()
        raw = "def foo():\r\n    return 42\r\n"
        result = sanitizer.sanitize(raw)

        # Line endings normalized to LF
        assert "\r" not in result.code
        assert result.code == "def foo():\n    return 42\n"
        assert result.line_count == 2
        assert result.byte_size == len(result.code.encode("utf-8"))
        assert result.sha256 == hashlib.sha256(result.code.encode("utf-8")).hexdigest()

    def test_strip_null_bytes(self) -> None:
        """Verify embedded null bytes are stripped out safely."""
        sanitizer = CodeSanitizer()
        raw = "x = 'hello\x00world'\n"
        result = sanitizer.sanitize(raw)
        assert "\x00" not in result.code
        assert result.code == "x = 'helloworld'\n"

    def test_reject_empty_or_whitespace(self) -> None:
        """Verify empty and whitespace inputs raise ValueError."""
        sanitizer = CodeSanitizer()
        with pytest.raises(ValueError, match="cannot be empty"):
            sanitizer.sanitize("")

        with pytest.raises(ValueError, match="cannot be empty"):
            sanitizer.sanitize("   \t  \n  ")

    def test_reject_non_string(self) -> None:
        """Verify non-string inputs raise ValueError."""
        sanitizer = CodeSanitizer()
        with pytest.raises(ValueError, match="must be a non-null string"):
            sanitizer.sanitize(None)  # type: ignore

    def test_max_bytes_limit(self) -> None:
        """Verify byte size limit enforcement."""
        sanitizer = CodeSanitizer(max_bytes=50)
        small_code = "x = 1\n"
        assert sanitizer.sanitize(small_code).code == small_code

        large_code = "x = '" + ("A" * 100) + "'\n"
        with pytest.raises(ValueError, match="exceeds maximum limit of 50 bytes"):
            sanitizer.sanitize(large_code)

    def test_max_lines_limit(self) -> None:
        """Verify line count limit enforcement."""
        sanitizer = CodeSanitizer(max_lines=5)
        four_lines = "a = 1\nb = 2\nc = 3\nd = 4\n"
        assert sanitizer.sanitize(four_lines).line_count == 4

        six_lines = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n"
        with pytest.raises(ValueError, match="exceeds maximum limit of 5 lines"):
            sanitizer.sanitize(six_lines)
