"""Python source code syntax validation using the standard library ast module.

CRITICAL SECURITY GUARDRAIL:
This module NEVER executes, evaluates, or imports submitted code.
All syntax analysis is strictly performed via ast.parse().
"""

import ast
from typing import Optional

from bug_detector.core.models import SyntaxValidationResult


class SyntaxChecker:
    """Safely checks Python source code for syntax validity."""

    def check(self, source_code: str, filename: str = "snippet.py") -> SyntaxValidationResult:
        """Parse source code into an AST and catch any SyntaxError.

        Args:
            source_code: Python source code string.
            filename: Virtual filename for syntax error tracking.

        Returns:
            SyntaxValidationResult with line, column, error message, and excerpt if invalid.
        """
        try:
            ast.parse(source_code, filename=filename)
            return SyntaxValidationResult(
                is_valid=True,
                error_message=None,
                line=None,
                column=None,
                text=None,
            )
        except SyntaxError as err:
            clean_text: Optional[str] = None
            if err.text:
                clean_text = err.text.strip("\r\n")

            return SyntaxValidationResult(
                is_valid=False,
                error_message=err.msg or "Syntax error in Python source code",
                line=err.lineno or 1,
                column=err.offset or 0,
                text=clean_text,
            )
        except Exception as err:  # In case of memory error or unexpected parser exception
            return SyntaxValidationResult(
                is_valid=False,
                error_message=f"Failed to parse source code: {str(err)}",
                line=1,
                column=0,
                text=None,
            )
