"""Abstract base rule definition for modular AST analyzers."""

import ast
from abc import ABC, abstractmethod
from typing import List, Optional

from bug_detector.core.models import (
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
)


class BaseRule(ABC):
    """Abstract base class for all AST-based bug detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., CORR001, SEC001, STYLE001)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Short human-readable title for the rule."""
        pass

    @property
    @abstractmethod
    def category(self) -> BugCategory:
        """Category of issues detected by this rule."""
        pass

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity classification for findings from this rule."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed explanation of the issue and why it is flagged."""
        pass

    @abstractmethod
    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        """Inspect the AST and return any identified bug findings.

        Args:
            tree: Parsed Python AST.
            lines: Source code split by lines (for snippet extraction).
            filename: Name of the file being inspected.

        Returns:
            List of BugFinding items.
        """
        pass

    def create_finding(
        self,
        line: int,
        column: int,
        message: str,
        explanation: Optional[str] = None,
        suggested_fix: Optional[str] = None,
        end_line: Optional[int] = None,
        end_column: Optional[int] = None,
        lines: Optional[List[str]] = None,
    ) -> BugFinding:
        """Helper to create a validated BugFinding instance with snippet context."""
        snippet: Optional[str] = None
        if lines and 1 <= line <= len(lines):
            snippet = lines[line - 1].strip()

        return BugFinding(
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            message=message,
            explanation=explanation or self.description,
            suggested_fix=suggested_fix,
            location=CodeLocation(
                line=line,
                column=column,
                end_line=end_line,
                end_column=end_column,
            ),
            code_snippet=snippet,
        )
