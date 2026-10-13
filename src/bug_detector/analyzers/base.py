"""Abstract Base Analyzer definition for the Bug Detection System."""

from abc import ABC, abstractmethod
from typing import List

from bug_detector.core.models import BugFinding


class BaseAnalyzer(ABC):
    """Abstract interface that all static analyzers and rule checkers must implement.

    CRITICAL SECURITY GUARDRAIL:
    Subclasses MUST NEVER execute, compile for execution (eval/exec/subprocess),
    or dynamically import user-supplied source code.
    All inspection MUST be performed strictly via AST traversal, token analysis,
    or static pattern matching.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier for the analyzer."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of issues detected by this analyzer."""
        pass

    @abstractmethod
    def analyze(self, source_code: str, filename: str = "snippet.py") -> List[BugFinding]:
        """Analyze source code and return a list of detected findings.

        Args:
            source_code: Raw Python code string to inspect.
            filename: Virtual or original filename for reporting.

        Returns:
            List of BugFinding items identified in the source.
        """
        pass
