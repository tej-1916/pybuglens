"""Modular AST analysis rules package."""

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

__all__ = [
    "BareExceptRule",
    "BaseRule",
    "DangerousDynamicExecRule",
    "DivisionByZeroRule",
    "DuplicateBranchRule",
    "HardcodedSecretsRule",
    "IneffectiveComparisonRule",
    "InsecureTempFileRule",
    "MutableDefaultArgRule",
    "UnreachableCodeRule",
    "UnusedLocalVariableRule",
]
