"""AST analysis rules detecting common Python correctness bugs."""

import ast
from typing import List

from bug_detector.analyzers.rules.base import BaseRule
from bug_detector.core.models import BugCategory, BugFinding, Severity


class MutableDefaultArgRule(BaseRule):
    """Detects mutable default arguments in function definitions."""

    @property
    def rule_id(self) -> str:
        return "CORR001"

    @property
    def name(self) -> str:
        return "Mutable default argument"

    @property
    def category(self) -> BugCategory:
        return BugCategory.CORRECTNESS

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    @property
    def description(self) -> str:
        return (
            "Default argument values are evaluated once when the function definition is executed. "
            "Using mutable objects (like lists, dictionaries, or sets) causes shared state "
            "to persist across multiple function calls, leading to subtle bugs."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Inspect positional defaults and keyword-only defaults
                all_defaults = list(node.args.defaults) + [
                    d for d in node.args.kw_defaults if d is not None
                ]

                for default_expr in all_defaults:
                    if self._is_mutable_literal_or_call(default_expr):
                        findings.append(
                            self.create_finding(
                                line=default_expr.lineno,
                                column=default_expr.col_offset,
                                end_line=getattr(default_expr, "end_lineno", None),
                                end_column=getattr(default_expr, "end_col_offset", None),
                                message=(
                                    f"Function '{node.name}' uses a mutable default argument."
                                ),
                                suggested_fix=(
                                    "Use 'None' as the default argument value and initialize "
                                    "the mutable container inside the function body "
                                    "(e.g., 'if arg is None: arg = []')."
                                ),
                                lines=lines,
                            )
                        )
        return findings

    @staticmethod
    def _is_mutable_literal_or_call(node: ast.AST) -> bool:
        """Check if an AST node represents a mutable literal or construction call."""
        if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("list", "dict", "set"):
                return True
        return False


class DivisionByZeroRule(BaseRule):
    """Detects division, floor division, or modulo by literal zero."""

    @property
    def rule_id(self) -> str:
        return "CORR002"

    @property
    def name(self) -> str:
        return "Literal division by zero"

    @property
    def category(self) -> BugCategory:
        return BugCategory.CORRECTNESS

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Performing division, floor division, or modulo with a statically "
            "provable literal zero divisor unconditionally raises a ZeroDivisionError at runtime."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Div, ast.FloorDiv, ast.Mod)
            ):
                if self._is_literal_zero(node.right):
                    op_symbol = (
                        "/"
                        if isinstance(node.op, ast.Div)
                        else "//"
                        if isinstance(node.op, ast.FloorDiv)
                        else "%"
                    )
                    findings.append(
                        self.create_finding(
                            line=node.lineno,
                            column=node.col_offset,
                            end_line=getattr(node, "end_lineno", None),
                            end_column=getattr(node, "end_col_offset", None),
                            message=f"Division by literal zero using operator '{op_symbol}'.",
                            suggested_fix=(
                                "Ensure the divisor is non-zero before executing the operation, "
                                "or handle division by zero with a condition."
                            ),
                            lines=lines,
                        )
                    )
        return findings

    @staticmethod
    def _is_literal_zero(node: ast.AST) -> bool:
        """Determine if an AST node evaluates statically to literal zero."""
        if isinstance(node, ast.Constant) and (node.value == 0 or node.value == 0.0):
            # Explicitly guard against boolean False (in Python, False == 0 is True)
            return type(node.value) in (int, float) and not isinstance(node.value, bool)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            return DivisionByZeroRule._is_literal_zero(node.operand)
        return False


class IneffectiveComparisonRule(BaseRule):
    """Detects standalone comparison statements whose boolean results are discarded."""

    @property
    def rule_id(self) -> str:
        return "CORR003"

    @property
    def name(self) -> str:
        return "Ineffective standalone comparison"

    @property
    def category(self) -> BugCategory:
        return BugCategory.CORRECTNESS

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    @property
    def description(self) -> str:
        return (
            "A comparison expression is executed as an isolated statement and its "
            "boolean result is immediately discarded. This is typically a typo for an "
            "assignment ('=') or an if-statement."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Compare):
                findings.append(
                    self.create_finding(
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=getattr(node, "end_lineno", None),
                        end_column=getattr(node, "end_col_offset", None),
                        message="Standalone comparison expression result is unused and discarded.",
                        suggested_fix=(
                            "If assigning a value, replace '==' with '='. "
                            "If testing a condition, wrap the comparison inside an 'if' statement."
                        ),
                        lines=lines,
                    )
                )
        return findings


class UnreachableCodeRule(BaseRule):
    """Detects unreachable statements following unconditional jump/return statements."""

    @property
    def rule_id(self) -> str:
        return "CORR004"

    @property
    def name(self) -> str:
        return "Unreachable code"

    @property
    def category(self) -> BugCategory:
        return BugCategory.CORRECTNESS

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    @property
    def description(self) -> str:
        return (
            "Statements located directly after an unconditional return, raise, break, or continue "
            "within the same block can never be reached during execution."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            # Check any AST node that contains a list of statements
            for attr in ("body", "orelse", "finalbody"):
                stmts = getattr(node, attr, None)
                if isinstance(stmts, list):
                    findings.extend(self._scan_statement_list(stmts, lines))
        return findings

    def _scan_statement_list(
        self, stmts: List[ast.stmt], lines: List[str]
    ) -> List[BugFinding]:
        findings: List[BugFinding] = []
        terminator_found = False
        terminator_stmt = None

        for stmt in stmts:
            if terminator_found:
                findings.append(
                    self.create_finding(
                        line=stmt.lineno,
                        column=stmt.col_offset,
                        end_line=getattr(stmt, "end_lineno", None),
                        end_column=getattr(stmt, "end_col_offset", None),
                        message=(
                            f"Unreachable statement following '{terminator_stmt}' terminator."
                        ),
                        suggested_fix=(
                            "Remove dead code or reposition it before the terminating statement."
                        ),
                        lines=lines,
                    )
                )
            elif isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminator_found = True
                terminator_stmt = stmt.__class__.__name__.lower()

        return findings
