"""AST analysis rules detecting style, maintainability, and code hygiene issues."""

import ast
from typing import Dict, List, Set

from bug_detector.analyzers.rules.base import BaseRule
from bug_detector.core.models import BugCategory, BugFinding, Severity


class BareExceptRule(BaseRule):
    """Detects bare except: clauses that catch BaseException."""

    @property
    def rule_id(self) -> str:
        return "STYLE001"

    @property
    def name(self) -> str:
        return "Bare except clause"

    @property
    def category(self) -> BugCategory:
        return BugCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    @property
    def description(self) -> str:
        return (
            "A bare 'except:' clause catches BaseException, which includes SystemExit, "
            "KeyboardInterrupt, and MemoryError. This interferes with clean process exits "
            "and hides critical program crashes."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(
                    self.create_finding(
                        line=node.lineno,
                        column=node.col_offset,
                        end_line=getattr(node, "end_lineno", None),
                        end_column=getattr(node, "end_col_offset", None),
                        message="Bare 'except:' clause catches all exceptions indiscriminately.",
                        suggested_fix=(
                            "Specify the expected exception type(s), or catch 'Exception' "
                            "(e.g., 'except Exception:')."
                        ),
                        lines=lines,
                    )
                )
        return findings


class UnusedLocalVariableRule(BaseRule):
    """Detects unused local variables within function scopes.

    Filters out variables prefixed with underscore (_), self, cls, and global/nonlocal declarations.
    """

    IGNORABLE_NAMES = {"self", "cls", "_"}

    @property
    def rule_id(self) -> str:
        return "STYLE002"

    @property
    def name(self) -> str:
        return "Unused local variable"

    @property
    def category(self) -> BugCategory:
        return BugCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    @property
    def description(self) -> str:
        return (
            "A local variable is assigned inside a function but is never read or referenced. "
            "This often indicates dead code, an incomplete refactor, or a calculation "
            "whose result is forgotten."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function_scope(node, lines))
        return findings

    def _check_function_scope(
        self, func_node: ast.AST, lines: List[str]
    ) -> List[BugFinding]:
        findings: List[BugFinding] = []
        defined_vars: Dict[str, ast.Name] = {}
        used_vars: Set[str] = set()
        global_or_nonlocal: Set[str] = set()

        # Extract parameter names so we do not flag function parameters
        param_names: Set[str] = set()
        args_obj = getattr(func_node, "args", None)
        if args_obj:
            for arg in (
                args_obj.posonlyargs
                + args_obj.args
                + args_obj.kwonlyargs
            ):
                param_names.add(arg.arg)
            if args_obj.vararg:
                param_names.add(args_obj.vararg.arg)
            if args_obj.kwarg:
                param_names.add(args_obj.kwarg.arg)

        # Walk the function body (avoiding nested function definitions to prevent scope pollution)
        for child in ast.walk(func_node):
            if child is func_node:
                continue

            # Record global and nonlocal keywords
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                global_or_nonlocal.update(child.names)
                continue

            # Skip traversing inside nested functions/classes when collecting local variables
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Nested functions can read outer variables; record their loaded names
                for nested_child in ast.walk(child):
                    if (
                        isinstance(nested_child, ast.Name)
                        and isinstance(nested_child.ctx, ast.Load)
                    ):
                        used_vars.add(nested_child.id)
                continue

            # Record variable stores: x = ...
            if isinstance(child, ast.Name):
                if isinstance(child.ctx, ast.Store):
                    name = child.id
                    if (
                        name not in self.IGNORABLE_NAMES
                        and not name.startswith("_")
                        and name not in param_names
                    ):
                        if name not in defined_vars:
                            defined_vars[name] = child
                elif isinstance(child.ctx, ast.Load):
                    used_vars.add(child.id)

        # Identify defined locals that were never loaded
        for var_name, store_node in defined_vars.items():
            if var_name not in used_vars and var_name not in global_or_nonlocal:
                findings.append(
                    self.create_finding(
                        line=store_node.lineno,
                        column=store_node.col_offset,
                        end_line=getattr(store_node, "end_lineno", None),
                        end_column=getattr(store_node, "end_col_offset", None),
                        message=f"Local variable '{var_name}' is assigned but never used.",
                        suggested_fix=(
                            f"Remove the unused variable '{var_name}', or rename it to "
                            f"'_{var_name}' if required by an unpacking pattern."
                        ),
                        lines=lines,
                    )
                )

        return findings


class DuplicateBranchRule(BaseRule):
    """Detects duplicate or redundant branches in conditional statements."""

    @property
    def rule_id(self) -> str:
        return "STYLE003"

    @property
    def name(self) -> str:
        return "Duplicate conditional branch"

    @property
    def category(self) -> BugCategory:
        return BugCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    @property
    def description(self) -> str:
        return (
            "An if statement contains identical bodies across both the 'if' and 'else' branches, "
            "or contains redundant conditions across elif branches."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Check if if-body and else-body have identical non-trivial code
                if node.body and node.orelse:
                    if self._are_bodies_identical(node.body, node.orelse):
                        findings.append(
                            self.create_finding(
                                line=node.lineno,
                                column=node.col_offset,
                                end_line=getattr(node, "end_lineno", None),
                                end_column=getattr(node, "end_col_offset", None),
                                message=(
                                    "Both 'if' and 'else' branches execute identical statements."
                                ),
                                suggested_fix=(
                                    "Remove the redundant condition or differentiate the "
                                    "branch behaviors."
                                ),
                                lines=lines,
                            )
                        )
        return findings

    @staticmethod
    def _are_bodies_identical(
        body1: List[ast.stmt], body2: List[ast.stmt]
    ) -> bool:
        """Compare two statement lists for identical AST structure."""
        if len(body1) != len(body2):
            return False
        # If body is just pass, don't flag as duplicate logic
        if len(body1) == 1 and isinstance(body1[0], ast.Pass):
            return False

        for s1, s2 in zip(body1, body2, strict=False):
            if ast.dump(s1) != ast.dump(s2):
                return False
        return True
