"""AST analysis rules detecting common security issues and dangerous patterns.

CRITICAL SECURITY GUARDRAIL:
This module NEVER executes, evaluates, or imports submitted code.
All checks are performed by static AST tree inspection and pattern matching.
Sensitive secrets are ALWAYS redacted in findings and error messages.
"""

import ast
import re
from typing import List, Optional

from bug_detector.analyzers.rules.base import BaseRule
from bug_detector.core.models import BugCategory, BugFinding, Severity


class DangerousDynamicExecRule(BaseRule):
    """Detects calls to dangerous dynamic code evaluation primitives (eval / exec)."""

    @property
    def rule_id(self) -> str:
        return "SEC001"

    @property
    def name(self) -> str:
        return "Dangerous dynamic execution"

    @property
    def category(self) -> BugCategory:
        return BugCategory.SECURITY

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Calling 'eval()' or 'exec()' dynamically parses and executes arbitrary Python code. "
            "If any component of the input string originates from untrusted sources, "
            "it creates an immediate remote code execution (RCE) vulnerability."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_dangerous_call_name(node.func)
                if func_name:
                    findings.append(
                        self.create_finding(
                            line=node.lineno,
                            column=node.col_offset,
                            end_line=getattr(node, "end_lineno", None),
                            end_column=getattr(node, "end_col_offset", None),
                            message=f"Dangerous dynamic code execution call to '{func_name}()'.",
                            suggested_fix=(
                                "Use 'ast.literal_eval()' for safe parsing of data literals, "
                                "or map inputs to explicit dispatch lookup tables."
                            ),
                            lines=lines,
                        )
                    )
        return findings

    @staticmethod
    def _get_dangerous_call_name(node: ast.AST) -> Optional[str]:
        """Detect direct eval/exec calls or builtins.eval/exec calls."""
        if isinstance(node, ast.Name) and node.id in ("eval", "exec"):
            return node.id
        if isinstance(node, ast.Attribute) and node.attr in ("eval", "exec"):
            if isinstance(node.value, ast.Name) and node.value.id in (
                "builtins",
                "__builtins__",
            ):
                return f"{node.value.id}.{node.attr}"
        return None


class HardcodedSecretsRule(BaseRule):
    """Conservative detection of high-confidence hardcoded secrets and credentials.

    Redacts any sensitive tokens from messages and reports to prevent secret exposure.
    """

    SECRET_VAR_PATTERN = re.compile(
        r"^(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|"
        r"bearer[_-]?token|private[_-]?key|passwd|password|client[_-]?secret)$",
        re.IGNORECASE,
    )

    KNOWN_TOKEN_PATTERNS = [
        re.compile(r"^sk-[A-Za-z0-9_-]{20,}$"),  # OpenAI-style secret keys
        re.compile(r"^gh[pousr]-[A-Za-z0-9]{20,}$"),  # GitHub personal access tokens
        re.compile(r"^AKIA[0-9A-Z]{16}$"),  # AWS Access Key ID
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),  # Private Key header
    ]

    BENIGN_PLACEHOLDERS = {
        "test",
        "mock",
        "fake",
        "dummy",
        "example",
        "placeholder",
        "sample",
        "your-api-key",
        "your_api_key",
        "change_me",
        "changeme",
        "secret",
        "password",
        "none",
        "default",
    }

    @property
    def rule_id(self) -> str:
        return "SEC002"

    @property
    def name(self) -> str:
        return "Hardcoded secret or credential"

    @property
    def category(self) -> BugCategory:
        return BugCategory.SECURITY

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    @property
    def description(self) -> str:
        return (
            "Hardcoding sensitive API keys, tokens, or credentials in source code risks "
            "credential exposure and privilege compromise when pushed to repositories."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            # Check variable assignments: api_key = "..."
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and self.SECRET_VAR_PATTERN.match(
                        target.id
                    ):
                        if isinstance(node.value, ast.Constant) and isinstance(
                            node.value.value, str
                        ):
                            raw_val = node.value.value
                            if self._is_likely_real_secret(raw_val):
                                findings.append(
                                    self._build_secret_finding(
                                        target.id, node.value, lines
                                    )
                                )

            # Check annotated assignments: api_key: str = "..."
            elif isinstance(node, ast.AnnAssign):
                if (
                    isinstance(node.target, ast.Name)
                    and self.SECRET_VAR_PATTERN.match(node.target.id)
                    and node.value is not None
                ):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        raw_val = node.value.value
                        if self._is_likely_real_secret(raw_val):
                            findings.append(
                                self._build_secret_finding(
                                    node.target.id, node.value, lines
                                )
                            )

            # Check literal strings matching known token prefixes anywhere in AST
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                raw_str = node.value
                for pattern in self.KNOWN_TOKEN_PATTERNS:
                    if pattern.search(raw_str):
                        findings.append(
                            self.create_finding(
                                line=node.lineno,
                                column=node.col_offset,
                                end_line=getattr(node, "end_lineno", None),
                                end_column=getattr(node, "end_col_offset", None),
                                message="High-confidence API credential token literal detected.",
                                suggested_fix=(
                                    "Remove token literal from source and retrieve via "
                                    "environment variables ('os.getenv')."
                                ),
                                lines=self._redact_line_snippet(lines, node.lineno),
                            )
                        )
                        break
        return findings

    def _is_likely_real_secret(self, val: str) -> bool:
        """Filter out obvious placeholders, empty values, or short tests."""
        trimmed = val.strip().lower()
        if len(trimmed) < 10:
            return False
        if trimmed in self.BENIGN_PLACEHOLDERS:
            return False
        if any(b in trimmed for b in ("placeholder", "example", "your-key", "your_key")):
            return False
        return True

    def _build_secret_finding(
        self, var_name: str, const_node: ast.Constant, lines: List[str]
    ) -> BugFinding:
        return self.create_finding(
            line=const_node.lineno,
            column=const_node.col_offset,
            end_line=getattr(const_node, "end_lineno", None),
            end_column=getattr(const_node, "end_col_offset", None),
            message=(
                f"Potential hardcoded secret assigned to variable '{var_name}'."
            ),
            suggested_fix=(
                f"Replace literal credential with environment variable retrieval: "
                f"os.getenv('{var_name.upper()}')"
            ),
            lines=self._redact_line_snippet(lines, const_node.lineno),
        )

    @staticmethod
    def _redact_line_snippet(lines: List[str], line_no: int) -> List[str]:
        """Return a copy of lines where the target line is redacted to prevent secret leak."""
        if not lines or line_no < 1 or line_no > len(lines):
            return lines
        safe_lines = list(lines)
        target = safe_lines[line_no - 1]
        # Replace string literal contents with [REDACTED_SECRET]
        redacted = re.sub(r"(['\"])[^'\"]{8,}\1", r"\1[REDACTED_SECRET]\1", target)
        safe_lines[line_no - 1] = redacted
        return safe_lines


class InsecureTempFileRule(BaseRule):
    """Detects usage of tempfile.mktemp() which is vulnerable to race conditions."""

    @property
    def rule_id(self) -> str:
        return "SEC003"

    @property
    def name(self) -> str:
        return "Insecure temporary file creation"

    @property
    def category(self) -> BugCategory:
        return BugCategory.SECURITY

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    @property
    def description(self) -> str:
        return (
            "tempfile.mktemp() is deprecated and vulnerable to race conditions (symlink attacks). "
            "An attacker can create a file or symlink between the time the filename is generated "
            "and when the file is opened."
        )

    def check(self, tree: ast.AST, lines: List[str], filename: str) -> List[BugFinding]:
        findings: List[BugFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "mktemp":
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "tempfile"
                    ):
                        findings.append(
                            self.create_finding(
                                line=node.lineno,
                                column=node.col_offset,
                                end_line=getattr(node, "end_lineno", None),
                                end_column=getattr(node, "end_col_offset", None),
                                message="Insecure temporary file creation using tempfile.mktemp().",
                                suggested_fix=(
                                    "Use 'tempfile.NamedTemporaryFile()' or "
                                    "'tempfile.TemporaryDirectory()' instead."
                                ),
                                lines=lines,
                            )
                        )
                elif isinstance(node.func, ast.Name) and node.func.id == "mktemp":
                    findings.append(
                        self.create_finding(
                            line=node.lineno,
                            column=node.col_offset,
                            end_line=getattr(node, "end_lineno", None),
                            end_column=getattr(node, "end_col_offset", None),
                            message="Insecure temporary file generation using 'mktemp()'.",
                            suggested_fix="Use 'tempfile.NamedTemporaryFile()' instead.",
                            lines=lines,
                        )
                    )
        return findings
