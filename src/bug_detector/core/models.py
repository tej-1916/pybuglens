"""Core data models and schemas for the Bug Detection System."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Bug finding severity classifications."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class BugCategory(str, Enum):
    """Categorization for static and syntactic bugs."""

    SYNTAX = "syntax"
    CORRECTNESS = "correctness"
    SECURITY = "security"
    STYLE = "style"
    PERFORMANCE = "performance"


class CodeLocation(BaseModel):
    """Source code coordinates representing error/finding locations."""

    line: int = Field(ge=1, description="1-indexed line number")
    column: int = Field(ge=0, description="0-indexed or 1-indexed column offset")
    end_line: Optional[int] = Field(
        default=None, ge=1, description="Ending line number if range"
    )
    end_column: Optional[int] = Field(
        default=None, ge=0, description="Ending column offset if range"
    )


class BugFinding(BaseModel):
    """An individual bug or issue identified by the static analyzer or AI."""

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique finding ID")
    rule_id: str = Field(description="Identifier for the rule or detector that flagged this issue")
    category: BugCategory = Field(description="Category of the bug")
    severity: Severity = Field(description="Severity classification")
    message: str = Field(description="Short human-readable headline describing the issue")
    explanation: str = Field(description="Detailed explanation of why this is problematic")
    suggested_fix: Optional[str] = Field(
        default=None, description="Recommended fix or code remediation"
    )
    location: CodeLocation = Field(description="Coordinates within the source code")
    code_snippet: Optional[str] = Field(
        default=None, description="Excerpt of code containing the issue"
    )


class SyntaxValidationResult(BaseModel):
    """Result of AST syntax parsing and verification."""

    is_valid: bool = Field(description="Whether the code successfully compiled to an AST")
    error_message: Optional[str] = Field(
        default=None, description="SyntaxError description if invalid"
    )
    line: Optional[int] = Field(default=None, description="Syntax error line")
    column: Optional[int] = Field(default=None, description="Syntax error column")
    text: Optional[str] = Field(default=None, description="Syntax error line text")


class AIReviewResult(BaseModel):
    """Structured response from optional OpenAI-assisted review."""

    enabled: bool = Field(default=False, description="Whether AI review was requested")
    success: bool = Field(default=False, description="Whether AI review completed successfully")
    review_text: Optional[str] = Field(
        default=None, description="AI-generated review insights and recommendations"
    )
    model_used: Optional[str] = Field(default=None, description="OpenAI model identifier used")
    error_message: Optional[str] = Field(
        default=None, description="Error details if AI review failed"
    )
    tokens_used: Optional[int] = Field(default=None, description="Token count consumed")


class AnalysisRequest(BaseModel):
    """Incoming request payload for code analysis."""

    source_code: str = Field(description="Raw Python source code to analyze")
    filename: str = Field(default="snippet.py", description="Name of the file being reviewed")
    enable_ai: bool = Field(
        default=False, description="Whether to request optional AI code review"
    )

    @field_validator("source_code")
    @classmethod
    def validate_source_code_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source_code cannot be empty or purely whitespace")
        return v


class AnalysisSummary(BaseModel):
    """Aggregated finding counts for quick consumption."""

    total_findings: int = 0
    critical_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0

    @classmethod
    def from_findings(cls, findings: List[BugFinding]) -> "AnalysisSummary":
        """Compute counts from a list of findings."""
        summary = cls(total_findings=len(findings))
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                summary.critical_count += 1
            elif finding.severity == Severity.ERROR:
                summary.error_count += 1
            elif finding.severity == Severity.WARNING:
                summary.warning_count += 1
            elif finding.severity == Severity.INFO:
                summary.info_count += 1
        return summary


class AnalysisResult(BaseModel):
    """Complete structured output of a code analysis job."""

    review_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique review run ID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the analysis run",
    )
    filename: str = Field(default="snippet.py", description="Filename analyzed")
    source_code: str = Field(description="Submitted source code")
    code_hash: str = Field(description="SHA-256 hash of the submitted source code")
    line_count: int = Field(ge=0, description="Total line count of source code")
    char_count: int = Field(ge=0, description="Total character count of source code")
    syntax: SyntaxValidationResult = Field(description="Python syntax verification result")
    findings: List[BugFinding] = Field(default_factory=list, description="List of detected bugs")
    summary: AnalysisSummary = Field(description="Summary metrics of findings")
    ai_review: Optional[AIReviewResult] = Field(
        default=None, description="Optional AI review output"
    )
    execution_duration_ms: float = Field(
        ge=0.0, description="Total execution duration in milliseconds"
    )


class AnalysisHistoryItem(BaseModel):
    """Compact summary of an analysis for listing in history views."""

    review_id: str = Field(description="Unique review identifier")
    timestamp: datetime = Field(description="UTC timestamp of analysis run")
    filename: str = Field(description="Filename analyzed")
    code_hash: str = Field(description="SHA-256 hash of code")
    total_findings: int = Field(ge=0, description="Total number of findings")
    is_valid_syntax: bool = Field(description="Whether the code had valid Python syntax")
    execution_duration_ms: float = Field(ge=0.0, description="Duration in ms")
