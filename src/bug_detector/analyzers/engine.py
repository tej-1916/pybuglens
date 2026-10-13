"""Analysis engine coordinating sanitization, syntax verification, and static AST inspection."""

import time
from typing import Optional

from bug_detector.analyzers.ast_scanner import ASTScanner
from bug_detector.core.config import Settings, get_settings
from bug_detector.core.models import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisSummary,
)
from bug_detector.storage.repository import ReviewRepository
from bug_detector.utils.sanitizer import CodeSanitizer


class AnalysisEngine:
    """Core pipeline engine coordinating end-to-end static code analysis."""

    def __init__(
        self,
        scanner: Optional[ASTScanner] = None,
        sanitizer: Optional[CodeSanitizer] = None,
        repository: Optional[ReviewRepository] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.scanner = scanner or ASTScanner()
        self.sanitizer = sanitizer or CodeSanitizer()
        self.repository = repository
        self.settings = settings or get_settings()

    def analyze(
        self, request: AnalysisRequest, save: bool = True
    ) -> AnalysisResult:
        """Execute complete static analysis pipeline on submitted Python code.

        Workflow:
            1. Sanitize raw input (enforce size bounds, strip null bytes, normalize CRLF).
            2. Compute SHA-256 code hash and source line metrics.
            3. Run AST Syntax parsing and rule checks.
            4. Compile findings and metrics into structured AnalysisResult.
            5. Optionally persist review to database when requested and repository is present.
            6. Return structured result.

        CRITICAL SECURITY INVARIANT:
            Under NO circumstances is user-submitted code executed or evaluated.
        """
        start_time = time.perf_counter()

        # Step 1: Input sanitization & size guards
        sanitized = self.sanitizer.sanitize(request.source_code)

        # Step 2: AST Analysis & Syntax Verification
        findings, syntax_res = self.scanner.analyze_with_syntax(
            source_code=sanitized.code,
            filename=request.filename,
        )

        # Step 3: Compute summary counts
        summary = AnalysisSummary.from_findings(findings)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Construct comprehensive result
        result = AnalysisResult(
            filename=request.filename,
            source_code=sanitized.code,
            code_hash=sanitized.sha256,
            line_count=sanitized.line_count,
            char_count=sanitized.char_count,
            syntax=syntax_res,
            findings=findings,
            summary=summary,
            ai_review=None,
            execution_duration_ms=round(duration_ms, 2),
        )

        # Step 5: Optional persistence
        # Strict security guardrail: DEMO_MODE strictly prevents persisting visitor code
        if save and not self.settings.demo_mode and self.repository is not None:
            self.repository.save_review(result)

        return result
