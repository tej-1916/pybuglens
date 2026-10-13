"""Repository providing typed SQLite data access for code reviews."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bug_detector.core.models import (
    AIReviewResult,
    AnalysisHistoryItem,
    AnalysisResult,
    AnalysisSummary,
    BugFinding,
    SyntaxValidationResult,
)
from bug_detector.storage.database import DatabaseManager


class StorageError(RuntimeError):
    """Exception raised for storage failures to prevent leaking sensitive source data."""

    pass


class ReviewRepository:
    """Repository handling CRUD operations and queries on the reviews SQLite table."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save_review(self, result: AnalysisResult) -> None:
        """Persist an AnalysisResult record to SQLite.

        Uses parameterized SQL to prevent SQL injection.
        """
        syntax_json: Optional[str] = None
        if not result.syntax.is_valid:
            syntax_json = result.syntax.model_dump_json()

        findings_data: List[Dict[str, Any]] = [
            f.model_dump() for f in result.findings
        ]
        findings_json = json.dumps(findings_data)

        ai_review_json: Optional[str] = None
        if result.ai_review is not None:
            ai_review_json = result.ai_review.model_dump_json()

        sql = """
        INSERT INTO reviews (
            review_id,
            timestamp,
            filename,
            source_code,
            code_hash,
            line_count,
            char_count,
            is_valid_syntax,
            syntax_error_details,
            findings_json,
            critical_count,
            error_count,
            warning_count,
            info_count,
            total_findings,
            ai_review_json,
            execution_duration_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            result.review_id,
            result.timestamp.isoformat(),
            result.filename,
            result.source_code,
            result.code_hash,
            result.line_count,
            result.char_count,
            1 if result.syntax.is_valid else 0,
            syntax_json,
            findings_json,
            result.summary.critical_count,
            result.summary.error_count,
            result.summary.warning_count,
            result.summary.info_count,
            result.summary.total_findings,
            ai_review_json,
            result.execution_duration_ms,
        )

        try:
            with self.db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, params)
        except Exception as err:
            raise StorageError(
                f"Failed to persist review record: {type(err).__name__}"
            ) from None

    def get_review_by_id(self, review_id: str) -> Optional[AnalysisResult]:
        """Retrieve a full AnalysisResult by its unique review UUID.

        Returns None if no record exists with the specified review_id.
        """
        sql = """
        SELECT
            review_id,
            timestamp,
            filename,
            source_code,
            code_hash,
            line_count,
            char_count,
            is_valid_syntax,
            syntax_error_details,
            findings_json,
            critical_count,
            error_count,
            warning_count,
            info_count,
            total_findings,
            ai_review_json,
            execution_duration_ms
        FROM reviews
        WHERE review_id = ?
        """
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (review_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return self._row_to_analysis_result(row)

    def list_recent_reviews(
        self, limit: int = 50, offset: int = 0
    ) -> List[AnalysisHistoryItem]:
        """List historical reviews ordered newest-first with pagination."""
        sql = """
        SELECT
            review_id,
            timestamp,
            filename,
            code_hash,
            total_findings,
            is_valid_syntax,
            execution_duration_ms
        FROM reviews
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (limit, offset))
            rows = cursor.fetchall()
            return [self._row_to_history_item(row) for row in rows]

    def search_reviews(
        self,
        code_hash: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AnalysisHistoryItem]:
        """Search reviews matching optional code hash and UTC timestamp ranges."""
        conditions = ["1=1"]
        params: List[Any] = []

        if code_hash:
            conditions.append("code_hash = ?")
            params.append(code_hash)

        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time.isoformat())

        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time.isoformat())

        where_clause = " AND ".join(conditions)
        sql = f"""
        SELECT
            review_id,
            timestamp,
            filename,
            code_hash,
            total_findings,
            is_valid_syntax,
            execution_duration_ms
        FROM reviews
        WHERE {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_history_item(row) for row in rows]

    def delete_review(self, review_id: str) -> bool:
        """Delete an individual review record by ID.

        Returns True if a row was deleted, False if review_id did not exist.
        """
        sql = "DELETE FROM reviews WHERE review_id = ?"
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (review_id,))
            return cursor.rowcount > 0

    def clear_history(self) -> int:
        """Delete all review records from the database.

        Requires an explicit call and returns the number of deleted rows.
        """
        sql = "DELETE FROM reviews"
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            return cursor.rowcount

    def count_reviews(self) -> int:
        """Return total count of stored review records."""
        sql = "SELECT COUNT(*) FROM reviews"
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql)
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    @staticmethod
    def _row_to_history_item(row: Any) -> AnalysisHistoryItem:
        """Convert a database row into an AnalysisHistoryItem."""
        ts = datetime.fromisoformat(row["timestamp"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return AnalysisHistoryItem(
            review_id=row["review_id"],
            timestamp=ts,
            filename=row["filename"],
            code_hash=row["code_hash"],
            total_findings=row["total_findings"],
            is_valid_syntax=bool(row["is_valid_syntax"]),
            execution_duration_ms=float(row["execution_duration_ms"]),
        )

    @staticmethod
    def _row_to_analysis_result(row: Any) -> AnalysisResult:
        """Reconstruct a full AnalysisResult from a database row."""
        ts = datetime.fromisoformat(row["timestamp"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        # Reconstruct syntax result
        if row["is_valid_syntax"]:
            syntax = SyntaxValidationResult(
                is_valid=True,
                error_message=None,
                line=None,
                column=None,
                text=None,
            )
        else:
            if row["syntax_error_details"]:
                syntax = SyntaxValidationResult.model_validate_json(
                    row["syntax_error_details"]
                )
            else:
                syntax = SyntaxValidationResult(
                    is_valid=False,
                    error_message="Syntax error",
                    line=1,
                    column=0,
                )

        # Reconstruct findings
        findings_raw = json.loads(row["findings_json"])
        findings = [BugFinding.model_validate(f) for f in findings_raw]

        # Reconstruct summary
        summary = AnalysisSummary(
            total_findings=row["total_findings"],
            critical_count=row["critical_count"],
            error_count=row["error_count"],
            warning_count=row["warning_count"],
            info_count=row["info_count"],
        )

        # Reconstruct optional AI review
        ai_review: Optional[AIReviewResult] = None
        if row["ai_review_json"]:
            ai_review = AIReviewResult.model_validate_json(row["ai_review_json"])

        return AnalysisResult(
            review_id=row["review_id"],
            timestamp=ts,
            filename=row["filename"],
            source_code=row["source_code"],
            code_hash=row["code_hash"],
            line_count=row["line_count"],
            char_count=row["char_count"],
            syntax=syntax,
            findings=findings,
            summary=summary,
            ai_review=ai_review,
            execution_duration_ms=float(row["execution_duration_ms"]),
        )
