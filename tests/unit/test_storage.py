"""Unit tests for SQLite database manager, repository layer, and pipeline persistence."""

import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

from bug_detector.analyzers.engine import AnalysisEngine
from bug_detector.core.config import Settings
from bug_detector.core.models import (
    AIReviewResult,
    AnalysisRequest,
    AnalysisResult,
    AnalysisSummary,
    BugCategory,
    BugFinding,
    CodeLocation,
    Severity,
    SyntaxValidationResult,
)
from bug_detector.storage.database import CURRENT_SCHEMA_VERSION, DatabaseManager
from bug_detector.storage.repository import ReviewRepository, StorageError


@pytest.fixture
def temp_db_dir() -> Generator[str, None, None]:
    """Provide an isolated temporary directory for testing filesystem SQLite databases."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def memory_db() -> Generator[DatabaseManager, None, None]:
    """Provide an in-memory DatabaseManager instance with clean teardown."""
    db = DatabaseManager(db_path=":memory:")
    yield db
    db.close()


@pytest.fixture
def repository(memory_db: DatabaseManager) -> ReviewRepository:
    """Provide a ReviewRepository wired to in-memory SQLite."""
    return ReviewRepository(memory_db)


@pytest.fixture
def sample_analysis_result() -> AnalysisResult:
    """Create a sample AnalysisResult with full fields populated."""
    finding = BugFinding(
        rule_id="CORR001",
        category=BugCategory.CORRECTNESS,
        severity=Severity.ERROR,
        message="Mutable default argument",
        explanation="Default list is shared.",
        suggested_fix="Use None default.",
        location=CodeLocation(line=2, column=10),
        code_snippet="def f(x=[]):",
    )
    return AnalysisResult(
        review_id="test-review-uuid-001",
        timestamp=datetime.now(timezone.utc),
        filename="app.py",
        source_code="def f(x=[]):\n    return x\n",
        code_hash="3a8e94a1d8487b92bbcf4130089e9f95d",
        line_count=2,
        char_count=25,
        syntax=SyntaxValidationResult(is_valid=True),
        findings=[finding],
        summary=AnalysisSummary.from_findings([finding]),
        ai_review=AIReviewResult(
            enabled=True,
            success=True,
            review_text="Looks mostly fine except mutable default.",
            model_used="gpt-4o-mini",
            tokens_used=75,
        ),
        execution_duration_ms=15.4,
    )


class TestStorageAndRepository:
    """Test suite for SQLite database manager and repository operations."""

    def test_database_initialization(self, memory_db: DatabaseManager) -> None:
        """Verify schema tables, versioning, and indexes are properly created."""
        with memory_db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            assert "schema_version" in tables
            assert "reviews" in tables

            cursor.execute("SELECT version FROM schema_version;")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == CURRENT_SCHEMA_VERSION

    def test_database_directory_auto_creation(self, temp_db_dir: str) -> None:
        """Verify parent directories are automatically created if they do not exist."""
        nested_dir = os.path.join(temp_db_dir, "deep", "nested", "storage")
        db_path = os.path.join(nested_dir, "test.db")
        assert not os.path.exists(nested_dir)

        db = DatabaseManager(db_path=db_path)
        assert os.path.exists(nested_dir)
        assert os.path.exists(db.db_path)
        db.close()

    def test_save_and_get_review(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify saving a complete review and retrieving it by ID."""
        repository.save_review(sample_analysis_result)

        retrieved = repository.get_review_by_id(sample_analysis_result.review_id)
        assert retrieved is not None
        assert retrieved.review_id == sample_analysis_result.review_id
        assert retrieved.filename == sample_analysis_result.filename
        assert retrieved.code_hash == sample_analysis_result.code_hash
        assert retrieved.line_count == 2
        assert retrieved.syntax.is_valid is True
        assert len(retrieved.findings) == 1
        assert retrieved.findings[0].rule_id == "CORR001"
        assert retrieved.ai_review is not None
        assert retrieved.ai_review.tokens_used == 75

    def test_get_nonexistent_review(self, repository: ReviewRepository) -> None:
        """Verify get_review_by_id returns None for unknown review IDs."""
        res = repository.get_review_by_id("non-existent-uuid-999")
        assert res is None

    def test_list_recent_reviews_and_pagination(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify listing reviews orders newest-first and respects limit and offset."""
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            res = sample_analysis_result.model_copy(
                update={
                    "review_id": f"rev-batch-{i}",
                    "timestamp": base_time + timedelta(seconds=i),
                }
            )
            repository.save_review(res)

        assert repository.count_reviews() == 5

        # First page (limit 3)
        page1 = repository.list_recent_reviews(limit=3, offset=0)
        assert len(page1) == 3
        # Newest first: rev-batch-4 should be first
        assert page1[0].review_id == "rev-batch-4"
        assert page1[1].review_id == "rev-batch-3"
        assert page1[2].review_id == "rev-batch-2"

        # Second page (limit 3, offset 3)
        page2 = repository.list_recent_reviews(limit=3, offset=3)
        assert len(page2) == 2
        assert page2[0].review_id == "rev-batch-1"
        assert page2[1].review_id == "rev-batch-0"

    def test_search_reviews_by_code_hash(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify searching reviews by SHA-256 hash."""
        res1 = sample_analysis_result.model_copy(
            update={"review_id": "r1", "code_hash": "hash-target-aaa"}
        )
        res2 = sample_analysis_result.model_copy(
            update={"review_id": "r2", "code_hash": "hash-other-bbb"}
        )
        repository.save_review(res1)
        repository.save_review(res2)

        results = repository.search_reviews(code_hash="hash-target-aaa")
        assert len(results) == 1
        assert results[0].review_id == "r1"

    def test_search_reviews_by_date_range(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify searching reviews by timestamp range."""
        t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 10, 10, 0, 0, tzinfo=timezone.utc)

        r0 = sample_analysis_result.model_copy(update={"review_id": "r0", "timestamp": t0})
        r1 = sample_analysis_result.model_copy(update={"review_id": "r1", "timestamp": t1})
        r2 = sample_analysis_result.model_copy(update={"review_id": "r2", "timestamp": t2})

        repository.save_review(r0)
        repository.save_review(r1)
        repository.save_review(r2)

        # Range filtering between Jan 2 and Jan 7
        filtered = repository.search_reviews(
            start_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 7, tzinfo=timezone.utc),
        )
        assert len(filtered) == 1
        assert filtered[0].review_id == "r1"

    def test_delete_review(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify deleting an existing review returns True, and deleting missing returns False."""
        repository.save_review(sample_analysis_result)
        assert repository.count_reviews() == 1

        # Delete existing
        assert repository.delete_review(sample_analysis_result.review_id) is True
        assert repository.count_reviews() == 0

        # Delete already deleted / non-existent
        assert repository.delete_review(sample_analysis_result.review_id) is False

    def test_clear_history(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify clear_history removes all reviews and returns count."""
        repository.save_review(sample_analysis_result.model_copy(update={"review_id": "c1"}))
        repository.save_review(sample_analysis_result.model_copy(update={"review_id": "c2"}))
        assert repository.count_reviews() == 2

        deleted_count = repository.clear_history()
        assert deleted_count == 2
        assert repository.count_reviews() == 0

    def test_utc_timestamp_handling(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify UTC timestamp retains timezone information after persistence."""
        repository.save_review(sample_analysis_result)
        item = repository.get_review_by_id(sample_analysis_result.review_id)
        assert item is not None
        assert item.timestamp.tzinfo is not None
        assert item.timestamp.tzinfo == timezone.utc

    def test_json_syntax_error_details_persistence(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify syntax error details serialize and deserialize properly."""
        syntax_err = SyntaxValidationResult(
            is_valid=False,
            error_message="invalid syntax at line 1",
            line=1,
            column=4,
            text="def broken(:",
        )
        res = sample_analysis_result.model_copy(
            update={"review_id": "syntax-err-rev", "syntax": syntax_err}
        )
        repository.save_review(res)

        retrieved = repository.get_review_by_id("syntax-err-rev")
        assert retrieved is not None
        assert retrieved.syntax.is_valid is False
        assert retrieved.syntax.line == 1
        assert retrieved.syntax.text == "def broken(:"

    def test_transaction_rollback_on_failure(self, memory_db: DatabaseManager) -> None:
        """Verify transaction rollbacks completely when an exception occurs."""
        with pytest.raises(RuntimeError):
            with memory_db.connection() as conn:
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (999, 'temp')"
                )
                raise RuntimeError("Simulated transaction failure!")

        with memory_db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT version FROM schema_version WHERE version = 999;")
            assert cursor.fetchone() is None

    def test_sql_injection_prevention(self, repository: ReviewRepository) -> None:
        """Verify SQL injection payloads in parameters do not execute or corrupt the database."""
        hostile_review_id = "'; DROP TABLE reviews; --"
        hostile_code_hash = "' OR '1'='1"

        # Searching with hostile hash
        results = repository.search_reviews(code_hash=hostile_code_hash)
        assert len(results) == 0

        # Deleting with hostile id
        deleted = repository.delete_review(hostile_review_id)
        assert deleted is False

        # Verify reviews table still exists and is healthy
        assert repository.count_reviews() == 0

    def test_engine_integration_with_save_enabled(
        self, repository: ReviewRepository
    ) -> None:
        """Verify AnalysisEngine automatically persists review when save=True."""
        engine = AnalysisEngine(repository=repository)
        req = AnalysisRequest(source_code="x = 10\n", filename="persist_test.py")

        res = engine.analyze(req, save=True)
        assert repository.count_reviews() == 1
        stored = repository.get_review_by_id(res.review_id)
        assert stored is not None
        assert stored.code_hash == res.code_hash

    def test_engine_integration_with_save_disabled(
        self, repository: ReviewRepository
    ) -> None:
        """Verify AnalysisEngine does NOT persist review when save=False (demo / privacy mode)."""
        engine = AnalysisEngine(repository=repository)
        req = AnalysisRequest(source_code="y = 20\n", filename="no_persist.py")

        res = engine.analyze(req, save=False)
        assert repository.count_reviews() == 0
        stored = repository.get_review_by_id(res.review_id)
        assert stored is None

    def test_engine_without_repository_does_not_crash(self) -> None:
        """Verify AnalysisEngine works seamlessly when no repository is configured."""
        engine = AnalysisEngine(repository=None)
        req = AnalysisRequest(source_code="z = 30\n", filename="standalone.py")
        res = engine.analyze(req, save=True)
        assert res.syntax.is_valid is True

    def test_unsupported_schema_version_fails_safely(self, temp_db_dir: str) -> None:
        """Verify connecting to an incompatible higher schema version raises RuntimeError."""
        db_file = os.path.join(temp_db_dir, "future_schema.db")
        db = DatabaseManager(db_path=db_file)
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (999, 'future')"
            )
        db.close()

        with pytest.raises(RuntimeError, match="Unsupported database schema version"):
            DatabaseManager(db_path=db_file)

    def test_engine_integration_demo_mode_blocks_persistence(
        self, repository: ReviewRepository
    ) -> None:
        """Verify AnalysisEngine in DEMO_MODE strictly prevents persisting review."""
        demo_settings = Settings(demo_mode=True)
        engine = AnalysisEngine(repository=repository, settings=demo_settings)
        req = AnalysisRequest(source_code="secret_code = 1\n", filename="demo.py")

        res = engine.analyze(req, save=True)
        assert res.syntax.is_valid is True
        assert repository.count_reviews() == 0
        assert repository.get_review_by_id(res.review_id) is None

    def test_storage_error_does_not_leak_source_code(
        self, repository: ReviewRepository, sample_analysis_result: AnalysisResult
    ) -> None:
        """Verify StorageError masks raw SQL driver details and never leaks source code."""
        with repository.db.connection() as conn:
            conn.execute("DROP TABLE reviews;")

        with pytest.raises(StorageError) as exc_info:
            repository.save_review(sample_analysis_result)

        err_msg = str(exc_info.value)
        assert sample_analysis_result.source_code not in err_msg
        assert "Failed to persist review record" in err_msg
