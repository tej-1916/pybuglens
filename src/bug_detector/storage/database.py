"""SQLite database connection management and schema migration."""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from bug_detector.core.config import get_settings

CURRENT_SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    review_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    filename TEXT NOT NULL,
    source_code TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    line_count INTEGER NOT NULL,
    char_count INTEGER NOT NULL,
    is_valid_syntax INTEGER NOT NULL,
    syntax_error_details TEXT,
    findings_json TEXT NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    ai_review_json TEXT,
    execution_duration_ms REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reviews_timestamp ON reviews (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_code_hash ON reviews (code_hash);
CREATE INDEX IF NOT EXISTS idx_reviews_filename ON reviews (filename);
"""


class DatabaseManager:
    """Manages SQLite database initialization, transactions, and connections."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize database manager.

        Args:
            db_path: Optional explicit file path or ':memory:'. If None, resolved from Settings.
        """
        if db_path is not None:
            self.raw_path = db_path
        else:
            settings = get_settings()
            self.raw_path = settings.database_url

        self.db_path = self._resolve_db_path(self.raw_path)
        self._is_memory = self.db_path == ":memory:"
        self._memory_conn: Optional[sqlite3.Connection] = None
        if self._is_memory:
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")

        self._ensure_directory_exists()
        self.init_db()

    @staticmethod
    def _resolve_db_path(raw_path: str) -> str:
        """Convert sqlite URL or raw path to a filesystem path or :memory:."""
        if raw_path == ":memory:":
            return ":memory:"
        if raw_path.startswith("sqlite:///"):
            return raw_path.replace("sqlite:///", "", 1)
        return raw_path

    def _ensure_directory_exists(self) -> None:
        """Create parent directory for the SQLite database if it does not exist."""
        if not self._is_memory:
            parent_dir = Path(self.db_path).parent
            if parent_dir and not parent_dir.exists():
                os.makedirs(parent_dir, exist_ok=True)

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a transactional SQLite connection.

        Automatically commits on successful block execution, rolls back on exception,
        and safely closes file-based connections upon completion.
        """
        if self._is_memory and self._memory_conn is not None:
            try:
                yield self._memory_conn
                self._memory_conn.commit()
            except Exception:
                self._memory_conn.rollback()
                raise
        else:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=20.0,
            )
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def close(self) -> None:
        """Close persistent connections when shutting down or completing tests."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None

    def init_db(self) -> None:
        """Initialize the database schema and record the migration version."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(version) FROM schema_version;")
            row = cursor.fetchone()
            current_version = row[0] if row else None

            if current_version is not None and current_version > CURRENT_SCHEMA_VERSION:
                raise RuntimeError(
                    f"Unsupported database schema version: {current_version}. "
                    f"Maximum supported schema version is {CURRENT_SCHEMA_VERSION}."
                )

            if current_version is None:
                cursor.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (
                        CURRENT_SCHEMA_VERSION,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
