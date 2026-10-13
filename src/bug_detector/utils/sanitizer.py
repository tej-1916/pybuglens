"""Input validation and sanitization for user-submitted code."""

import hashlib
from typing import Optional

from pydantic import BaseModel, Field

from bug_detector.core.config import get_settings


class SanitizedInput(BaseModel):
    """Container for validated, sanitized source code and metadata."""

    code: str = Field(description="Normalized source code")
    sha256: str = Field(description="SHA-256 hexadecimal digest of normalized code")
    line_count: int = Field(ge=0, description="Total line count")
    char_count: int = Field(ge=0, description="Total character count")
    byte_size: int = Field(ge=0, description="Size in bytes (UTF-8 encoded)")


class CodeSanitizer:
    """Sanitizer and validator for source code inputs."""

    def __init__(
        self,
        max_bytes: Optional[int] = None,
        max_lines: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.max_bytes = max_bytes if max_bytes is not None else settings.max_code_size_bytes
        self.max_lines = max_lines if max_lines is not None else settings.max_code_lines

    def sanitize(self, raw_code: str) -> SanitizedInput:
        """Sanitize and validate raw user-submitted Python code.

        Raises:
            ValueError: If code is empty, exceeds byte limit, or exceeds line limit.
        """
        if raw_code is None or not isinstance(raw_code, str):
            raise ValueError("Source code must be a non-null string.")

        # Check for empty or whitespace-only code
        trimmed = raw_code.strip()
        if not trimmed:
            raise ValueError("Source code cannot be empty.")

        # Normalize line endings: CRLF/CR -> LF
        normalized = raw_code.replace("\r\n", "\n").replace("\r", "\n")

        # Strip null bytes (defense against null byte injection / C-string truncations)
        if "\x00" in normalized:
            normalized = normalized.replace("\x00", "")

        # Check byte size
        encoded = normalized.encode("utf-8")
        byte_size = len(encoded)
        if byte_size > self.max_bytes:
            raise ValueError(
                f"Source code size ({byte_size} bytes) exceeds maximum limit "
                f"of {self.max_bytes} bytes ({self.max_bytes // 1024} KB)."
            )

        # Check line count
        lines = normalized.splitlines()
        line_count = len(lines) if lines else 1
        if line_count > self.max_lines:
            raise ValueError(
                f"Source code line count ({line_count} lines) exceeds maximum limit "
                f"of {self.max_lines} lines."
            )

        # Compute SHA-256 digest
        sha256_hash = hashlib.sha256(encoded).hexdigest()

        return SanitizedInput(
            code=normalized,
            sha256=sha256_hash,
            line_count=line_count,
            char_count=len(normalized),
            byte_size=byte_size,
        )
