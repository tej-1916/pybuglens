"""In-memory thread-safe rate limiter for API endpoints."""

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List


class RateLimiter:
    """Sliding-window in-memory rate limiter per client IP address."""

    def __init__(self) -> None:
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(
        self,
        client_ip: str,
        max_requests: int,
        window_seconds: float = 60.0,
    ) -> bool:
        """Check if client_ip has exceeded max_requests in window_seconds.

        Returns True if allowed, False if limit exceeded.
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests[client_ip]
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            if len(valid_timestamps) >= max_requests:
                self._requests[client_ip] = valid_timestamps
                return False

            valid_timestamps.append(now)
            self._requests[client_ip] = valid_timestamps
            return True

    def reset(self) -> None:
        """Clear all tracked request timestamps (useful for testing)."""
        with self._lock:
            self._requests.clear()


global_rate_limiter = RateLimiter()
