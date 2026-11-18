"""Rate + concurrency limiting.

Two independent controls, both important against a live test network:

  * a token-bucket rate limiter (requests/second with a burst allowance), so the
    agent never hammers an endpoint or a scanner API, and
  * a concurrency cap (max simultaneous host operations), enforced via an async
    semaphore in the collector fan-out.

Both the sync `acquire()` and async `aacquire()` paths share one bucket.
"""
from __future__ import annotations

import asyncio
import threading
import time


class RateLimitExceeded(Exception):
    """Raised by try_acquire() when no token is available and blocking is off."""


class RateLimiter:
    def __init__(self, rate_per_sec: float = 5.0, burst: int | None = None):
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self.rate = float(rate_per_sec)
        self.capacity = float(burst if burst is not None else max(1, int(rate_per_sec)))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def try_acquire(self, cost: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    def acquire(self, cost: float = 1.0, timeout: float | None = None) -> None:
        """Block until a token is available (or raise RateLimitExceeded on timeout)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self.try_acquire(cost):
                return
            if deadline is not None and time.monotonic() >= deadline:
                raise RateLimitExceeded("rate limit timeout")
            time.sleep(self._sleep_for(cost, deadline))

    async def aacquire(self, cost: float = 1.0, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self.try_acquire(cost):
                return
            if deadline is not None and time.monotonic() >= deadline:
                raise RateLimitExceeded("rate limit timeout")
            await asyncio.sleep(self._sleep_for(cost, deadline))

    def _sleep_for(self, cost: float, deadline: float | None) -> float:
        wait = self._wait_time(cost)
        if deadline is not None:
            # Never sleep past the deadline, so the next loop can time out.
            remaining = deadline - time.monotonic()
            wait = min(wait, max(0.0, remaining))
        return wait

    def _wait_time(self, cost: float) -> float:
        with self._lock:
            self._refill()
            missing = max(0.0, cost - self._tokens)
            return max(0.01, missing / self.rate)

    @property
    def tokens(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens
