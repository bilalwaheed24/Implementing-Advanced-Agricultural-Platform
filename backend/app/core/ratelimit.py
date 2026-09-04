"""Token-bucket rate limiting per identity and per IP (Security.md T-19).

ponytail: in-process buckets, correct for a single node. Swap the store for Redis
when more than one API instance runs — the algorithm does not change.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    def __init__(self, capacity: int, refill_per_minute: int) -> None:
        self.capacity = float(capacity)
        self.rate = refill_per_minute / 60.0
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > 50_000:
                cutoff = now - 3600
                self._buckets = {k: b for k, b in self._buckets.items() if b.updated > cutoff}
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[key] = bucket
            elapsed = now - bucket.updated
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate)
            bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            deficit = cost - bucket.tokens
            return False, round(deficit / self.rate, 2) if self.rate else 60.0

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
