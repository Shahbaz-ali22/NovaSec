"""Async utility helpers — rate limiter, semaphore wrappers."""
from __future__ import annotations
import asyncio
from typing import Any, AsyncIterator


class AsyncRateLimiter:
    """Token-bucket rate limiter for async operations.

    Usage::
        limiter = AsyncRateLimiter(rate=10)  # 10 calls/sec
        async for item in items:
            await limiter.acquire()
            result = await fetch(item)
    """

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._min_interval = 1.0 / rate
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_call
            wait = self._min_interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = asyncio.get_event_loop().time()


async def gather_with_concurrency(
    n: int, *coros: Any
) -> list[Any]:
    """Run coroutines with at most *n* concurrently."""
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro: Any) -> Any:
        async with semaphore:
            return await coro

    return list(await asyncio.gather(*(sem_coro(c) for c in coros), return_exceptions=True))
