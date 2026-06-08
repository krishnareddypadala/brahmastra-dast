"""
Adaptive concurrency controller — AIMD (additive increase, multiplicative decrease)
based on observed response latency. Inspired by TCP congestion control and Netflix's
concurrency-limits library.

Usage:
    sem = AdaptiveSemaphore(mode="adaptive", initial=20, min_limit=4, max_limit=100)
    async with sem:
        ... do http request ...
    # latency is auto-recorded; controller resizes itself every N samples
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Deque


# Named presets for the concurrency_mode field on ScanConfig / ScanRequest.
# 'adaptive' is the default — auto-tunes based on observed p95 latency.
# 'fixed' disables AIMD entirely and uses max_concurrency literally.
MODE_PRESETS: dict[str, dict] = {
    "polite": {
        "initial": 5,
        "min": 2,
        "max": 15,
        "fast_ms": 800,
        "slow_ms": 3000,
    },
    "balanced": {
        "initial": 20,
        "min": 4,
        "max": 50,
        "fast_ms": 500,
        "slow_ms": 2000,
    },
    "aggressive": {
        "initial": 50,
        "min": 10,
        "max": 150,
        "fast_ms": 300,
        "slow_ms": 1500,
    },
    "adaptive": {
        "initial": 20,
        "min": 4,
        "max": 100,
        "fast_ms": 400,
        "slow_ms": 1500,
    },
    "fixed": {
        "initial": 20,
        "min": 20,
        "max": 20,
        "fast_ms": 0,
        "slow_ms": 0,
    },
}


class AdaptiveSemaphore:
    """
    Semaphore whose 'size' grows when responses are fast and shrinks when they slow.

    Tracks a rolling window of recent latencies; recalculates the limit every 10
    samples using AIMD:
        p95 < fast_ms  → limit += 4   (additive increase)
        p95 > slow_ms  → limit //= 2  (multiplicative decrease)
        otherwise      → hold steady

    Min/max are hard floors and ceilings — the controller never crosses them.
    Use the async-context-manager interface to get automatic latency timing:

        async with sem:
            await client.get(url)
    """

    def __init__(
        self,
        mode: str = "adaptive",
        initial: int = 20,
        min_limit: int = 4,
        max_limit: int = 100,
        fast_ms: float = 400,
        slow_ms: float = 1500,
        window: int = 50,
    ):
        self.mode = mode
        self.min_limit = max(1, int(min_limit))
        self.max_limit = max(self.min_limit, int(max_limit))
        self.fast_ms = float(fast_ms)
        self.slow_ms = float(slow_ms)
        self.window = int(window)

        self.limit = max(self.min_limit, min(int(initial), self.max_limit))
        self._inflight = 0
        self._cond = asyncio.Condition()
        self._latencies: Deque[float] = deque(maxlen=self.window)
        self._sample_count = 0
        self._last_p95: float = 0.0
        self._resizes = 0

    @property
    def inflight(self) -> int:
        return self._inflight

    @property
    def p95_ms(self) -> float:
        return self._last_p95

    async def acquire(self) -> None:
        async with self._cond:
            while self._inflight >= self.limit:
                await self._cond.wait()
            self._inflight += 1

    async def release(self, latency_ms: float) -> None:
        async with self._cond:
            self._inflight -= 1
            self._latencies.append(float(latency_ms))
            self._sample_count += 1
            if self._sample_count >= 10 and self.mode != "fixed":
                self._sample_count = 0
                self._recalc()
            self._cond.notify_all()

    def _recalc(self) -> None:
        if not self._latencies:
            return
        sorted_ms = sorted(self._latencies)
        idx = min(len(sorted_ms) - 1, int(len(sorted_ms) * 0.95))
        p95 = sorted_ms[idx]
        self._last_p95 = p95

        old_limit = self.limit
        if p95 < self.fast_ms:
            self.limit = min(self.limit + 4, self.max_limit)
        elif p95 > self.slow_ms:
            self.limit = max(self.limit // 2, self.min_limit)
        # else: hold

        if self.limit != old_limit:
            self._resizes += 1

    async def __aenter__(self) -> "AdaptiveSemaphore":
        await self.acquire()
        self._t0 = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        elapsed_ms = (time.perf_counter() - self._t0) * 1000.0
        await self.release(elapsed_ms)

    def snapshot(self) -> dict:
        """Telemetry snapshot for SSE / dashboard display."""
        return {
            "mode": self.mode,
            "limit": self.limit,
            "inflight": self._inflight,
            "min": self.min_limit,
            "max": self.max_limit,
            "p95_ms": round(self._last_p95, 1),
            "samples": len(self._latencies),
            "resizes": self._resizes,
        }


def make_semaphore(mode: str, max_concurrency: int) -> AdaptiveSemaphore:
    """
    Build an AdaptiveSemaphore from a named preset, capping at max_concurrency.

    `max_concurrency` is treated as a hard ceiling for adaptive modes and as
    the literal limit for `fixed` mode.
    """
    preset = MODE_PRESETS.get(mode, MODE_PRESETS["adaptive"])
    if mode == "fixed":
        return AdaptiveSemaphore(
            mode="fixed",
            initial=max_concurrency,
            min_limit=max_concurrency,
            max_limit=max_concurrency,
            fast_ms=0,
            slow_ms=0,
        )
    return AdaptiveSemaphore(
        mode="adaptive",
        initial=min(preset["initial"], max_concurrency),
        min_limit=min(preset["min"], max_concurrency),
        max_limit=min(preset["max"], max_concurrency),
        fast_ms=preset["fast_ms"],
        slow_ms=preset["slow_ms"],
    )
