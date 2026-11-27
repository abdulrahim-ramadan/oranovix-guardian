"""Background application service for a single code scan."""
from __future__ import annotations

from concurrent.futures import Executor
from queue import Empty, SimpleQueue
from threading import Event
from typing import Iterator

from oranovix_guardian.scanner_engine.base import ScanResult
from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator, ScanProgress


class ScanJob:
    """Own one scan's worker, progress channel and cancellation request."""

    def __init__(self, executor: Executor, target: str) -> None:
        self._progress: SimpleQueue[ScanProgress] = SimpleQueue()
        self._stop = Event()
        self._future = executor.submit(
            ScanOrchestrator(on_progress=self._progress.put).scan, target, cancel=self._stop,
        )

    @property
    def cancelling(self) -> bool:
        return self._stop.is_set()

    def cancel(self) -> None:
        self._stop.set()

    def updates(self, limit: int) -> Iterator[ScanProgress]:
        for _ in range(limit):
            try:
                yield self._progress.get_nowait()
            except Empty:
                return

    @property
    def ready(self) -> bool:
        # Once the worker is done the queue cannot receive any more updates.
        return self._future.done() and self._progress.empty()

    def result(self) -> ScanResult:
        return self._future.result()
