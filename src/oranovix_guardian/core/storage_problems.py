"""
Write failures the user has to see.

A store that cannot write (a full disk, a folder without write access)
reports it here instead of swallowing the error. Each file is reported
once per run. The GUI registers a listener when its window exists;
problems reported before that are kept and handed over then.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, List, Optional, Set


@dataclass(frozen=True)
class StorageProblem:
    what: str           # e.g. "settings", "scan history"
    path: str
    reason: str


Listener = Callable[[StorageProblem], object]


class StorageProblems:
    """Process-wide collector of failed writes."""

    _lock = threading.Lock()
    _reported: Set[str] = set()
    _pending: List[StorageProblem] = []
    _listener: Optional[Listener] = None

    @classmethod
    def report(cls, what: str, path: object, error: BaseException) -> None:
        reason = getattr(error, "strerror", None) or str(error) or type(error).__name__
        problem = StorageProblem(what, str(path), str(reason))
        with cls._lock:
            key = problem.path.lower()
            if key in cls._reported:
                return
            cls._reported.add(key)
            listener = cls._listener
            if listener is None:
                cls._pending.append(problem)
                return
        cls._deliver(listener, problem)

    @classmethod
    def set_listener(cls, listener: Optional[Listener]) -> None:
        """Register the GUI's listener; problems reported so far are delivered now."""
        with cls._lock:
            cls._listener = listener
            pending, cls._pending = (cls._pending, []) if listener is not None else ([], cls._pending)
        for problem in pending:
            cls._deliver(listener, problem)

    @staticmethod
    def _deliver(listener: Optional[Listener], problem: StorageProblem) -> None:
        if listener is None:
            return
        try:
            listener(problem)
        except Exception:
            pass
