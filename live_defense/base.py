"""
Base of every Live Defense monitor.

A monitor runs ``check()`` in a background thread every few seconds. It
never touches Tk: results go to an ``on_report`` callback, which the GUI
wraps with ``widget.after`` so they arrive on the Tk thread. Alarms go to
the shared ``AlarmCenter`` with ``full_scan=False``, because a monitor only
ever sees part of a project.
"""
from __future__ import annotations

import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, List, Optional, Sequence, Tuple

from core.alarm_center import Alarm, AlarmCenter
from scanner_engine.base import Issue, Severity
from scanner_engine.categories import IssueCategory


class ChangeType(str, Enum):
    NEW = "NEW"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    TAMPERED = "TAMPERED"       # the baseline itself was changed outside the app

    @property
    def rule_id(self) -> str:
        return {
            ChangeType.NEW: "FIM001",
            ChangeType.MODIFIED: "FIM002",
            ChangeType.DELETED: "FIM003",
            ChangeType.TAMPERED: "FIM004",
        }[self]

    @property
    def label(self) -> str:
        return {
            ChangeType.NEW: "New file",
            ChangeType.MODIFIED: "Modified file",
            ChangeType.DELETED: "Deleted file",
            ChangeType.TAMPERED: "Baseline tampered",
        }[self]


@dataclass
class IntegrityEvent:
    """One change of the monitored folder compared with the baseline."""

    change: ChangeType
    severity: Severity
    root: str
    relative_path: str              # posix style, relative to root; "" for TAMPERED
    reasons: Tuple[str, ...]
    old_sha256: str = ""            # baseline hash; "" for a new file
    new_sha256: str = ""            # current hash; "" for a deleted file
    line_number: int = 0            # line of a web shell signature, if any
    detected_at: datetime = field(default_factory=datetime.now)
    findings: List[Issue] = field(default_factory=list)   # from the code scan

    @property
    def event_id(self) -> str:
        """Same id for the same change to the same content."""
        return f"{self.change.value}|{self.relative_path}|{self.old_sha256}|{self.new_sha256}"

    @property
    def path(self) -> str:
        if not self.relative_path:
            return self.root
        return os.path.join(self.root, *self.relative_path.split("/"))

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons)

    @property
    def can_accept(self) -> bool:
        return self.change is not ChangeType.TAMPERED

    @property
    def state_key(self) -> str:
        """Ties alarm ids to this exact state: the baseline and the new hash."""
        return f"{self.change.value}|{self.old_sha256}|{self.new_sha256}"

    def to_issue(self) -> Issue:
        """The event as an ``Issue``, so ``AlarmCenter`` can announce it."""
        title = f"{self.change.label}: {self.reasons[0]}" if self.reasons else self.change.label
        return Issue(
            rule_id=self.change.rule_id,
            title=title,
            description=self.reason,
            severity=self.severity,
            file_path=self.path,
            line_number=self.line_number,
            recommendation=(
                "Check who changed the file. Accept the change if it is expected, "
                "otherwise restore the file and investigate."
            ),
            confidence="HIGH",
            category=IssueCategory.INTEGRITY,
            finding_key=self.state_key,
        )

    def alarm_issues(self) -> List[Issue]:
        """The event plus its code-scan findings, each tied to this state."""
        issues = [self.to_issue()]
        for finding in self.findings:
            finding.finding_key = "|".join(
                part for part in (finding.finding_key, self.state_key) if part
            )
            issues.append(finding)
        return issues


@dataclass(frozen=True)
class MonitorReport:
    """What one cycle of a monitor delivers to its listener."""

    new_events: Tuple[IntegrityEvent, ...]
    open_events: Tuple[IntegrityEvent, ...]
    error: str = ""
    finished_at: datetime = field(default_factory=datetime.now)


ReportListener = Callable[[MonitorReport], None]


class Monitor(ABC):
    """Runs ``check()`` in a background thread until ``stop()``."""

    MIN_INTERVAL_SECONDS = 5

    def __init__(
        self,
        root: str,
        interval_seconds: float = 30,
        alarm_center: Optional[AlarmCenter] = None,
        on_report: Optional[ReportListener] = None,
    ) -> None:
        self._root = os.path.abspath(root)
        self._interval = max(float(interval_seconds), self.MIN_INTERVAL_SECONDS)
        self._alarm_center = alarm_center
        self._on_report = on_report
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def root(self) -> str:
        return self._root

    @property
    def interval(self) -> float:
        return self._interval

    @interval.setter
    def interval(self, seconds: float) -> None:
        self._interval = max(float(seconds), self.MIN_INTERVAL_SECONDS)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @abstractmethod
    def check(self) -> List[IntegrityEvent]:
        """Run one cycle and return the events that are new since the last one."""

    def open_events(self) -> List[IntegrityEvent]:
        """Events that are still unresolved. Monitors without state return none."""
        return []

    def first_check(self) -> List[IntegrityEvent]:
        """The cycle run right after ``start()``. Subclasses may make it thorough."""
        return self.check()

    # ------------------------------------------------------------------
    # Thread
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self.is_running:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"{type(self).__name__}", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> bool:
        """Ask the thread to end and wait for it. Returns ``True`` when it ended."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        ended = thread is None or not thread.is_alive()
        if ended:
            self._thread = None
        return ended

    def _run(self) -> None:
        cycle: Callable[[], List[IntegrityEvent]] = self.first_check
        while not self._stop.is_set():
            try:
                events = cycle()
                self._deliver(MonitorReport(tuple(events), tuple(self.open_events())))
            except Exception as exc:
                self._deliver(MonitorReport(
                    (), tuple(self.open_events()), error=f"{type(exc).__name__}: {exc}"
                ))
            cycle = self.check
            if self._stop.wait(self._interval):
                break

    def _deliver(self, report: MonitorReport) -> None:
        if self._on_report is not None:
            try:
                self._on_report(report)
            except Exception:
                pass    # a broken listener must not end the monitor

    # ------------------------------------------------------------------
    # Alarm
    # ------------------------------------------------------------------

    def raise_alarms(self, events: Sequence[IntegrityEvent]) -> Optional[Alarm]:
        """Hand the events and their findings to the alarm center (partial view)."""
        if self._alarm_center is None or not events:
            return None
        issues = [issue for event in events for issue in event.alarm_issues()]
        return self._alarm_center.notify(issues, self._root, full_scan=False)
