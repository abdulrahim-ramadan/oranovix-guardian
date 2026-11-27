"""
Live Defense controller: owns the running monitor for the whole app.

Pages are rebuilt on every theme or language change, so the monitor
cannot live in a page. The controller holds it, remembers the monitored
root in ``settings.json``, and tells listeners about changes through a
``dispatch`` function. The GUI passes ``lambda fn: widget.after(0, fn)``,
so listeners always run on the Tk thread; the controller itself never
touches Tk.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from oranovix_guardian.core.alarm_center import AlarmCenter
from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.settings_file import SettingsFile

from .base import IntegrityEvent, Monitor, MonitorReport
from .baseline import Baseline, BaselineError, BaselineResult, KeyStore
from .file_integrity import FileIntegrityMonitor, FileScanner

Dispatch = Callable[[Callable[[], None]], object]


class LiveDefenseSettings:
    """The ``live_defense`` entry of ``settings.json``: root, interval, running."""

    KEY = "live_defense"
    DEFAULT_INTERVAL = 30

    def __init__(self, path: Optional[str] = None) -> None:
        self._file = SettingsFile(path)

    @staticmethod
    def default_path() -> Path:
        return AppPaths.settings_path()

    def load(self) -> Dict[str, object]:
        return self._file.section(self.KEY)

    def save(self, **values: object) -> bool:
        """Merge *values* into the entry; ``False`` (and reported) when not saved."""
        return self._file.update_section(self.KEY, **values)


@dataclass(frozen=True)
class LiveDefenseState:
    """Snapshot handed to listeners."""

    root: str
    running: bool
    interval: int
    baseline_exists: bool
    baseline_created_at: Optional[datetime]
    baseline_files: int
    baseline_ok: bool
    baseline_problem: str
    ignore_patterns: Tuple[str, ...]
    open_events: Tuple[IntegrityEvent, ...]
    new_events: Tuple[IntegrityEvent, ...] = ()
    last_check_at: Optional[datetime] = None
    last_error: str = ""


Listener = Callable[[LiveDefenseState], None]


class LiveDefenseController:
    """Starts, stops and talks to the file integrity monitor."""

    def __init__(
        self,
        dispatch: Dispatch,
        alarm_center: Optional[AlarmCenter] = None,
        settings: Optional[LiveDefenseSettings] = None,
        db_path: Optional[str] = None,
        key_store: Optional[KeyStore] = None,
        file_scanner: Optional[FileScanner] = None,
        read_state: Optional[Callable[[Callable[[], LiveDefenseState], Listener], None]] = None,
    ) -> None:
        self._dispatch = dispatch
        self._read_state = read_state
        self._alarm_center = alarm_center
        self._settings = settings or LiveDefenseSettings()
        self._db_path = db_path
        self._key_store = key_store
        self._file_scanner = file_scanner
        self._listeners: List[Listener] = []
        self._monitor: Optional[FileIntegrityMonitor] = None
        self._last_report: Optional[MonitorReport] = None
        saved = self._settings.load()
        self._root = str(saved.get("root") or "")
        self._interval = self._valid_interval(saved.get("interval"))

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def root(self) -> str:
        return self._root

    @property
    def interval(self) -> int:
        return self._interval

    @property
    def is_running(self) -> bool:
        return self._monitor is not None and self._monitor.is_running

    def baseline(self) -> Optional[Baseline]:
        if not self._root:
            return None
        return Baseline(self._root, self._db_path, self._key_store)

    def state(self, new_events: Sequence[IntegrityEvent] = ()) -> LiveDefenseState:
        baseline = self.baseline()
        exists = baseline is not None and baseline.exists()
        verified = baseline.verify() if baseline is not None and exists else None
        report = self._last_report
        return LiveDefenseState(
            root=self._root,
            running=self.is_running,
            interval=self._interval,
            baseline_exists=exists,
            baseline_created_at=baseline.created_at() if baseline is not None and exists else None,
            baseline_files=len(baseline.entries()) if baseline is not None and exists else 0,
            baseline_ok=bool(verified and verified.ok),
            baseline_problem=verified.detail if verified is not None and not verified.ok else "",
            ignore_patterns=baseline.ignore_patterns() if baseline is not None and exists else (),
            open_events=tuple(self._monitor.open_events()) if self._monitor else (),
            new_events=tuple(new_events),
            last_check_at=report.finished_at if report else None,
            last_error=report.error if report else "",
        )

    def open_events(self) -> List[IntegrityEvent]:
        """Open events of the running monitor; safe to call from any thread."""
        monitor = self._monitor
        return monitor.open_events() if monitor is not None and monitor.is_running else []

    def resume_candidate(self) -> str:
        """The root to offer for resuming, or ``""``: it was running when the app closed."""
        saved = self._settings.load()
        root = str(saved.get("root") or "")
        if not saved.get("running") or not root or not os.path.isdir(root):
            return ""
        baseline = Baseline(root, self._db_path, self._key_store)
        return root if baseline.exists() else ""

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listener(self, listener: Listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def notify(self, new_events: Sequence[IntegrityEvent] = ()) -> None:
        """Send the current state to every listener (on the dispatch thread)."""
        if self._read_state is None:
            self._deliver(self.state(new_events))
        else:
            self._read_state(lambda: self.state(new_events), self._deliver)

    def _deliver(self, snapshot: LiveDefenseState) -> None:
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                self.remove_listener(listener)      # e.g. a destroyed page

    # ------------------------------------------------------------------
    # Actions (may block: the GUI runs them in a worker thread)
    # ------------------------------------------------------------------

    def set_root(self, root: str) -> None:
        root = os.path.abspath(root) if root else ""
        if root != self._root:
            self.stop()
            self._root = root
            self._settings.save(root=root, running=False)

    def set_interval(self, seconds: int) -> None:
        self._interval = self._valid_interval(seconds)
        if self._monitor is not None:
            self._monitor.interval = self._interval
        self._settings.save(interval=self._interval)

    def create_baseline(self, ignore_patterns: Optional[Sequence[str]] = None) -> BaselineResult:
        baseline = self.baseline()
        if baseline is None:
            raise BaselineError("Choose a folder first.")
        was_running = self.is_running
        self.stop(remember=False)
        result = baseline.create(ignore_patterns)
        if was_running:
            self.start()
        return result

    def start(self) -> None:
        baseline = self.baseline()
        if baseline is None:
            raise BaselineError("Choose a folder first.")
        if not baseline.exists():
            raise BaselineError("Create a baseline before starting.")
        if self.is_running:
            return
        self._monitor = FileIntegrityMonitor(
            baseline,
            interval_seconds=self._interval,
            alarm_center=self._alarm_center,
            on_report=self._on_report,
            file_scanner=self._file_scanner,
        )
        self._last_report = None
        self._monitor.start()
        self._settings.save(root=self._root, running=True, interval=self._interval)

    def stop(self, remember: bool = True) -> None:
        """Stop the monitor. With *remember* the saved state says "not running"."""
        if self._monitor is not None:
            self._monitor.stop()
        if remember:
            self._settings.save(running=False)

    def shutdown(self, timeout: Optional[float] = 2) -> None:
        """App closes: stop the thread but keep "running" so it can be resumed."""
        if self._monitor is not None:
            self._monitor.stop(timeout=timeout)

    def accept(self, event_ids: Sequence[str]) -> int:
        return self._require_monitor().accept(event_ids)

    def accept_all(self) -> int:
        return self._require_monitor().accept_all()

    def set_ignore_patterns(self, patterns: Sequence[str]) -> Tuple[str, ...]:
        if self._monitor is not None:
            return self._monitor.set_ignore_patterns(patterns)
        baseline = self.baseline()
        if baseline is None or not baseline.exists():
            raise BaselineError("Create a baseline first.")
        return baseline.set_ignore_patterns(patterns)

    def check_now(self) -> List[IntegrityEvent]:
        """One cycle in the caller's thread (used by tests and "Scan now")."""
        events = self._require_monitor().check()
        self._last_report = MonitorReport(tuple(events), tuple(self._require_monitor().open_events()))
        return events

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _on_report(self, report: MonitorReport) -> None:
        # Called in the monitor thread: hand over to the dispatch thread.
        self._last_report = report
        self._dispatch(lambda: self.notify(report.new_events))

    def _require_monitor(self) -> FileIntegrityMonitor:
        if self._monitor is None:
            raise BaselineError("Start monitoring first.")
        return self._monitor

    @staticmethod
    def _valid_interval(value: object) -> int:
        try:
            seconds = int(str(value))
        except (TypeError, ValueError):
            return LiveDefenseSettings.DEFAULT_INTERVAL
        return max(seconds, int(Monitor.MIN_INTERVAL_SECONDS))
