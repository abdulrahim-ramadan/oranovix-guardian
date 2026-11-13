"""
File integrity monitor: finds planted, changed and deleted files.

Every cycle compares the folder with the signed baseline. The quick pass
re-hashes only files whose size or mtime changed; every tenth cycle (and
the first one after ``start()``) re-hashes everything, which catches a
file whose content changed while its size and mtime were put back.
"""
from __future__ import annotations

import hashlib
import os
import threading
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from core.alarm_center import AlarmCenter
from scanner_engine.base import Issue, Severity

from .base import ChangeType, IntegrityEvent, Monitor, ReportListener
from .baseline import TAMPER_REASON, UNREADABLE, Baseline, FileState, FileTree, StatInfo
from .classifier import ChangeClassifier
from .webshell import SignatureHit, WebShellDetector

FileScanner = Callable[[str], List[Issue]]

__all__ = ["ChangeClassifier", "FileIntegrityMonitor", "OrchestratorFileScanner"]


class OrchestratorFileScanner:
    """Runs the full scan engine on one file."""

    def __call__(self, path: str) -> List[Issue]:
        from scanner_engine.orchestrator import ScanOrchestrator

        if not ScanOrchestrator.scannable_files(path):
            return []
        try:
            return list(ScanOrchestrator().scan(path).issues)
        except Exception:
            return []


class FileIntegrityMonitor(Monitor):
    """Compares a folder with its baseline every ``interval`` seconds."""

    FULL_EVERY = 10
    MAX_EVENTS_PER_FILE = 20

    def __init__(
        self,
        baseline: Baseline,
        interval_seconds: float = 30,
        alarm_center: Optional[AlarmCenter] = None,
        on_report: Optional[ReportListener] = None,
        file_scanner: Optional[FileScanner] = None,
        full_every: int = FULL_EVERY,
    ) -> None:
        super().__init__(baseline.root, interval_seconds, alarm_center, on_report)
        self._baseline = baseline
        self._scan_file: FileScanner = file_scanner or OrchestratorFileScanner()
        self._full_every = max(int(full_every), 1)
        self._classifier = ChangeClassifier()
        self._root_name = os.path.basename(baseline.root)
        self._lock = threading.RLock()
        self._cycle = 0
        self._observed: Dict[str, FileState] = dict(baseline.entries())
        self._open: Dict[str, IntegrityEvent] = {}
        self.last_pass_was_full = False

    @property
    def baseline(self) -> Baseline:
        return self._baseline

    def open_events(self) -> List[IntegrityEvent]:
        with self._lock:
            return sorted(
                self._open.values(),
                key=lambda e: (-e.severity.weight, -e.detected_at.timestamp(), e.relative_path),
            )

    def first_check(self) -> List[IntegrityEvent]:
        return self.check(full=True)

    def check(self, full: Optional[bool] = None) -> List[IntegrityEvent]:
        with self._lock:
            self._cycle += 1
            if full is None:
                full = self._cycle % self._full_every == 0
            self.last_pass_was_full = full

            verified = self._baseline.verify()
            if not verified.ok:
                events = self._tampered(verified.detail)
            else:
                self._open.pop("", None)
                events = self._compare(full)
            self.raise_alarms(events)
            return events

    # ------------------------------------------------------------------
    # Accepting changes
    # ------------------------------------------------------------------

    def accept(self, event_ids: Sequence[str]) -> int:
        """Take the current state of the events' files into the baseline.

        Every open event of those files is closed, so a later change shows
        up as a new event with a new alarm. Returns the number of files.
        Raises ``BaselineError`` when the baseline is not trusted.
        """
        with self._lock:
            paths = {
                event.relative_path
                for event in self._open.values()
                if event.event_id in set(event_ids) and event.can_accept
            }
            return self._accept_paths(paths)

    def accept_all(self) -> int:
        with self._lock:
            return self._accept_paths(
                {event.relative_path for event in self._open.values() if event.can_accept}
            )

    def set_ignore_patterns(self, patterns: Sequence[str]) -> Tuple[str, ...]:
        """Change the ignore patterns; events of files now ignored are closed."""
        with self._lock:
            cleaned = self._baseline.set_ignore_patterns(patterns)
            visible = set(self._baseline.tree().walk()) | set(self._baseline.entries())
            for event_id, event in list(self._open.items()):
                if event.can_accept and event.relative_path not in visible:
                    del self._open[event_id]
            return cleaned

    def _accept_paths(self, paths: set) -> int:
        if not paths:
            return 0
        tree = self._baseline.tree()
        present = tree.walk()
        changes: Dict[str, Optional[FileState]] = {}
        for relative in paths:
            info = present.get(relative)
            changes[relative] = None if info is None else tree.state(relative, info)
        self._baseline.apply(changes)
        for relative, state in changes.items():
            if state is None:
                self._observed.pop(relative, None)
            else:
                self._observed[relative] = state
        for event_id, event in list(self._open.items()):
            if event.relative_path in paths and event.can_accept:
                del self._open[event_id]
        return len(paths)

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def _compare(self, full: bool) -> List[IntegrityEvent]:
        tree = self._baseline.tree()
        known = self._baseline.entries()
        walked = tree.walk()
        current = self._current_states(tree, walked, full)

        changes: List[Tuple[ChangeType, str, str, str]] = []
        for relative, state in current.items():
            before = known.get(relative)
            if before is None:
                changes.append((ChangeType.NEW, relative, "", state.sha256))
            elif before.sha256 != state.sha256:
                changes.append((ChangeType.MODIFIED, relative, before.sha256, state.sha256))
        for relative, before in known.items():
            if relative not in current:
                changes.append((ChangeType.DELETED, relative, before.sha256, ""))

        events: List[IntegrityEvent] = []
        for change, relative, old, new in sorted(changes, key=lambda c: c[1]):
            event_id = f"{change.value}|{relative}|{old}|{new}"
            if event_id in self._open:
                continue
            event = self._event(tree, change, relative, old, new, walked.get(relative))
            self._remember(event)
            events.append(event)
        return events

    def _current_states(
        self, tree: FileTree, walked: Dict[str, StatInfo], full: bool
    ) -> Dict[str, FileState]:
        states: Dict[str, FileState] = {}
        for relative, info in walked.items():
            cached = self._observed.get(relative)
            if (
                not full and cached is not None
                and cached.size == info.size and cached.mtime_ns == info.mtime_ns
            ):
                states[relative] = cached
                continue
            sha = tree.hash(relative, info.is_link)
            if sha == UNREADABLE and cached is not None:
                sha = cached.sha256         # locked right now: judge it next cycle
            states[relative] = FileState(info.size, info.mtime_ns, sha)
        self._observed = states
        return states

    def _event(
        self, tree: FileTree, change: ChangeType, relative: str, old: str, new: str,
        info: Optional[StatInfo] = None,
    ) -> IntegrityEvent:
        path = tree.absolute(relative)
        hits: List[SignatureHit] = []
        findings: List[Issue] = []
        link = tree.link_info(relative) if info is not None and info.is_link else None
        # A link's content belongs to its target, which may lie outside the root.
        too_large = False
        if change is not ChangeType.DELETED and link is None:
            hits = WebShellDetector.scan_file(path)
            findings = self._scan_file(path)
            too_large = info is not None and WebShellDetector.too_large(info.size)
        severity, reasons = self._classifier.classify(
            change, relative, hits, findings,
            root_name=self._root_name, link=link, too_large=too_large,
        )
        if new == UNREADABLE:
            # Often an antivirus that locked or removed the file: worth knowing.
            reasons = (*reasons, "Content could not be read (locked, or removed by an antivirus?)")
        return IntegrityEvent(
            change=change, severity=severity, root=self.root, relative_path=relative,
            reasons=reasons, old_sha256=old, new_sha256=new,
            line_number=hits[0].line if hits else 0, findings=findings,
        )

    def _remember(self, event: IntegrityEvent) -> None:
        self._open[event.event_id] = event
        same_file = [e for e in self._open.values() if e.relative_path == event.relative_path]
        for stale in sorted(same_file, key=lambda e: e.detected_at)[: -self.MAX_EVENTS_PER_FILE]:
            self._open.pop(stale.event_id, None)

    def _tampered(self, detail: str) -> List[IntegrityEvent]:
        state = hashlib.sha256(f"{self._baseline.signature()}|{detail}".encode("utf-8")).hexdigest()
        current = self._open.get("")
        if current is not None and current.new_sha256 == state:
            return []
        event = IntegrityEvent(
            change=ChangeType.TAMPERED, severity=Severity.CRITICAL, root=self.root,
            relative_path="", reasons=(TAMPER_REASON, detail), new_sha256=state,
        )
        self._open[""] = event
        return [event]
