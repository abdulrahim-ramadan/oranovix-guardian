"""
File integrity monitor: finds planted, changed and deleted files.

Every cycle compares the folder with the signed baseline. The quick pass
re-hashes only files whose size or mtime changed; every tenth cycle (and
the first one after ``start()``) re-hashes everything, which catches a
file whose content changed while its size and mtime were put back.
"""
from __future__ import annotations

import hashlib
import threading
from pathlib import PurePosixPath
from typing import Callable, ClassVar, Dict, FrozenSet, List, Optional, Sequence, Tuple

from core.alarm_center import AlarmCenter
from scanner_engine.base import Issue, Severity

from .base import ChangeType, IntegrityEvent, Monitor, ReportListener
from .baseline import TAMPER_REASON, UNREADABLE, Baseline, FileState, FileTree
from .webshell import SignatureHit, WebShellDetector

FileScanner = Callable[[str], List[Issue]]


class ChangeClassifier:
    """Severity and reasons of one change."""

    EXECUTABLE: ClassVar[FrozenSet[str]] = frozenset({
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phps", ".phar",
        ".inc", ".asp", ".aspx", ".ashx", ".asmx", ".cshtml", ".jsp", ".jspx", ".jspf", ".cfm",
        ".cgi", ".pl", ".py", ".js", ".sh", ".bat", ".ps1", ".exe", ".dll",
    })
    CODE: ClassVar[FrozenSet[str]] = EXECUTABLE | frozenset({
        ".ts", ".tsx", ".jsx", ".mjs", ".java", ".cs", ".html", ".htm", ".rb", ".go",
        ".pl", ".cgi", ".asp", ".jspx", ".ps1", ".bat", ".cmd", ".vbs",
    })
    PUBLIC_DIRS: ClassVar[FrozenSet[str]] = frozenset({
        "upload", "uploads", "media", "static", "public", "tmp", "temp",
    })
    # Extensions an upload filter usually lets through.
    HARMLESS_LOOKING: ClassVar[FrozenSet[str]] = frozenset({
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg", ".tif", ".tiff",
        ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip", ".mp3", ".mp4",
    })
    SENSITIVE_NAMES: ClassVar[FrozenSet[str]] = frozenset({
        "settings.py", "wsgi.py", "asgi.py", "urls.py", ".htaccess", ".user.ini",
        "nginx.conf", "httpd.conf", "apache2.conf",
    })
    SERVER_CONF_DIRS: ClassVar[FrozenSet[str]] = frozenset({
        "nginx", "apache", "apache2", "httpd", "conf.d", "sites-available", "sites-enabled",
    })

    def classify(
        self,
        change: ChangeType,
        relative: str,
        hits: Sequence[SignatureHit] = (),
        findings: Sequence[Issue] = (),
    ) -> Tuple[Severity, Tuple[str, ...]]:
        path = self.normalized(relative)
        suffix = path.suffix.lower()
        rated: List[Tuple[Severity, str]] = []
        if path.name != PurePosixPath(relative).name:
            rated.append((Severity.LOW, f"Name ends with a dot or space; Windows serves it as {path.name}"))

        if change in (ChangeType.NEW, ChangeType.MODIFIED):
            for hit in hits:
                rated.append((Severity.CRITICAL, f"Web shell signature: {hit.description} (line {hit.line})"))
            hidden = self._hidden_extension(path)
            if hidden:
                rated.append((Severity.CRITICAL, f"Executable extension {hidden} hidden behind {suffix}"))

        public = self._public_dir(path)
        sensitive = self._is_sensitive(path)
        if change is ChangeType.NEW:
            if suffix in self.EXECUTABLE and public:
                rated.append((Severity.CRITICAL, f"New executable file in the {public}/ folder"))
            elif sensitive:
                rated.append((Severity.HIGH, "New sensitive configuration file"))
            elif suffix in self.CODE:
                rated.append((Severity.MEDIUM, "New code file"))
            else:
                rated.append((Severity.LOW, "New file"))
        elif change is ChangeType.MODIFIED:
            if sensitive:
                rated.append((Severity.HIGH, "Sensitive configuration file changed"))
            elif suffix in self.CODE:
                rated.append((Severity.MEDIUM, "Source file changed"))
            else:
                rated.append((Severity.LOW, "File changed"))
        elif change is ChangeType.DELETED:
            if sensitive:
                rated.append((Severity.HIGH, "Sensitive configuration file deleted"))
            else:
                rated.append((Severity.MEDIUM, "File deleted"))

        if findings:
            worst = max(findings, key=lambda issue: issue.severity.weight).severity
            rated.append((Severity.LOW, f"Code scan: {len(findings)} finding(s), worst {worst.value}"))

        rated.sort(key=lambda item: -item[0].weight)
        return rated[0][0], tuple(reason for _, reason in rated)

    def is_code(self, relative: str) -> bool:
        return self.normalized(relative).suffix.lower() in self.CODE

    @staticmethod
    def normalized(relative: str) -> PurePosixPath:
        """Trailing dots and spaces dropped from every part: Windows ignores them."""
        parts = [part.rstrip(". ") or part for part in PurePosixPath(relative).parts]
        return PurePosixPath(*parts) if parts else PurePosixPath(relative)

    def _hidden_extension(self, path: PurePosixPath) -> str:
        """``shell.php.jpg`` -> ``.php``: an executable extension before a harmless one."""
        suffixes = [s.lower() for s in path.suffixes]
        if len(suffixes) < 2 or suffixes[-1] not in self.HARMLESS_LOOKING:
            return ""
        return next((s for s in suffixes[:-1] if s in self.EXECUTABLE), "")

    def _public_dir(self, path: PurePosixPath) -> str:
        return next((p for p in path.parts[:-1] if p.lower() in self.PUBLIC_DIRS), "")

    def _is_sensitive(self, path: PurePosixPath) -> bool:
        name = path.name.lower()
        parents = {p.lower() for p in path.parts[:-1]}
        if name in self.SENSITIVE_NAMES:
            return True
        if name == ".env" or name.startswith(".env."):
            return True
        if name == "dockerfile" or name.startswith("dockerfile."):
            return True
        if name.endswith(".conf") and parents & self.SERVER_CONF_DIRS:
            return True
        if "sites-enabled" in parents or "sites-available" in parents:
            return True
        return "settings" in parents and name.endswith(".py")


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
        current = self._current_states(tree, full)

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
            event = self._event(tree, change, relative, old, new)
            self._remember(event)
            events.append(event)
        return events

    def _current_states(self, tree: FileTree, full: bool) -> Dict[str, FileState]:
        states: Dict[str, FileState] = {}
        for relative, info in tree.walk().items():
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
        self, tree: FileTree, change: ChangeType, relative: str, old: str, new: str
    ) -> IntegrityEvent:
        path = tree.absolute(relative)
        hits: List[SignatureHit] = []
        findings: List[Issue] = []
        if change is not ChangeType.DELETED:
            hits = WebShellDetector.scan_file(path)
            findings = self._scan_file(path)
        severity, reasons = self._classifier.classify(change, relative, hits, findings)
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
