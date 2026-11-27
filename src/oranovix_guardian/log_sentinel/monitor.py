"""
Log Sentinel monitor: tails access logs, detects attacks, stores events,
raises alarms. Detection only: nothing is blocked.

It is a Live Defense ``Monitor``, so it runs in its own thread with the
same start/stop handling. Its results go to ``on_sentinel_report``; the
integrity events the base class expects are always empty.

The link to the file integrity monitor is optional and goes through
``PlantedPathProvider``: when a file that was planted in a public folder
is then requested and served, the web shell is probably in use.
"""
from __future__ import annotations

import os
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter
from oranovix_guardian.live_defense.base import ChangeType, IntegrityEvent, Monitor
from oranovix_guardian.live_defense.paths import PUBLIC_DIRS
from oranovix_guardian.scanner_engine.base import Severity

from .behaviour import BehaviourConfig, SentinelEngine
from .entry import AccessLogEntry, ClientAddressResolver
from .events import EventFactory, EventSink, SecurityEvent
from .normalize import NormalizedRequest, RequestNormalizer
from .parsers import JsonFieldMap, LogFormat, LogFormatDetector, LogParser, ParseStats
from .rules import AttackCategory, Detection, Reason
from .tail import LogTailer, TailStateStore

Clock = Callable[[], datetime]
ALARM_SEVERITIES = (Severity.HIGH, Severity.CRITICAL)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WatchedLog:
    path: str
    log_format: LogFormat = LogFormat.AUTO


@dataclass(frozen=True)
class SentinelConfig:
    logs: Tuple[WatchedLog, ...] = ()
    interval_seconds: int = 10
    max_bytes_per_cycle: int = 5 * 1024 * 1024
    backfill_bytes: int = 0                     # read the last N bytes once when a log is new
    trusted_proxies: Tuple[str, ...] = ()
    allowlist: Tuple[str, ...] = ()
    behaviour: BehaviourConfig = BehaviourConfig()
    json_fields: JsonFieldMap = JsonFieldMap()
    alarm_window_minutes: int = 10


# ---------------------------------------------------------------------------
# Link to the file integrity monitor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlantedFile:
    """A new or changed file in a public folder that the integrity monitor reported."""

    event_id: str
    relative_path: str          # posix, relative to the monitored root
    url_suffix: str             # lower case, from the public folder on: "/media/uploads/x.php"
    severity: Severity = Severity.HIGH


class PlantedPathProvider(ABC):
    @abstractmethod
    def planted_files(self) -> Sequence[PlantedFile]:
        """The files to watch for in the log. Called once per cycle."""


class IntegrityPlantedPaths(PlantedPathProvider):
    """Reads the open events of the file integrity monitor.

    Only files that matter count: code types, or files the integrity
    monitor already rated HIGH or CRITICAL. A changed stylesheet that is
    requested after a deploy is not a web shell.
    """

    SCRIPT_EXTENSIONS = frozenset({
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".pht", ".jsp", ".jspx",
        ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".py", ".pl", ".cgi", ".sh", ".rb", ".shtml",
    })

    def __init__(self, open_events: Callable[[], Sequence[IntegrityEvent]]) -> None:
        self._open_events = open_events

    def planted_files(self) -> List[PlantedFile]:
        files = []
        try:
            events = list(self._open_events())
        except Exception:
            return []
        for event in events:
            planted = self.planted(event)
            if planted is not None:
                files.append(planted)
        return files

    @classmethod
    def planted(cls, event: IntegrityEvent) -> Optional[PlantedFile]:
        if event.change not in (ChangeType.NEW, ChangeType.MODIFIED) or not event.relative_path:
            return None
        parts = event.relative_path.split("/")
        index = next((i for i, part in enumerate(parts[:-1]) if part.lower() in PUBLIC_DIRS), None)
        if index is None:
            return None
        extensions = {"." + piece.lower() for piece in parts[-1].split(".")[1:]}
        if not (extensions & cls.SCRIPT_EXTENSIONS or event.severity in ALARM_SEVERITIES):
            return None
        suffix = "/" + "/".join(parts[index:]).lower()
        return PlantedFile(event.event_id, event.relative_path, suffix, event.severity)


class PlantedFileLink:
    """Raises one CRITICAL detection when a planted file is served."""

    rule_id = "LS301"

    def __init__(self, provider: PlantedPathProvider) -> None:
        self._provider = provider
        self._files: Tuple[PlantedFile, ...] = ()
        self._linked: Set[str] = set()

    def refresh(self) -> None:
        self._files = tuple(self._provider.planted_files())
        current = {planted.event_id for planted in self._files}
        self._linked &= current          # an accepted file that comes back links again

    def check(self, entry: AccessLogEntry, request: NormalizedRequest) -> Optional[Detection]:
        if not self._files or not 200 <= entry.status < 400:
            return None
        path = request.path
        for planted in self._files:
            if planted.event_id in self._linked or not path.endswith(planted.url_suffix):
                continue
            self._linked.add(planted.event_id)
            return Detection(
                self.rule_id, AttackCategory.PLANTED_FILE, Severity.CRITICAL, entry,
                evidence=f"{planted.relative_path} <- {entry.method} {path}",
                reasons=(Reason.of("ls_reason_planted", file=planted.relative_path, status=entry.status),),
                normalized=request.text,
            )
        return None


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileReport:
    path: str
    lines: int = 0
    parsed: int = 0
    malformed: int = 0
    bytes_read: int = 0
    pending: int = 0
    rotated: bool = False
    truncated: bool = False
    missing: bool = False
    log_format: str = ""


@dataclass(frozen=True)
class SentinelReport:
    new_events: Tuple[SecurityEvent, ...] = ()
    files: Tuple[FileReport, ...] = ()
    alarm: Optional[Alarm] = None
    error: str = ""
    finished_at: datetime = field(default_factory=utc_now)


SentinelListener = Callable[[SentinelReport], None]


# ---------------------------------------------------------------------------
# The monitor
# ---------------------------------------------------------------------------

class _WatchedFile:
    """Tailer, parser and behaviour state of one log (one server)."""

    def __init__(self, watched: WatchedLog, store: TailStateStore, config: SentinelConfig, clock: Clock) -> None:
        self.watched = watched
        self.tailer = LogTailer(watched.path, store, config.backfill_bytes)
        self.detector = LogFormatDetector(ClientAddressResolver(config.trusted_proxies), config.json_fields)
        self.parser: Optional[LogParser] = None
        self.engine = SentinelEngine(config.allowlist, config.behaviour, clock=clock)

    def parser_for(self, lines: Sequence[str]) -> LogParser:
        if self.parser is None:
            self.parser = self.detector.parser_for(self.watched.log_format, lines)
        return self.parser


class AlarmThrottle:
    """Remembers recent alarm keys so a burst of requests calls the alarm center once."""

    def __init__(self, size: int = 10_000) -> None:
        self._keys: "OrderedDict[str, None]" = OrderedDict()
        self._size = size

    def first(self, key: str) -> bool:
        if key in self._keys:
            return False
        self._keys[key] = None
        while len(self._keys) > self._size:
            self._keys.popitem(last=False)
        return True


class LogSentinelMonitor(Monitor):
    """Watches one or more access logs."""

    def __init__(
        self,
        config: SentinelConfig,
        sink: EventSink,
        factory: EventFactory,
        tail_store: Optional[TailStateStore] = None,
        alarm_center: Optional[AlarmCenter] = None,
        planted: Optional[PlantedPathProvider] = None,
        on_sentinel_report: Optional[SentinelListener] = None,
        clock: Clock = utc_now,
    ) -> None:
        first = config.logs[0].path if config.logs else "."
        super().__init__(os.path.dirname(os.path.abspath(first)), config.interval_seconds, alarm_center)
        self._config = config
        self._sink = sink
        self._factory = factory
        self._clock = clock
        self._tail_store = tail_store or TailStateStore()
        self._files = [_WatchedFile(log, self._tail_store, config, clock) for log in config.logs]
        self._link = PlantedFileLink(planted) if planted is not None else None
        self._normalizer = RequestNormalizer()
        self._throttle = AlarmThrottle()
        self._on_sentinel_report = on_sentinel_report
        self._lock = threading.Lock()
        self.last_report: Optional[SentinelReport] = None

    @property
    def config(self) -> SentinelConfig:
        return self._config

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------

    def check(self) -> List[IntegrityEvent]:
        try:
            report = self.run_cycle()
        except Exception as exc:
            report = SentinelReport(error=f"{type(exc).__name__}: {exc}")
        self._publish(report)
        return []

    @staticmethod
    def _cooperate(index: int) -> None:
        # Briefly release the GIL during CPU-heavy batches so Tk can handle
        # timers and input even when the Python worker is continuously busy.
        if index % 256 == 0:
            time.sleep(0.001)

    def run_cycle(self) -> SentinelReport:
        """Read what is new in every log, at most ``max_bytes_per_cycle`` in total."""
        with self._lock:
            if self._link is not None:
                self._link.refresh()
            budget = self._config.max_bytes_per_cycle
            detections: List[Tuple[Detection, str]] = []
            files: List[FileReport] = []
            for watched in self._files:
                result = watched.tailer.read(budget)
                budget -= result.bytes_read
                stats_before = self._stats(watched)
                if result.lines:
                    parser = watched.parser_for(result.lines[:LogFormatDetector.SAMPLE])
                    for index, line in enumerate(result.lines, 1):
                        self._cooperate(index)
                        entry = parser.parse(line)
                        if entry is not None:
                            detections.extend((d, watched.watched.path) for d in self._detect(watched, entry))
                stats = self._stats(watched)
                files.append(FileReport(
                    path=watched.watched.path, lines=stats.lines - stats_before.lines,
                    parsed=stats.parsed - stats_before.parsed, malformed=stats.malformed - stats_before.malformed,
                    bytes_read=result.bytes_read, pending=result.pending, rotated=result.rotated,
                    truncated=result.truncated, missing=result.missing,
                    log_format=watched.parser.NAME if watched.parser else "",
                ))
            for watched in self._files:
                watched.engine.prune()
            events = self._store(detections)
            alarm = self._alarm(events)
            return SentinelReport(tuple(events), tuple(files), alarm)

    def analyse_lines(self, lines: Sequence[str], source: str, log_format: LogFormat = LogFormat.AUTO,
                      alarm: bool = False) -> SentinelReport:
        """Analyse lines once, with fresh state (the sample log, or an old log the user picks)."""
        watched = _WatchedFile(WatchedLog(source, log_format), self._tail_store, self._config, self._clock)
        parser = watched.parser_for(lines[:LogFormatDetector.SAMPLE])
        detections: List[Tuple[Detection, str]] = []
        for index, line in enumerate(lines, 1):
            self._cooperate(index)
            entry = parser.parse(line)
            if entry is not None:
                detections.extend((d, source) for d in self._detect(watched, entry, link=False))
        events = self._store(detections)
        stats = parser.stats
        report = SentinelReport(
            tuple(events),
            (FileReport(source, stats.lines, stats.parsed, stats.malformed, log_format=parser.NAME),),
            self._alarm(events) if alarm else None,
        )
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _detect(self, watched: _WatchedFile, entry: AccessLogEntry, link: bool = True) -> List[Detection]:
        found = watched.engine.process(entry)
        if link and self._link is not None and not watched.engine.allowlist.contains(entry.client_ip):
            request = self._normalizer.normalize(entry.path, entry.query)
            linked = self._link.check(entry, request)
            if linked is not None:
                found.append(linked)
        return found

    @staticmethod
    def _stats(watched: _WatchedFile) -> ParseStats:
        stats = watched.parser.stats if watched.parser else ParseStats()
        return ParseStats(stats.lines, stats.parsed, stats.malformed, stats.oversize)

    def _store(self, detections: Iterable[Tuple[Detection, str]]) -> List[SecurityEvent]:
        """One event per rule, address, window and severity; repeats are counted in ``hits``."""
        window = self._config.alarm_window_minutes
        merged: Dict[str, SecurityEvent] = {}
        for index, (detection, source) in enumerate(detections, 1):
            self._cooperate(index)
            event = self._factory.build(detection, source, self._clock())
            key = event.dedup_key(window)
            known = merged.get(key)
            if known is None:
                merged[key] = event
            else:
                merged[key] = replace(known, hits=known.hits + 1, last_time=max(known.last_time or known.time, event.time))
        if not merged:
            return []
        return self._sink.add(list(merged.values()))

    def _alarm(self, events: Sequence[SecurityEvent]) -> Optional[Alarm]:
        if self._alarm_center is None:
            return None
        window = self._config.alarm_window_minutes
        issues = [
            event.to_issue(window) for event in events
            if event.severity in ALARM_SEVERITIES and self._throttle.first(event.dedup_key(window))
        ]
        if not issues:
            return None
        return self._alarm_center.notify(issues, scan_root="", full_scan=False)

    def _publish(self, report: SentinelReport) -> None:
        self.last_report = report
        if self._on_sentinel_report is not None:
            try:
                self._on_sentinel_report(report)
            except Exception:
                pass    # a broken listener must not end the monitor
