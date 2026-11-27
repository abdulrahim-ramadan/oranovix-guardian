"""
Log Sentinel controller: owns the monitor for the whole app.

Like the Live Defense controller it outlives page rebuilds, keeps its
settings in ``settings.json`` (entry ``log_sentinel``) and tells
listeners about changes through ``dispatch``; it never touches Tk.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from oranovix_guardian.core.alarm_center import AlarmCenter
from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.live_defense.controller import LiveDefenseSettings
from oranovix_guardian.scanner_engine.base import Severity

from .behaviour import BehaviourConfig
from .entry import NetworkList
from .events import EventFactory, SecurityEvent
from .export import EventExporter
from .monitor import LogSentinelMonitor, PlantedPathProvider, SentinelConfig, SentinelReport, WatchedLog
from .parsers import JsonFieldMap, LogFormat
from .privacy import HashKeyProvider, IpAnonymizer, KeyStore
from .store import Attacker, EventFilter, SecurityEventStore
from .tail import TailStateStore

Dispatch = Callable[[Callable[[], None]], object]


class SentinelError(RuntimeError):
    """A setting or an action was refused; the text is shown to the user."""


class SentinelSettings(LiveDefenseSettings):
    """The ``log_sentinel`` entry of ``settings.json``."""

    KEY = "log_sentinel"
    DEFAULT_INTERVAL = 10
    MIN_INTERVAL = 5
    MAX_INTERVAL = 3600


@dataclass(frozen=True)
class SentinelOptions:
    """What the user set, as read from the settings file."""

    logs: Tuple[WatchedLog, ...] = ()
    interval: int = SentinelSettings.DEFAULT_INTERVAL
    trusted_proxies: Tuple[str, ...] = ()
    allowlist: Tuple[str, ...] = ()
    keep_full_ips: bool = False
    retention_days: int = SecurityEventStore.DEFAULT_RETENTION_DAYS
    backfill_mb: int = 0
    flood_per_minute: int = 300
    brute_force_threshold: int = 10
    json_fields: JsonFieldMap = JsonFieldMap()
    running: bool = False

    @classmethod
    def load(cls, raw: Dict[str, object]) -> "SentinelOptions":
        logs = []
        listed = raw.get("logs")
        for item in listed if isinstance(listed, list) else []:
            if isinstance(item, dict) and str(item.get("path") or "").strip():
                try:
                    log_format = LogFormat(str(item.get("format") or "auto"))
                except ValueError:
                    log_format = LogFormat.AUTO
                logs.append(WatchedLog(str(item["path"]), log_format))
        return cls(
            logs=tuple(logs),
            interval=_number(raw.get("interval"), SentinelSettings.DEFAULT_INTERVAL,
                             SentinelSettings.MIN_INTERVAL, SentinelSettings.MAX_INTERVAL),
            trusted_proxies=_strings(raw.get("trusted_proxies")),
            allowlist=_strings(raw.get("allowlist")),
            keep_full_ips=raw.get("keep_full_ips") is True,
            retention_days=_number(raw.get("retention_days"), SecurityEventStore.DEFAULT_RETENTION_DAYS, 1, 3650),
            backfill_mb=_number(raw.get("backfill_mb"), 0, 0, 500),
            flood_per_minute=_number(raw.get("flood_per_minute"), 300, 10, 1_000_000),
            brute_force_threshold=_number(raw.get("brute_force_threshold"), 10, 2, 1000),
            json_fields=JsonFieldMap.from_settings(raw.get("json_fields")),
            running=raw.get("running") is True,
        )

    def config(self) -> SentinelConfig:
        return SentinelConfig(
            logs=self.logs,
            interval_seconds=self.interval,
            backfill_bytes=self.backfill_mb * 1024 * 1024,
            trusted_proxies=self.trusted_proxies,
            allowlist=self.allowlist,
            behaviour=BehaviourConfig(
                brute_force_threshold=self.brute_force_threshold, flood_per_minute=self.flood_per_minute,
            ),
            json_fields=self.json_fields,
        )


def _number(value: object, default: int, low: int, high: int) -> int:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return default
    return min(max(number, low), high)


def _strings(value: object) -> Tuple[str, ...]:
    if isinstance(value, str):
        value = value.replace(";", ",").replace("\n", ",").split(",")
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(text for text in (str(item).strip() for item in value) if text)[:200]


@dataclass(frozen=True)
class SentinelState:
    """Snapshot handed to listeners."""

    running: bool
    options: SentinelOptions
    open_critical: int
    open_high: int
    last_report: Optional[SentinelReport] = None
    new_events: Tuple[SecurityEvent, ...] = ()
    last_check_at: Optional[datetime] = None
    last_error: str = ""
    analysing: bool = False

    @property
    def open_alarming(self) -> int:
        return self.open_critical + self.open_high


Listener = Callable[[SentinelState], None]


def sample_log_path() -> Path:
    """The demo log that ships with the app."""
    return AppPaths.resource("assets", "sample_access.log")


class LogSentinelController:
    """Starts, stops and talks to the Log Sentinel monitor."""

    def __init__(
        self,
        dispatch: Dispatch,
        alarm_center: Optional[AlarmCenter] = None,
        settings: Optional[SentinelSettings] = None,
        store: Optional[SecurityEventStore] = None,
        tail_store: Optional[TailStateStore] = None,
        key_store: Optional[KeyStore] = None,
        planted: Optional[PlantedPathProvider] = None,
        spawn: Callable[[Callable[[], None]], object] = lambda work: threading.Thread(target=work, daemon=True).start(),
        read_state: Optional[Callable[[Callable[[], SentinelState], Listener], None]] = None,
    ) -> None:
        self._dispatch = dispatch
        self._read_state = read_state
        self._alarm_center = alarm_center
        self._settings = settings or SentinelSettings()
        self._store = store or SecurityEventStore()
        self._tail_store = tail_store
        self._planted = planted
        self._spawn = spawn
        self._key = HashKeyProvider(key_store, self._store).key()
        self._listeners: List[Listener] = []
        self._monitor: Optional[LogSentinelMonitor] = None
        self._last_report: Optional[SentinelReport] = None
        self._analysing = False
        self._lock = threading.Lock()
        # Retention is applied on every start of the app.
        self.purged = self._store.purge(self.options().retention_days)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def store(self) -> SecurityEventStore:
        return self._store

    @property
    def is_running(self) -> bool:
        return self._monitor is not None and self._monitor.is_running

    def options(self) -> SentinelOptions:
        return SentinelOptions.load(self._settings.load())

    def state(self, new_events: Sequence[SecurityEvent] = ()) -> SentinelState:
        report = self._last_report
        return SentinelState(
            running=self.is_running,
            options=self.options(),
            open_critical=self._store.open_count((Severity.CRITICAL,)),
            open_high=self._store.open_count((Severity.HIGH,)),
            last_report=report,
            new_events=tuple(new_events),
            last_check_at=report.finished_at if report else None,
            last_error=report.error if report else "",
            analysing=self._analysing,
        )

    def events(self, event_filter: EventFilter = EventFilter(), limit: int = 200) -> List[SecurityEvent]:
        return self._store.events(event_filter, limit)

    def top_attackers(self, limit: int = 5) -> List[Attacker]:
        return self._store.top_attackers(limit)

    def resume_candidate(self) -> Tuple[str, ...]:
        """The logs to offer for resuming, or ``()``: monitoring was on when the app closed."""
        options = self.options()
        if not options.running:
            return ()
        return tuple(log.path for log in options.logs if os.path.isfile(log.path))

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listener(self, listener: Listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def notify(self, new_events: Sequence[SecurityEvent] = ()) -> None:
        if self._read_state is None:
            self._deliver(self.state(new_events))
        else:
            self._read_state(lambda: self.state(new_events), self._deliver)

    def _deliver(self, snapshot: SentinelState) -> None:
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                self.remove_listener(listener)

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def add_log(self, path: str, log_format: LogFormat = LogFormat.AUTO) -> None:
        path = os.path.abspath(path.strip())
        if not os.path.isfile(path):
            raise SentinelError(f"{path}: not a file.")
        logs = [log for log in self.options().logs if os.path.normcase(log.path) != os.path.normcase(path)]
        logs.append(WatchedLog(path, log_format))
        self._save_logs(logs)

    def remove_log(self, path: str) -> None:
        logs = [log for log in self.options().logs if os.path.normcase(log.path) != os.path.normcase(path)]
        self._save_logs(logs)

    def set_interval(self, seconds: object) -> int:
        value = _number(seconds, SentinelSettings.DEFAULT_INTERVAL, SentinelSettings.MIN_INTERVAL,
                        SentinelSettings.MAX_INTERVAL)
        self._settings.save(interval=value)
        if self._monitor is not None:
            self._monitor.interval = value
        return value

    def set_networks(self, trusted_proxies: str, allowlist: str) -> List[str]:
        """Save both lists. Returns the entries that are not addresses or ranges (not saved)."""
        proxies, allowed = NetworkList(_strings(trusted_proxies)), NetworkList(_strings(allowlist))
        self._settings.save(trusted_proxies=list(proxies.entries), allowlist=list(allowed.entries))
        self._restart_if_running()
        return proxies.invalid + allowed.invalid

    def set_keep_full_ips(self, keep: bool) -> None:
        """Off also truncates the addresses that were stored in full."""
        self._settings.save(keep_full_ips=bool(keep))
        if not keep:
            self._store.forget_full_addresses()
        self._restart_if_running()

    def set_retention(self, days: object) -> int:
        value = _number(days, SecurityEventStore.DEFAULT_RETENTION_DAYS, 1, 3650)
        self._settings.save(retention_days=value)
        self._store.purge(value)
        return value

    def _save_logs(self, logs: Sequence[WatchedLog]) -> None:
        self._settings.save(logs=[{"path": log.path, "format": log.log_format.value} for log in logs])
        self._restart_if_running()

    def _restart_if_running(self) -> None:
        if self.is_running:
            self.stop(remember=False)
            self.start()

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    def build_monitor(self) -> LogSentinelMonitor:
        options = self.options()
        return LogSentinelMonitor(
            options.config(),
            self._store,
            EventFactory(IpAnonymizer(self._key, options.keep_full_ips)),
            tail_store=self._tail_store or TailStateStore(),
            alarm_center=self._alarm_center,
            planted=self._planted,
            on_sentinel_report=self._on_report,
        )

    def start(self) -> None:
        if not self.options().logs:
            raise SentinelError("Add a log file first.")
        if self.is_running:
            return
        self._monitor = self.build_monitor()
        self._last_report = None
        self._monitor.start()
        self._settings.save(running=True)

    def stop(self, remember: bool = True) -> None:
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None
        if remember:
            self._settings.save(running=False)

    def shutdown(self, timeout: Optional[float] = 2) -> None:
        """App closes: stop the thread but keep "running" so it can be resumed."""
        if self._monitor is not None:
            self._monitor.stop(timeout=timeout)

    def check_now(self) -> SentinelReport:
        """One cycle in the caller's thread (tests and the hand test)."""
        monitor = self._monitor or self.build_monitor()
        report = monitor.run_cycle()
        self._last_report = report
        return report

    def analyse_file(self, path: str, alarm: bool = False) -> None:
        """Analyse a whole file once in the background (the sample, or an old log)."""
        if self._analysing:
            return
        self._analysing = True
        self._dispatch(self.notify)

        def work() -> None:
            report: Optional[SentinelReport] = None
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    lines = handle.read(50 * 1024 * 1024).splitlines()
                monitor = self.build_monitor()
                report = monitor.analyse_lines(lines, os.path.abspath(path), alarm=alarm)
            except OSError as exc:
                report = SentinelReport(error=f"{type(exc).__name__}: {exc}")
            finally:
                self._analysing = False
                self._last_report = report
                events = report.new_events if report is not None else ()
                self._dispatch(lambda: self.notify(events))

        self._spawn(work)

    def analyse_sample(self) -> None:
        self.analyse_file(str(sample_log_path()))

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def acknowledge(self, event_ids: Sequence[int]) -> int:
        changed = self._store.acknowledge(event_ids)
        self.notify()
        return changed

    def acknowledge_all(self, event_filter: EventFilter = EventFilter()) -> int:
        changed = self._store.acknowledge_all(event_filter)
        self.notify()
        return changed

    def export_csv(self, path: str, event_filter: EventFilter = EventFilter()) -> int:
        return EventExporter.to_csv(self._store.events(event_filter, limit=1_000_000), path)

    def _on_report(self, report: SentinelReport) -> None:
        # Called in the monitor thread: hand over to the dispatch thread.
        self._last_report = report
        self._dispatch(lambda: self.notify(report.new_events))
