"""
Uptime checks of the sites the user added to their projects.

Every five minutes each site gets one plain GET. Three failed checks in
a row raise one HIGH alarm; when the site answers again one recovery
event is reported. Only addresses the user entered are contacted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, List, Optional

from oranovix_guardian.core.alarm_center import AlarmCenter
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.live_defense.base import IntegrityEvent, Monitor, ReportListener
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory

from .fetcher import FetchError, Fetcher, HttpFetcher
from .projects import Project, ProjectRegistry
from .sources import utc_now
from .store import FeedDatabase, Timestamp

Clock = Callable[[], datetime]


@dataclass(frozen=True)
class UptimeCheck:
    """Result of one GET."""

    project: str
    url: str
    checked_at: datetime
    ok: bool
    status: int = 0             # 0 when no answer arrived
    response_ms: int = 0
    error: str = ""


class UptimeEventKind(str, Enum):
    DOWN = "down"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class UptimeEvent:
    kind: UptimeEventKind
    project: str
    url: str
    at: datetime
    down_since: datetime


EventListener = Callable[[UptimeEvent], None]


class UptimeStore:
    """History of the checks and which sites are currently down (``feed.db``)."""

    HISTORY_LENGTH = 100

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS uptime_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            url TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            ok INTEGER NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            response_ms INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS uptime_project ON uptime_checks (project, id);
        CREATE TABLE IF NOT EXISTS sites_down (
            project TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            down_since TEXT NOT NULL
        );
    """

    def __init__(self, database: Optional[FeedDatabase] = None) -> None:
        self._db = database or FeedDatabase()
        self._db.script(self._SCHEMA)

    def record(self, check: UptimeCheck) -> None:
        self._db.write(
            "INSERT INTO uptime_checks (project, url, checked_at, ok, status, response_ms, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (check.project, check.url, Timestamp.text(check.checked_at), int(check.ok),
             check.status, check.response_ms, check.error[:300]),
        )
        self._db.write(
            "DELETE FROM uptime_checks WHERE project = ? AND id NOT IN ("
            "SELECT id FROM uptime_checks WHERE project = ? ORDER BY id DESC LIMIT ?)",
            (check.project, check.project, self.HISTORY_LENGTH),
        )

    def history(self, project: str, limit: int = HISTORY_LENGTH) -> List[UptimeCheck]:
        """The checks of *project*, newest first."""
        rows = self._db.read(
            "SELECT project, url, checked_at, ok, status, response_ms, error FROM uptime_checks "
            "WHERE project = ? ORDER BY id DESC LIMIT ?",
            (project, limit),
        )
        return [
            UptimeCheck(name, url, Timestamp.parse(at) or utc_now(), bool(ok), status, ms, error)
            for name, url, at, ok, status, ms, error in rows
        ]

    def latest(self, project: str) -> Optional[UptimeCheck]:
        checks = self.history(project, limit=1)
        return checks[0] if checks else None

    def down_since(self, project: str, url: str) -> Optional[datetime]:
        rows = self._db.read(
            "SELECT down_since FROM sites_down WHERE project = ? AND url = ?", (project, url)
        )
        return Timestamp.parse(rows[0][0]) if rows else None

    def set_down(self, project: str, url: str, since: datetime) -> None:
        self._db.write(
            "INSERT INTO sites_down (project, url, down_since) VALUES (?, ?, ?) "
            "ON CONFLICT(project) DO UPDATE SET url = excluded.url, down_since = excluded.down_since",
            (project, url, Timestamp.text(since)),
        )

    def clear_down(self, project: str) -> None:
        self._db.write("DELETE FROM sites_down WHERE project = ?", (project,))

    def forget(self, project: str) -> None:
        """Drop everything about a removed project."""
        self._db.write("DELETE FROM uptime_checks WHERE project = ?", (project,))
        self.clear_down(project)


class UptimeMonitor(Monitor):
    """Checks every project site in a background thread."""

    INTERVAL_SECONDS = 300
    FAILURES_FOR_ALARM = 3
    RULE_ID = "UP001"

    def __init__(
        self,
        registry: ProjectRegistry,
        store: UptimeStore,
        fetcher: Optional[Fetcher] = None,
        alarm_center: Optional[AlarmCenter] = None,
        on_report: Optional[ReportListener] = None,
        on_event: Optional[EventListener] = None,
        interval_seconds: float = INTERVAL_SECONDS,
        clock: Clock = utc_now,
    ) -> None:
        # A site is not a folder; the monitor base only needs the root for its alarms.
        super().__init__("", interval_seconds, alarm_center, on_report)
        self._registry = registry
        self._store = store
        # Only the status matters, so a long page is cut instead of refused.
        self._fetcher = fetcher or HttpFetcher(allow_http=True, max_bytes=64 * 1024, truncate=True)
        self._on_event = on_event
        self._clock = clock

    def check(self) -> List[IntegrityEvent]:
        """One cycle. Site events go to ``on_event``; there are no integrity events."""
        self.check_sites()
        return []

    def check_sites(self) -> List[UptimeEvent]:
        events: List[UptimeEvent] = []
        for project in self._registry.list():
            if not project.site_url:
                continue
            check = self.check_project(project)
            event = self._judge(project, check)
            if event is not None:
                events.append(event)
                self._announce(event)
        return events

    def check_project(self, project: Project) -> UptimeCheck:
        """GET the site once and record the result."""
        url = project.site_url or ""
        now = self._clock()
        try:
            response = self._fetcher.get(url)
            # 4xx still means the server is there and answering.
            check = UptimeCheck(
                project.name, url, now, ok=response.status < 500,
                status=response.status, response_ms=response.elapsed_ms,
                error="" if response.status < 500 else f"HTTP {response.status}",
            )
        except FetchError as exc:
            check = UptimeCheck(project.name, url, now, ok=False, error=str(exc))
        except Exception as exc:
            check = UptimeCheck(project.name, url, now, ok=False, error=type(exc).__name__)
        self._store.record(check)
        return check

    # ------------------------------------------------------------------
    # Down / recovered
    # ------------------------------------------------------------------

    def _judge(self, project: Project, check: UptimeCheck) -> Optional[UptimeEvent]:
        down_since = self._store.down_since(project.name, check.url)
        if check.ok:
            if down_since is None:
                self._store.clear_down(project.name)       # also drops an entry of an old address
                return None
            self._store.clear_down(project.name)
            return UptimeEvent(UptimeEventKind.RECOVERED, project.name, check.url, check.checked_at, down_since)

        if down_since is not None:
            return None                                     # already announced
        recent = [
            c for c in self._store.history(project.name, self.FAILURES_FOR_ALARM) if c.url == check.url
        ]
        if len(recent) < self.FAILURES_FOR_ALARM or any(c.ok for c in recent):
            return None
        since = recent[-1].checked_at
        self._store.set_down(project.name, check.url, since)
        self._alarm(project, check, since)
        return UptimeEvent(UptimeEventKind.DOWN, project.name, check.url, check.checked_at, since)

    def _alarm(self, project: Project, check: UptimeCheck, since: datetime) -> None:
        if self._alarm_center is None:
            return
        lm = LanguageManager()
        issue = Issue(
            rule_id=self.RULE_ID,
            title=lm.t("up_alarm_down", project=project.name, url=check.url,
                       count=self.FAILURES_FOR_ALARM),
            description=check.error,
            severity=Severity.HIGH,
            file_path=project.path,
            line_number=0,
            recommendation=lm.t("up_alarm_advice"),
            confidence="HIGH",
            category=IssueCategory.NETWORK,
            # The start of the outage is part of the id, so a later outage alarms again.
            finding_key=f"site-down|{check.url}|{Timestamp.text(since)}",
        )
        self._alarm_center.notify([issue], project.path, full_scan=False)

    def _announce(self, event: UptimeEvent) -> None:
        if self._on_event is not None:
            try:
                self._on_event(event)
            except Exception:
                pass
