"""
App-wide owner of the Threat Feed and the project list.

Pages are rebuilt on every theme or language change, so nothing that
runs in the background can live in a page. The hub holds the service,
the periodic refresh and the uptime monitor, and tells listeners about
changes through ``dispatch`` (the GUI passes ``widget.after``), so it
never touches Tk itself.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from oranovix_guardian.core.alarm_center import AlarmCenter
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.live_defense.base import IntegrityEvent, Monitor, MonitorReport

from .digest import Digest, DigestBuilder, DigestTexts
from .exposure import ExposureReport
from .fetcher import Fetcher
from .models import AcceptedRisk, Relevance, RiskKey, SourceHealth, StoredItem, project_key
from .projects import Project, ProjectRegistry, ScanSummary, ScanSummaryLookup
from .relevance import RelevanceMatcher
from .service import RefreshReport, ThreatFeedService
from .sanitize import TextCleaner
from .settings import ThreatFeedConfig, ThreatFeedSettings
from .sources import SourceCatalog, SourceConfig, SourceKind
from .store import FeedDatabase, ThreatStore
from .uptime import UptimeCheck, UptimeEvent, UptimeMonitor, UptimeStore

Dispatch = Callable[[Callable[[], None]], object]
Spawn = Callable[[Callable[[], None]], object]


def in_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="ThreatIntelWork", daemon=True).start()


class CheckState(str, Enum):
    """Whether "nothing affects your projects" may be said at all."""

    CHECKED = "checked"
    OFF = "off"                     # the feed is switched off
    NEVER = "never"                 # no download has succeeded yet
    UNREACHABLE = "unreachable"     # the last refresh reached no source
    NO_PROJECTS = "no_projects"
    NO_DATABASE = "no_database"     # without OSV data nothing can be confirmed
    PARTIAL = "partial"             # the catalog of exploited vulnerabilities failed

    @property
    def text_key(self) -> str:
        return f"tf_not_checked_{self.value}"


@dataclass(frozen=True)
class HubState:
    """Snapshot handed to listeners."""

    enabled: bool
    asked: bool
    refreshing: bool
    last_success: Optional[datetime]
    unread_for_you: int
    database_ready: bool
    last_report: Optional[RefreshReport] = None
    uptime_event: Optional[UptimeEvent] = None      # set only on the notification it belongs to
    has_projects: bool = True
    failed_catalogs: Tuple[str, ...] = ()           # KEV sources whose newest attempt failed

    @property
    def check(self) -> CheckState:
        """The first reason why the projects count as not checked."""
        if not self.enabled:
            return CheckState.OFF
        if self.last_success is None:
            return CheckState.NEVER
        if self.last_report is not None and self.last_report.offline:
            return CheckState.UNREACHABLE
        if not self.has_projects:
            return CheckState.NO_PROJECTS
        if not self.database_ready:
            return CheckState.NO_DATABASE
        if self.failed_catalogs:
            # News alone cannot give the all clear. A failed news feed does not matter here.
            return CheckState.PARTIAL
        return CheckState.CHECKED

    @property
    def checked(self) -> bool:
        return self.check is CheckState.CHECKED

    def not_checked_text(self, translate: Callable[..., str]) -> str:
        """Why the all clear cannot be given, in the user's language; ``""`` when it can."""
        check = self.check
        if check is CheckState.CHECKED:
            return ""
        return translate(check.text_key, source=", ".join(self.failed_catalogs))


@dataclass(frozen=True)
class ProjectRow:
    """Everything the My Projects table shows for one project."""

    project: Project
    scan: Optional[ScanSummary]
    check: Optional[UptimeCheck]
    down_since: Optional[datetime]
    affecting: int                          # open confirmed items, read or not
    packages: int
    checked: bool = True                    # False: "nothing affects it" cannot be said
    accepted: int = 0                       # confirmed items whose risk the user accepted


Listener = Callable[[HubState], None]


class FeedRefreshMonitor(Monitor):
    """Refreshes the feed on a timer, with the thread handling of every monitor."""

    def __init__(self, refresh: Callable[[], object], interval_seconds: float) -> None:
        super().__init__("", interval_seconds)
        self._refresh = refresh

    def check(self) -> List[IntegrityEvent]:
        self._refresh()
        return []


class ThreatIntelHub:
    """Starts, stops and talks to the feed service and the uptime monitor."""

    PAGE_SIZE = 200

    def __init__(
        self,
        dispatch: Dispatch,
        alarm_center: Optional[AlarmCenter] = None,
        database: Optional[FeedDatabase] = None,
        settings: Optional[ThreatFeedSettings] = None,
        fetcher: Optional[Fetcher] = None,
        uptime_fetcher: Optional[Fetcher] = None,
        matcher: Optional[RelevanceMatcher] = None,
        scan_lookup: Optional[ScanSummaryLookup] = None,
        spawn: Spawn = in_thread,
    ) -> None:
        """*spawn* runs slow work off the caller's thread; tests run it inline."""
        self._dispatch = dispatch
        self._spawn = spawn
        database = database or FeedDatabase()
        self._store = ThreatStore(database)
        self._registry = ProjectRegistry(database)
        self._uptime_store = UptimeStore(database)
        self._settings = settings or ThreatFeedSettings()
        self._service = ThreatFeedService(
            self._store, self._registry, self._settings,
            fetcher=fetcher, matcher=matcher, alarm_center=alarm_center,
        )
        self._uptime = UptimeMonitor(
            self._registry, self._uptime_store, fetcher=uptime_fetcher,
            alarm_center=alarm_center, on_report=self._on_uptime_report,
            on_event=self._on_uptime_event,
        )
        self._scan_lookup = scan_lookup or ScanSummaryLookup()
        self._listeners: List[Listener] = []
        self._refresher: Optional[FeedRefreshMonitor] = None
        self._busy = threading.Lock()           # held while a refresh is running
        self._last_report: Optional[RefreshReport] = None
        # "New" on the page means newer than the visit before this session.
        self._session_since = self._store.last_visit()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def store(self) -> ThreatStore:
        return self._store

    @property
    def registry(self) -> ProjectRegistry:
        return self._registry

    @property
    def uptime_store(self) -> UptimeStore:
        return self._uptime_store

    @property
    def session_since(self) -> Optional[datetime]:
        return self._session_since

    @property
    def is_refreshing(self) -> bool:
        return self._busy.locked()

    def config(self) -> ThreatFeedConfig:
        return self._settings.load()

    def hosts(self) -> List[str]:
        """Hosts a refresh would contact, for the consent dialog."""
        return SourceCatalog.hosts(self.config().sources)

    def state(self, uptime_event: Optional[UptimeEvent] = None) -> HubState:
        config = self.config()
        return HubState(
            enabled=config.enabled,
            asked=config.asked,
            refreshing=self.is_refreshing,
            last_success=self._store.last_success(),
            unread_for_you=self._store.unread_for_you(),
            database_ready=self._service.database_ready,
            last_report=self._last_report,
            uptime_event=uptime_event,
            has_projects=bool(self._registry.list()),
            failed_catalogs=self._failed_catalogs(),
        )

    def _failed_catalogs(self) -> Tuple[str, ...]:
        """Read from the stored source health, so it also holds after a restart."""
        return tuple(
            config.name for config, health in self._service.source_health()
            if config.kind is SourceKind.KEV and config.enabled
            and health.last_error_at is not None and not health.ok
        )

    def items(
        self, for_you: bool, limit: int = PAGE_SIZE, offset: int = 0, show_read: bool = True,
    ) -> List[StoredItem]:
        """One page of a tab.

        "All" is every item, newest first. "For you" is every item that
        affects a project, whatever its age, followed by the guesses.
        Without *show_read* the guesses that were read are left out. An
        item that affects a project is never left out.
        """
        if not for_you:
            return self._store.items(limit=limit, newest_first=True, offset=offset)
        return self._store.items(
            [Relevance.AFFECTS_YOU, Relevance.POSSIBLE], limit=limit, offset=offset,
            unread_only=not show_read, keep_affecting=True,
        )

    def item_count(self, for_you: bool, show_read: bool = True) -> int:
        """How many items the tab has in the store, shown or not."""
        if not for_you:
            return self._store.count()
        return self._store.count(
            [Relevance.AFFECTS_YOU, Relevance.POSSIBLE], unread_only=not show_read, keep_affecting=True,
        )

    def exposure(self) -> ExposureReport:
        """What every project is exposed to. The read flags play no part."""
        return ExposureReport.build(
            self._store.items([Relevance.AFFECTS_YOU], limit=100000),
            self._registry.list(), self._store.accepted_risks(),
        )

    def accepted_risks(self) -> Dict[RiskKey, AcceptedRisk]:
        return self._store.accepted_risks()

    def source_health(self) -> List[Tuple[SourceConfig, SourceHealth]]:
        return self._service.source_health()

    def digest(self, since: Optional[datetime]) -> Digest:
        """What arrived after *since*, worded in the current language.

        When the projects could not be checked, the headline says why.
        """
        lm = LanguageManager()
        return DigestBuilder.build(
            self._store.items(limit=100000), self._registry.list(), since,
            DigestTexts.translated(lm.t),
            not_checked=self.state().not_checked_text(lm.t),
            exposure=self.exposure(),
        )

    def project_rows(self, exposure: Optional[ExposureReport] = None) -> List[ProjectRow]:
        if exposure is None:
            exposure = self.exposure()
        checked = self.state().checked
        rows = []
        for entry in exposure.projects:
            project = entry.project
            check = self._uptime_store.latest(project.name) if project.site_url else None
            if check is not None and check.url != project.site_url:
                check = None                    # the address was changed since
            rows.append(ProjectRow(
                project=project,
                scan=self._scan_lookup.latest_for(project),
                check=check,
                down_since=(
                    self._uptime_store.down_since(project.name, project.site_url)
                    if project.site_url else None
                ),
                affecting=len(entry.open),
                packages=len(self._service.inventory(project).dependencies),
                checked=checked,
                accepted=len(entry.accepted),
            ))
        return rows

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def add_listener(self, listener: Listener) -> None:
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove_listener(self, listener: Listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def notify(self, uptime_event: Optional[UptimeEvent] = None) -> None:
        """Send the current state to every listener (call on the dispatch thread)."""
        snapshot = self.state(uptime_event)
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                self.remove_listener(listener)      # e.g. a destroyed page

    # ------------------------------------------------------------------
    # Switching the feed on and off
    # ------------------------------------------------------------------

    def answer_first_run(self, enable: bool) -> None:
        """Record the answer of the first-run dialog."""
        self.set_enabled(enable)

    def set_enabled(self, enabled: bool) -> None:
        self._settings.update(enabled=enabled, asked=True)
        if enabled:
            self._start_refresher()
        else:
            self._stop_refresher()
        self.notify()

    def set_interval(self, minutes: object) -> int:
        config = self._settings.update(interval_minutes=ThreatFeedConfig.valid_interval(minutes))
        if self._refresher is not None:
            self._refresher.interval = config.interval_minutes * 60
        return config.interval_minutes

    def set_sources(self, sources: Sequence[SourceConfig]) -> None:
        self._settings.update(sources=tuple(sources))
        self.notify()

    # ------------------------------------------------------------------
    # Background work
    # ------------------------------------------------------------------

    def start(self) -> None:
        """App start: uptime checks always, feed refresh only when switched on."""
        self._uptime.start()
        if self.config().enabled:
            self._start_refresher()

    def shutdown(self, timeout: Optional[float] = 2) -> None:
        self._uptime.stop(timeout=timeout)
        self._stop_refresher(timeout=timeout)

    def refresh_async(self) -> bool:
        """Refresh in a background thread. Returns ``False`` when one is already running."""
        if self.is_refreshing:
            return False
        self._spawn(lambda: self._refresh() and None)
        return True

    def refresh_now(self) -> Optional[RefreshReport]:
        """Refresh in the caller's thread (tests, and the timer thread)."""
        return self._refresh()

    def _refresh(self) -> Optional[RefreshReport]:
        if not self._busy.acquire(blocking=False):
            return None
        try:
            self._dispatch(self.notify)                 # show "refreshing"
            self._last_report = self._service.refresh()
            return self._last_report
        finally:
            self._busy.release()
            self._dispatch(self.notify)

    def _start_refresher(self) -> None:
        if self._refresher is not None and self._refresher.is_running:
            return
        self._refresher = FeedRefreshMonitor(self._refresh, self.config().interval_minutes * 60)
        self._refresher.start()

    def _stop_refresher(self, timeout: Optional[float] = 10.0) -> None:
        if self._refresher is not None:
            self._refresher.stop(timeout)
            self._refresher = None

    def _on_uptime_report(self, report: MonitorReport) -> None:
        self._dispatch(self.notify)

    def _on_uptime_event(self, event: UptimeEvent) -> None:
        self._dispatch(lambda: self.notify(event))

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    def add_project(self, name: str, path: str, site_url: Optional[str] = None) -> Project:
        """Add the project at once; matching and the first site check follow in the background.

        Raises ``ProjectError`` when the values are not acceptable.
        """
        project = self._registry.add(name, path, site_url)

        def settle() -> None:
            self._service.rematch()
            if project.site_url:
                self._uptime.check_project(project)
            self._dispatch(self.notify)

        self._spawn(settle)
        return project

    def remove_project(self, name: str) -> None:
        project = self._registry.get(name)
        if project is None or not self._registry.remove(name):
            return
        self._uptime_store.forget(name)
        self._store.forget_risks(project.path)

        def settle() -> None:
            self._service.rematch()
            self._dispatch(self.notify)

        self._spawn(settle)

    def recheck_async(self) -> None:
        """Match the stored items against the manifests again, e.g. after a scan. No network."""
        def settle() -> None:
            self._service.rematch()
            self._dispatch(self.notify)

        self._spawn(settle)

    # ------------------------------------------------------------------
    # Accepted risks
    # ------------------------------------------------------------------

    MAX_REASON = 200

    def accept_risk(self, item_id: str, reason: str, project_path: Optional[str] = None) -> List[AcceptedRisk]:
        """Accept the risk of an item, for one project or for every project it hits.

        The item stays listed, in grey, and no longer counts as open.
        Raises ``ValueError`` without a reason: the note is the point.
        """
        text = TextCleaner.plain(reason)[: self.MAX_REASON].strip()
        if not text:
            raise ValueError(LanguageManager().t("tf_risk_reason_missing"))
        stored = self._store.get(item_id)
        if stored is None:
            return []
        wanted = project_key(project_path) if project_path else None
        paths = {
            project_key(match.project_path): match.project_path
            for match in stored.matches
            if match.confirmed and wanted in (None, project_key(match.project_path))
        }
        notes = [self._store.accept_risk(item_id, path, text) for path in paths.values()]
        self.notify()
        return notes

    def withdraw_risk(self, item_id: str, project_path: Optional[str] = None) -> None:
        self._store.withdraw_risk(item_id, project_path)
        self.notify()

    def check_sites_now(self) -> None:
        """One uptime cycle in the caller's thread."""
        self._uptime.check_sites()
