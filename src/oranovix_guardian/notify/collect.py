"""
Reads the local state the daily report is built from.

Only local stores are read (feed.db, security_events.db, scan_history.db
and the running Live Defense monitor); nothing is downloaded. It runs on
the notification monitor thread. What may leave the machine is decided
later by ``DailyReport.build``.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, List, Optional
from urllib.parse import urlsplit

from oranovix_guardian.core.scan_history import ScanHistory

from .report import ReportState, ScanSummary, SiteChange

LOOK_BACK = timedelta(days=8)       # the longest report period is a week


class ReportCollector:
    def __init__(self, hub: Callable[[], Any], live_defense: Callable[[], Any],
                 sentinel_store: Callable[[], Any], clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._hub = hub
        self._live_defense = live_defense
        self._sentinel_store = sentinel_store
        self._clock = clock

    def __call__(self) -> ReportState:
        since = self._clock() - LOOK_BACK
        hub = self._hub()
        items, projects, checked, sites = [], [], False, []
        if hub is not None:
            items = hub.store.items(limit=100000)
            projects = hub.registry.list()
            checked = hub.state().checked
            sites = self._sites(hub, projects, since)
        controller = self._live_defense()
        integrity = controller.open_events() if controller is not None else []
        store = self._sentinel_store()
        events = store.events_since(since) if store is not None else []
        return ReportState(feed_items=items, projects=projects, feed_checked=checked, sites=sites,
                           sentinel_events=events, integrity_events=integrity,
                           last_scan=self._last_scan(projects))

    @staticmethod
    def _sites(hub: Any, projects: List[Any], since: datetime) -> List[SiteChange]:
        changes = []
        for project in projects:
            if not project.site_url:
                continue
            host = urlsplit(project.site_url).hostname or ""
            down = hub.uptime_store.down_since(project.name, project.site_url)
            if down is not None:
                changes.append(SiteChange(project.name, host, down_since=down))
                continue
            back = ReportCollector._back_up(hub.uptime_store.history(project.name, limit=100), since)
            if back is not None:
                changes.append(SiteChange(project.name, host, down_since=back[0], back_up_at=back[1]))
        return changes

    @staticmethod
    def _back_up(history: List[Any], since: datetime) -> Optional[tuple]:
        """(first failure, first success after it) of the newest outage that ended after *since*."""
        newest_first = list(history)
        for index, check in enumerate(newest_first):
            if check.ok:
                continue
            ups = [c for c in newest_first[:index] if c.ok]
            if not ups or ups[-1].checked_at < since:
                return None
            start = check
            for older in newest_first[index:]:
                if older.ok:
                    break
                start = older
            return start.checked_at, ups[-1].checked_at
        return None

    @staticmethod
    def _last_scan(projects: List[Any]) -> Optional[ScanSummary]:
        last = ScanHistory().last_scan()
        if not last:
            return None
        try:
            moment = datetime.fromisoformat(last["date"])
        except ValueError:
            return None
        name = last["target"]
        path = os.path.normcase(os.path.abspath(last["path"])) if last["path"] else ""
        for project in projects:
            if path and project.key == path:
                name = project.name
        if moment.tzinfo is None:
            moment = moment.astimezone()
        return ScanSummary(moment, name, last["counts"])
