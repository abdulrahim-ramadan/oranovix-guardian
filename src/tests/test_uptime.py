"""UptimeMonitor with a fake fetcher. Cycles are called directly: no sleeps, no network."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from feed_fakes import FakeFetcher
from oranovix_guardian.live_defense.base import Monitor, MonitorReport
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.fetcher import FetchError, FetchResponse
from oranovix_guardian.threat_intel.projects import ProjectRegistry
from oranovix_guardian.threat_intel.store import FeedDatabase
from oranovix_guardian.threat_intel.uptime import UptimeEvent, UptimeEventKind, UptimeMonitor, UptimeStore

pytestmark = pytest.mark.usefixtures("no_network")

SHOP_URL = "https://shop.example.org/"
BLOG_URL = "http://blog.example.org/health"
START = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
UP = FetchResponse(status=200, body=b"ok", elapsed_ms=120)
DOWN = FetchError("URLError: connection refused")


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class SoundChannel(RecordingChannel):
    levels = frozenset({AlarmLevel.CRITICAL})


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.now = START
        self.fetcher = FakeFetcher({SHOP_URL: UP, BLOG_URL: UP})
        self.toast = RecordingChannel()
        self.sound = SoundChannel()
        self.events: List[UptimeEvent] = []
        database = FeedDatabase(str(tmp_path / "feed.db"))
        self.registry = ProjectRegistry(database)
        self.store = UptimeStore(database)
        self.monitor = UptimeMonitor(
            self.registry, self.store, fetcher=self.fetcher,
            alarm_center=AlarmCenter(
                store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")),
                channels=[self.toast, self.sound],
            ),
            on_event=self.events.append,
            clock=lambda: self.now,
        )
        self.shop_dir = tmp_path / "shop"
        self.shop_dir.mkdir()

    def cycle(self, count: int = 1) -> None:
        """Run *count* cycles, five minutes of pretended time apart."""
        for _ in range(count):
            self.monitor.check()
            self.now += timedelta(minutes=5)


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    rig = Rig(tmp_path)
    rig.registry.add("Shop", str(rig.shop_dir), SHOP_URL)
    return rig


def test_monitor_is_a_live_defense_monitor_with_a_five_minute_interval(rig: Rig) -> None:
    assert isinstance(rig.monitor, Monitor)
    assert rig.monitor.interval == 300
    assert rig.monitor.check() == []


def test_check_records_status_and_response_time(rig: Rig) -> None:
    rig.cycle()

    (check,) = rig.store.history("Shop")
    assert check.ok and check.status == 200 and check.response_ms == 120
    assert check.url == SHOP_URL and check.checked_at == START
    assert rig.fetcher.requests == [(SHOP_URL, "", "")]            # a plain GET, nothing attached


def test_projects_without_a_site_are_not_checked(rig: Rig, tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    rig.registry.add("Library", str(tmp_path / "lib"))
    rig.cycle()
    assert rig.fetcher.urls == [SHOP_URL]
    assert rig.store.history("Library") == []


def test_three_failed_checks_in_a_row_raise_one_high_alarm(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN

    rig.cycle(2)
    assert rig.toast.alarms == [] and rig.events == []

    rig.cycle()
    (alarm,) = rig.toast.alarms
    assert alarm.level is AlarmLevel.HIGH
    assert alarm.worst_issue.severity is Severity.HIGH
    assert alarm.worst_issue.rule_id == "UP001"
    assert SHOP_URL in alarm.worst_issue.title and "Shop" in alarm.worst_issue.title
    assert rig.sound.alarms == []                                   # HIGH never makes sound
    assert [(e.kind, e.down_since) for e in rig.events] == [(UptimeEventKind.DOWN, START)]

    rig.cycle(5)                                                    # still down: nothing new
    assert len(rig.toast.alarms) == 1 and len(rig.events) == 1


def test_two_failures_then_a_success_do_not_alarm(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(2)
    rig.fetcher.answers[SHOP_URL] = UP
    rig.cycle()
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(2)

    assert rig.toast.alarms == [] and rig.events == []


def test_one_recovery_event_when_the_site_is_back(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(4)
    rig.fetcher.answers[SHOP_URL] = UP

    rig.cycle(3)

    assert [e.kind for e in rig.events] == [UptimeEventKind.DOWN, UptimeEventKind.RECOVERED]
    recovered = rig.events[1]
    assert recovered.project == "Shop" and recovered.down_since == START
    assert recovered.at == START + timedelta(minutes=20)
    assert len(rig.toast.alarms) == 1                               # recovery is not an alarm
    assert rig.store.down_since("Shop", SHOP_URL) is None


def test_a_second_outage_alarms_again(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(3)
    rig.fetcher.answers[SHOP_URL] = UP
    rig.cycle()
    rig.fetcher.answers[SHOP_URL] = DOWN

    rig.cycle(3)

    assert len(rig.toast.alarms) == 2
    assert [e.kind for e in rig.events] == [
        UptimeEventKind.DOWN, UptimeEventKind.RECOVERED, UptimeEventKind.DOWN,
    ]


def test_server_error_counts_as_down_but_a_client_error_does_not(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = FetchResponse(status=503, elapsed_ms=40)
    rig.cycle(3)
    assert len(rig.toast.alarms) == 1
    assert rig.store.history("Shop")[0].error == "HTTP 503"

    rig.fetcher.answers[SHOP_URL] = FetchResponse(status=403, elapsed_ms=40)
    rig.cycle()
    latest = rig.store.latest("Shop")
    assert latest is not None and latest.ok and latest.status == 403
    assert rig.events[-1].kind is UptimeEventKind.RECOVERED


def test_each_site_is_judged_on_its_own(rig: Rig, tmp_path: Path) -> None:
    (tmp_path / "blog").mkdir()
    rig.registry.add("Blog", str(tmp_path / "blog"), BLOG_URL)
    rig.fetcher.answers[BLOG_URL] = DOWN

    rig.cycle(3)

    assert [e.project for e in rig.events] == ["Blog"]
    shop = rig.store.latest("Shop")
    assert shop is not None and shop.ok
    assert BLOG_URL in rig.toast.alarms[0].worst_issue.title


def test_down_state_survives_a_restart_without_a_second_alarm(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(3)

    restarted = UptimeMonitor(
        rig.registry, rig.store, fetcher=rig.fetcher,
        alarm_center=AlarmCenter(store=SqliteSeenFindingStore(str(rig.shop_dir.parent / "alarms.db")),
                                 channels=[rig.toast]),
        on_event=rig.events.append, clock=lambda: rig.now,
    )
    restarted.check()

    assert len(rig.toast.alarms) == 1 and len(rig.events) == 1


def test_history_keeps_the_last_100_checks_per_project(rig: Rig) -> None:
    rig.cycle(130)

    history = rig.store.history("Shop")
    assert len(history) == 100 == UptimeStore.HISTORY_LENGTH
    assert history[0].checked_at == START + timedelta(minutes=5 * 129)     # newest first
    assert history[-1].checked_at == START + timedelta(minutes=5 * 30)


def test_removed_project_is_forgotten(rig: Rig) -> None:
    rig.fetcher.answers[SHOP_URL] = DOWN
    rig.cycle(3)
    rig.registry.remove("Shop")
    rig.store.forget("Shop")

    rig.cycle()

    assert rig.store.history("Shop") == []
    assert rig.store.down_since("Shop", SHOP_URL) is None
    assert len(rig.fetcher.requests) == 3


def test_background_thread_runs_a_cycle_and_stops(rig: Rig) -> None:
    reports: List[MonitorReport] = []
    cycle_done = threading.Event()

    def on_report(report: MonitorReport) -> None:
        reports.append(report)
        cycle_done.set()

    monitor = UptimeMonitor(rig.registry, rig.store, fetcher=rig.fetcher,
                            on_report=on_report, interval_seconds=3600)
    monitor.start()
    assert cycle_done.wait(5)
    assert monitor.stop() is True                   # the long interval was interrupted

    assert len(reports) == 1 and reports[0].error == ""
    assert rig.store.latest("Shop") is not None
