"""Refresh cycle and alarms: fake fetcher, temporary databases, recording channels."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.threat_intel.fetcher import FetchResponse
from oranovix_guardian.threat_intel.models import Relevance
from oranovix_guardian.threat_intel.projects import ProjectRegistry
from oranovix_guardian.threat_intel.relevance import RelevanceMatcher
from oranovix_guardian.threat_intel.service import ThreatFeedService
from oranovix_guardian.threat_intel.settings import ThreatFeedSettings
from oranovix_guardian.threat_intel.sources import CisaKevSource, SourceConfig, SourceKind
from oranovix_guardian.threat_intel.store import FeedDatabase, ThreatStore

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURES = Path(__file__).parent / "fixtures"
OLD_SHOP = FIXTURES / "projects" / "old_shop"
PATCHED_SHOP = FIXTURES / "projects" / "patched_shop"
NEWS_URL = "https://news.example.org/feed/"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)

SOURCES = (
    SourceConfig("CISA KEV", CisaKevSource.URL, "en", True, SourceKind.KEV),
    SourceConfig("Example News", NEWS_URL, "en"),
)


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class SoundChannel(RecordingChannel):
    """Stands for the sound: it only takes CRITICAL alarms."""

    levels = frozenset({AlarmLevel.CRITICAL})


class Rig:
    """A service wired to temporary files and a fake network."""

    def __init__(self, tmp_path: Path, osv_db: OSVDatabase, enabled: bool = True) -> None:
        self.toast = RecordingChannel()
        self.sound = SoundChannel()
        self.fetcher = FakeFetcher({
            CisaKevSource.URL: (FIXTURES / "feeds" / "kev.json").read_bytes(),
            NEWS_URL: (FIXTURES / "feeds" / "news_rss.xml").read_bytes(),
        })
        database = FeedDatabase(str(tmp_path / "feed.db"))
        self.store = ThreatStore(database, clock=lambda: NOW)
        self.registry = ProjectRegistry(database)
        self.settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
        self.settings.update(enabled=enabled, asked=True, sources=SOURCES)
        self.service = ThreatFeedService(
            self.store, self.registry, self.settings, fetcher=self.fetcher,
            matcher=RelevanceMatcher(osv_db),
            alarm_center=AlarmCenter(
                store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")),
                channels=[self.toast, self.sound],
            ),
            clock=lambda: NOW,
        )


@pytest.fixture
def rig(tmp_path: Path, osv_db: OSVDatabase) -> Rig:
    return Rig(tmp_path, osv_db)


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

def test_refresh_stores_and_matches_items(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP))

    report = rig.service.refresh()

    # One catalog entry of the fixture is older than 30 days: stored, but not news.
    assert len(report.new_items) == 5 and report.background_items == 1
    assert report.sources_ok == 2 and report.failures == ()
    assert rig.store.count() == 6
    for_you = rig.store.items([Relevance.AFFECTS_YOU])
    assert {s.item.source for s in for_you} == {"CISA KEV", "Example News"}     # both name the CVE
    assert all(s.matches[0].project == "Shop" for s in for_you)
    assert rig.store.last_success() == NOW


def test_nothing_is_requested_while_the_feed_is_off(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db, enabled=False)
    rig.registry.add("Shop", str(OLD_SHOP))

    report = rig.service.refresh()

    assert report.disabled and report.new_items == ()
    assert rig.fetcher.requests == []
    assert rig.store.count() == 0


def test_only_feed_addresses_are_requested_and_nothing_about_projects_is_sent(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP), "https://shop.example.org/")

    rig.service.refresh()

    assert rig.fetcher.requests == [(CisaKevSource.URL, "", ""), (NEWS_URL, "", "")]


def test_one_failing_source_does_not_stop_the_others(rig: Rig) -> None:
    del rig.fetcher.answers[NEWS_URL]

    report = rig.service.refresh()

    assert report.sources_ok == 1 and len(report.new_items) == 2 and rig.store.count() == 3
    assert len(report.failures) == 1 and report.failures[0].startswith("Example News:")
    assert not report.offline
    health = {config.name: state for config, state in rig.service.source_health()}
    assert health["CISA KEV"].ok and not health["Example News"].ok
    assert health["Example News"].last_error == "no route to host"


def test_offline_refresh_keeps_the_cached_items(rig: Rig) -> None:
    rig.service.refresh()
    rig.fetcher.answers.clear()

    report = rig.service.refresh()

    assert report.offline and report.new_items == ()
    assert rig.store.count() == 6
    assert rig.store.last_success() == NOW


def test_second_refresh_sends_validators_and_304_adds_nothing(rig: Rig) -> None:
    rig.fetcher.answers[NEWS_URL] = FetchResponse(200, (FIXTURES / "feeds" / "news_rss.xml").read_bytes(), '"v1"')
    rig.service.refresh()
    rig.fetcher.answers[NEWS_URL] = FetchResponse(status=304)

    report = rig.service.refresh()

    assert rig.fetcher.requests[-1] == (NEWS_URL, '"v1"', "")
    assert report.new_items == () and report.sources_ok == 2


def test_adding_a_project_rematches_cached_items_without_the_network(rig: Rig) -> None:
    rig.service.refresh()
    assert rig.store.items([Relevance.AFFECTS_YOU]) == []
    requests = len(rig.fetcher.requests)

    rig.registry.add("Shop", str(OLD_SHOP))
    rig.service.rematch()

    assert len(rig.store.items([Relevance.AFFECTS_YOU])) == 2
    assert len(rig.fetcher.requests) == requests


# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

def test_exploited_item_that_affects_a_project_raises_one_critical_alarm(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP))

    report = rig.service.refresh()

    kev_alarm = next(a for a in rig.toast.alarms if "CVE-2019-14234" in a.worst_issue.title)
    assert kev_alarm.level is AlarmLevel.CRITICAL
    assert kev_alarm.worst_issue.severity is Severity.CRITICAL
    assert "Shop" in kev_alarm.worst_issue.title and "Django 2.2.0" in kev_alarm.worst_issue.title
    assert kev_alarm.worst_issue.rule_id == "TF001"
    assert Path(kev_alarm.worst_issue.file_path).name == "requirements.txt"
    assert len(rig.sound.alarms) == len(rig.toast.alarms) == len(report.alarms) == 2


def test_alarm_is_not_raised_again_on_the_next_refresh(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP))
    rig.service.refresh()
    first = len(rig.toast.alarms)

    again = rig.service.refresh()
    rig.service.rematch()

    assert first == 2
    assert again.alarms == () and len(rig.toast.alarms) == first


def test_alarm_is_not_repeated_when_the_manifest_line_moves(rig: Rig, tmp_path: Path) -> None:
    project = tmp_path / "moving"
    project.mkdir()
    (project / "requirements.txt").write_text("Django==2.2.0\n", encoding="utf-8")
    rig.registry.add("Moving", str(project))
    rig.service.refresh()
    first = len(rig.toast.alarms)

    (project / "requirements.txt").write_text("# pinned\n\nDjango==2.2.0\n", encoding="utf-8")
    rig.service.refresh()

    assert first == 2 and len(rig.toast.alarms) == first


def test_finding_id_includes_the_project(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP))
    rig.service.refresh()
    shop_ids = {fid for alarm in rig.toast.alarms for fid in alarm.finding_ids}
    assert str(OLD_SHOP).lower() in rig.toast.alarms[0].worst_issue.finding_key.lower()

    # The same items reach a second project later: those are new findings.
    other = rig.store.database.path.parent / "second"
    other.mkdir()
    (other / "requirements.txt").write_text("Django==2.2.0\n", encoding="utf-8")
    rig.registry.add("Second", str(other))
    new_alarms = rig.service.rematch()

    assert len(new_alarms) == 2
    assert all("Second" in alarm.worst_issue.title for alarm in new_alarms)
    assert shop_ids.isdisjoint({fid for alarm in new_alarms for fid in alarm.finding_ids})


def test_general_items_never_alarm(rig: Rig) -> None:
    report = rig.service.refresh()                  # no projects at all

    assert report.alarms == ()
    assert rig.toast.alarms == [] and rig.sound.alarms == []
    assert {s.relevance for s in rig.store.items()} == {Relevance.GENERAL}


def test_fixed_version_does_not_alarm(rig: Rig) -> None:
    rig.registry.add("Patched", str(PATCHED_SHOP))
    rig.service.refresh()
    assert rig.toast.alarms == []


def test_possible_match_never_alarms(rig: Rig) -> None:
    rig.registry.add("Toolbox", str(FIXTURES / "projects" / "toolbox"))

    rig.service.refresh()

    assert [s.item.cve_ids for s in rig.store.items([Relevance.POSSIBLE])] == [("CVE-2099-1111",)]
    assert rig.toast.alarms == [] and rig.sound.alarms == []


def test_affecting_item_that_is_neither_exploited_nor_critical_is_silent(rig: Rig, tmp_path: Path) -> None:
    # lodash 4.17.15: the fixture advisory is HIGH, and the news item is not from KEV.
    project = tmp_path / "frontend"
    project.mkdir()
    (project / "package-lock.json").write_text(
        (OLD_SHOP / "frontend" / "package-lock.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    rig.registry.add("Frontend", str(project))
    feed = (
        '<rss version="2.0"><channel><item><title>lodash prototype pollution CVE-2020-8203</title>'
        "<link>https://news.example.org/lodash</link></item></channel></rss>"
    )
    rig.fetcher.answers[NEWS_URL] = feed.encode()

    rig.service.refresh()

    (stored,) = rig.store.items([Relevance.AFFECTS_YOU])
    assert stored.matches[0].severity is Severity.HIGH
    assert rig.toast.alarms == [] and rig.sound.alarms == []


def test_critical_advisory_alarms_even_when_the_item_is_not_from_kev(rig: Rig) -> None:
    rig.registry.add("Shop", str(OLD_SHOP))
    del rig.fetcher.answers[CisaKevSource.URL]

    rig.service.refresh()

    (alarm,) = rig.toast.alarms
    assert alarm.level is AlarmLevel.CRITICAL
    assert "CVE-2019-14234" in alarm.worst_issue.title
