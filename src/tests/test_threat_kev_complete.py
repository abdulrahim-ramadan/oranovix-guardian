"""The whole CISA catalog is kept and matched, without flooding the user.

A catalog of 1500 entries is built in memory; the fetcher is a fake.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.scanner_engine.deps.versions import Ecosystem
from oranovix_guardian.threat_intel.digest import DigestBuilder
from oranovix_guardian.threat_intel.hub import ThreatIntelHub
from oranovix_guardian.threat_intel.models import FeedItem, Relevance
from oranovix_guardian.threat_intel.projects import ProjectRegistry
from oranovix_guardian.threat_intel.relevance import RelevanceMatcher
from oranovix_guardian.threat_intel.service import ThreatFeedService
from oranovix_guardian.threat_intel.settings import ThreatFeedSettings
from oranovix_guardian.threat_intel.sources import CisaKevSource, DownloadedFeedSource, SourceConfig, SourceKind
from oranovix_guardian.threat_intel.store import FeedDatabase, ThreatStore

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURES = Path(__file__).parent / "fixtures"
OLD_SHOP = FIXTURES / "projects" / "old_shop"           # Django==2.2.0
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
KEV_ONLY = (SourceConfig("CISA KEV", CisaKevSource.URL, "en", True, SourceKind.KEV),)
DJANGO_CVE = "CVE-2019-14234"                           # alias of a fixture OSV record for Django
SIZE = 1500
RECENT = 5                                              # entries added within the last 30 days


def entry(cve: str, added: datetime, vendor: str = "Example Corp", product: str = "Appliance") -> Dict[str, str]:
    return {
        "cveID": cve, "vendorProject": vendor, "product": product,
        "vulnerabilityName": f"{vendor} {product} Vulnerability",
        "dateAdded": added.strftime("%Y-%m-%d"), "shortDescription": "Exploited in the wild.",
        "knownRansomwareCampaignUse": "Unknown",
    }


def catalog(now: datetime, oldest: Sequence[Dict[str, str]] = (), size: int = SIZE) -> bytes:
    """*size* entries. *oldest* come first in time; the last ``RECENT`` are a few days old."""
    start = now - timedelta(days=5 * 365)
    entries: List[Dict[str, str]] = []
    for number, old in enumerate(oldest):
        entries.append({**old, "dateAdded": (start + timedelta(days=number)).strftime("%Y-%m-%d")})
    filler = size - len(entries)
    for number in range(filler):
        recent = filler - number <= RECENT
        added = now - timedelta(days=filler - number) if recent else start + timedelta(days=30 + number)
        entries.append(entry(f"CVE-2030-{10000 + number}", added))
    return json.dumps({"vulnerabilities": entries}).encode()


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class Rig:
    def __init__(self, tmp_path: Path, osv_db: OSVDatabase, body: bytes) -> None:
        self.channel = RecordingChannel()
        self.fetcher = FakeFetcher({CisaKevSource.URL: body})
        database = FeedDatabase(str(tmp_path / "feed.db"))
        self.store = ThreatStore(database, clock=lambda: NOW)
        self.registry = ProjectRegistry(database)
        settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
        settings.update(enabled=True, asked=True, sources=KEV_ONLY)
        self.service = ThreatFeedService(
            self.store, self.registry, settings, fetcher=self.fetcher,
            matcher=RelevanceMatcher(osv_db),
            alarm_center=AlarmCenter(
                store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")), channels=[self.channel],
            ),
            clock=lambda: NOW,
        )


@pytest.fixture
def oldest_hits(tmp_path: Path, osv_db: OSVDatabase) -> Rig:
    """1500 entries; the only one that matches a project is the oldest."""
    old = entry(DJANGO_CVE, NOW, "Django", "Django")
    rig = Rig(tmp_path, osv_db, catalog(NOW, [old]))
    rig.registry.add("Shop", str(OLD_SHOP))
    return rig


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------

def test_kev_source_keeps_every_entry_and_news_stay_capped() -> None:
    items = CisaKevSource(clock=lambda: NOW).fetch(FakeFetcher({CisaKevSource.URL: catalog(NOW)}))

    assert len(items) == SIZE
    assert CisaKevSource.MAX_ITEMS == 5000 and DownloadedFeedSource.MAX_ITEMS == 200


def test_kev_source_is_capped_at_5000() -> None:
    body = catalog(NOW, size=5100)
    items = CisaKevSource(clock=lambda: NOW).fetch(FakeFetcher({CisaKevSource.URL: body}))

    assert len(items) == 5000
    newest = max(item.published for item in items if item.published)
    assert items[0].published == newest                 # the oldest are the ones dropped


# ---------------------------------------------------------------------------
# The oldest entry still counts
# ---------------------------------------------------------------------------

def test_oldest_entry_of_the_catalog_affects_the_project(oldest_hits: Rig) -> None:
    oldest_hits.service.refresh()

    assert oldest_hits.store.count() == SIZE
    (affecting,) = oldest_hits.store.items([Relevance.AFFECTS_YOU])
    assert affecting.item.cve_ids == (DJANGO_CVE,)
    assert affecting.item.published is not None and affecting.item.published < NOW - timedelta(days=1800)
    assert affecting.matches[0].project == "Shop" and affecting.matches[0].package == "Django"
    assert affecting.matches[0].fixed_version == "2.2.4"


def test_first_refresh_does_not_flood(oldest_hits: Rig) -> None:
    report = oldest_hits.service.refresh()

    # New: the entries of the last 30 days, and the old one that hits the project.
    assert len(report.new_items) == RECENT + 1
    assert report.background_items == SIZE - RECENT - 1
    assert oldest_hits.store.unread_for_you() == 1
    assert len(oldest_hits.store.new_since(None)) == RECENT + 1

    digest = DigestBuilder.build(oldest_hits.store.items(limit=100000), oldest_hits.registry.list(), None)
    assert digest.headline == f"Since your last visit: {RECENT + 1} new  ·  1 of your projects is exposed"

    (alarm,) = oldest_hits.channel.alarms
    assert alarm.level is AlarmLevel.CRITICAL and DJANGO_CVE in alarm.worst_issue.title
    assert oldest_hits.service.refresh().alarms == ()   # and not again


def test_background_items_stay_in_the_background_on_later_refreshes(oldest_hits: Rig) -> None:
    oldest_hits.service.refresh()
    again = oldest_hits.service.refresh()

    assert again.new_items == () and again.background_items == 0
    assert oldest_hits.store.unread_for_you() == 1


def test_old_entry_becomes_news_when_a_project_is_added_later(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db, catalog(NOW, [entry(DJANGO_CVE, NOW, "Django", "Django")]))
    rig.service.refresh()
    assert rig.store.unread_for_you() == 0

    rig.registry.add("Shop", str(OLD_SHOP))
    alarms = rig.service.rematch()

    assert rig.store.unread_for_you() == 1 and len(alarms) == 1


# ---------------------------------------------------------------------------
# Many alarms at once
# ---------------------------------------------------------------------------

def flood_records(count: int) -> List[Dict[str, Any]]:
    return [
        {
            "id": f"GHSA-fl00-d000-{number:04d}", "aliases": [f"CVE-2031-{1000 + number}"],
            "summary": "Remote code execution in flood-lib",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "flood-lib"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        for number in range(count)
    ]


def flood_rig(tmp_path: Path, osv_records: Dict[Ecosystem, List[Dict[str, Any]]], count: int) -> Rig:
    records = dict(osv_records)
    records[Ecosystem.PYPI] = list(records[Ecosystem.PYPI]) + flood_records(count)
    database = OSVDatabase(str(tmp_path / "osv.db"))
    database.import_records(records)

    project = tmp_path / "flooded"
    project.mkdir()
    (project / "requirements.txt").write_text("flood-lib==1.0.0\n", encoding="utf-8")
    old = [entry(f"CVE-2031-{1000 + number}", NOW, "Flood", "Flood Lib") for number in range(count)]
    rig = Rig(tmp_path, database, catalog(NOW, old))
    rig.registry.add("Flooded", str(project))
    return rig


def test_five_matching_entries_give_one_aggregated_alarm(
    tmp_path: Path, osv_records: Dict[Ecosystem, List[Dict[str, Any]]]
) -> None:
    rig = flood_rig(tmp_path, osv_records, 5)

    report = rig.service.refresh()

    assert len(rig.store.items([Relevance.AFFECTS_YOU])) == 5
    (alarm,) = rig.channel.alarms
    assert report.alarms == (alarm,)
    issue = alarm.worst_issue
    assert alarm.level is AlarmLevel.CRITICAL and issue.rule_id == "TF002"
    assert issue.title == "5 exploited vulnerabilities affect your projects"
    assert issue.description.count("Flooded: flood-lib 1.0.0 (CVE-2031-") == 3
    assert issue.description.endswith("and 2 more")

    assert rig.service.refresh().alarms == () and len(rig.channel.alarms) == 1


def test_three_matching_entries_still_alarm_one_by_one(
    tmp_path: Path, osv_records: Dict[Ecosystem, List[Dict[str, Any]]]
) -> None:
    rig = flood_rig(tmp_path, osv_records, 3)

    rig.service.refresh()

    assert len(rig.channel.alarms) == 3
    assert all(alarm.worst_issue.rule_id == "TF001" for alarm in rig.channel.alarms)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def news(key: str, published: Optional[datetime] = NOW) -> FeedItem:
    built = FeedItem.build("News", key, f"Headline {key}", f"https://example.org/{key}", published=published)
    assert built is not None
    return built


def test_background_items_are_not_unread_until_they_affect_a_project(tmp_path: Path) -> None:
    store = ThreatStore(FeedDatabase(str(tmp_path / "feed.db")), clock=lambda: NOW)
    old, fresh = news("old"), news("fresh")
    store.add([old, fresh], background={old.id})
    store.set_relevance({old.id: (Relevance.POSSIBLE, ()), fresh.id: (Relevance.POSSIBLE, ())})

    assert store.unread_for_you() == 1
    assert {s.id: s.background for s in store.items()} == {old.id: True, fresh.id: False}

    store.set_relevance({old.id: (Relevance.AFFECTS_YOU, ())})
    assert store.unread_for_you() == 2


def test_newest_first_ignores_the_relevance(tmp_path: Path) -> None:
    store = ThreatStore(FeedDatabase(str(tmp_path / "feed.db")), clock=lambda: NOW)
    old, fresh = news("old", NOW - timedelta(days=400)), news("fresh")
    store.add([old, fresh])
    store.set_relevance({old.id: (Relevance.AFFECTS_YOU, ())})

    assert [s.id for s in store.items()] == [old.id, fresh.id]
    assert [s.id for s in store.items(newest_first=True)] == [fresh.id, old.id]
    assert store.count() == 2 and store.count([Relevance.AFFECTS_YOU]) == 1


def test_feed_db_of_the_first_version_is_upgraded(tmp_path: Path) -> None:
    path = tmp_path / "feed.db"
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(
            "CREATE TABLE items (id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT NOT NULL, "
            "url TEXT NOT NULL, published TEXT, summary TEXT NOT NULL DEFAULT '', "
            "cve_ids TEXT NOT NULL DEFAULT '[]', packages TEXT NOT NULL DEFAULT '[]', "
            "known_exploited INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT '', "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, "
            "relevance TEXT NOT NULL DEFAULT 'general', matches TEXT NOT NULL DEFAULT '[]')"
        )
        conn.execute(
            "INSERT INTO items (id, source, title, url, first_seen, last_seen) "
            "VALUES ('a', 'News', 'Kept', 'https://example.org/a', "
            "'2026-11-01T00:00:00.000000', '2026-11-01T00:00:00.000000')"
        )

    store = ThreatStore(FeedDatabase(str(path)), clock=lambda: NOW)
    store.add([news("b")], background=set())

    assert [s.item.title for s in store.items(newest_first=True)] == ["Headline b", "Kept"]
    assert all(not s.background for s in store.items())


# ---------------------------------------------------------------------------
# Tabs of the page (through the hub)
# ---------------------------------------------------------------------------

def test_all_tab_pages_through_the_catalog_and_for_you_lists_the_old_hit(
    tmp_path: Path, osv_db: OSVDatabase
) -> None:
    now = datetime.now(timezone.utc)
    settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
    settings.update(enabled=True, asked=True, sources=KEV_ONLY)
    body = catalog(now, [entry(DJANGO_CVE, now, "Django", "Django")])
    hub = ThreatIntelHub(
        dispatch=lambda fn: fn(), alarm_center=AlarmCenter(channels=[]),
        database=FeedDatabase(str(tmp_path / "feed.db")), settings=settings,
        fetcher=FakeFetcher({CisaKevSource.URL: body}), uptime_fetcher=FakeFetcher(),
        matcher=RelevanceMatcher(osv_db), spawn=lambda work: work(),
    )
    hub.registry.add("Shop", str(OLD_SHOP))
    hub.refresh_now()

    everything = hub.items(for_you=False)
    assert len(everything) == hub.PAGE_SIZE == 200 and hub.item_count(for_you=False) == SIZE
    dates = [stored.item.published for stored in everything if stored.item.published]
    assert dates == sorted(dates, reverse=True)         # the newest 200
    assert DJANGO_CVE not in {cve for stored in everything for cve in stored.item.cve_ids}
    second_page = hub.items(for_you=False, offset=200)
    assert len(second_page) == 200 and {s.id for s in second_page}.isdisjoint(s.id for s in everything)
    assert max(d for d in (s.item.published for s in second_page) if d) <= min(dates)
    assert len(hub.items(for_you=False, offset=1400)) == 100    # the last page ends with the oldest

    (for_you,) = hub.items(for_you=True)
    assert for_you.item.cve_ids == (DJANGO_CVE,) and for_you.relevance is Relevance.AFFECTS_YOU
    assert hub.item_count(for_you=True) == 1
    assert hub.state().unread_for_you == 1
