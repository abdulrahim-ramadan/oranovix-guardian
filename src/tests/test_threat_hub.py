"""ThreatIntelHub: first-run answer, background refresh, project rows. No network, no Tk."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import closing
from datetime import timezone
from pathlib import Path
from typing import Callable, List

import pytest

from oranovix_guardian.core.alarm_center import AlarmCenter, SqliteSeenFindingStore
from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.threat_intel.fetcher import FetchError, FetchResponse
from oranovix_guardian.threat_intel.hub import CheckState, HubState, ThreatIntelHub, in_thread
from oranovix_guardian.threat_intel.models import Relevance
from oranovix_guardian.threat_intel.projects import ScanSummaryLookup
from oranovix_guardian.threat_intel.relevance import RelevanceMatcher
from oranovix_guardian.threat_intel.settings import ThreatFeedSettings
from oranovix_guardian.threat_intel.sources import CisaKevSource, SourceConfig, SourceKind
from oranovix_guardian.threat_intel.store import FeedDatabase

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURES = Path(__file__).parent / "fixtures"
OLD_SHOP = FIXTURES / "projects" / "old_shop"
SHOP_URL = "https://shop.example.org/"
KEV_ONLY = (SourceConfig("CISA KEV", CisaKevSource.URL, "en", True, SourceKind.KEV),)


class Rig:
    def __init__(self, tmp_path: Path, osv_db: OSVDatabase, threaded: bool = False) -> None:
        self.states: List[HubState] = []
        self.refreshed = threading.Event()
        self.feed = FakeFetcher({CisaKevSource.URL: (FIXTURES / "feeds" / "kev.json").read_bytes()})
        self.sites = FakeFetcher({SHOP_URL: FetchResponse(status=200, elapsed_ms=87)})
        self.settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
        self.settings.update(sources=KEV_ONLY)
        self.history = str(tmp_path / "scan_history.db")
        self.hub = ThreatIntelHub(
            dispatch=self._dispatch,
            alarm_center=AlarmCenter(store=SqliteSeenFindingStore(str(tmp_path / "alarms.db"))),
            database=FeedDatabase(str(tmp_path / "feed.db")),
            settings=self.settings,
            fetcher=self.feed,
            uptime_fetcher=self.sites,
            matcher=RelevanceMatcher(osv_db),
            scan_lookup=ScanSummaryLookup(self.history),
            spawn=in_thread if threaded else (lambda work: work()),
        )
        self.hub.add_listener(self._listen)

    def _dispatch(self, fn: Callable[[], None]) -> None:
        fn()

    def _listen(self, state: HubState) -> None:
        self.states.append(state)
        if state.last_report is not None and not state.refreshing:
            self.refreshed.set()


@pytest.fixture
def rig(tmp_path: Path, osv_db: OSVDatabase) -> Rig:
    return Rig(tmp_path, osv_db)


def test_feed_is_off_and_unanswered_at_first(rig: Rig) -> None:
    state = rig.hub.state()
    assert state.enabled is False and state.asked is False
    assert state.unread_for_you == 0 and state.last_success is None
    assert rig.hub.hosts() == ["www.cisa.gov"]


def test_declining_the_first_run_dialog_keeps_it_off_and_asks_no_more(rig: Rig) -> None:
    rig.hub.answer_first_run(False)

    state = rig.hub.state()
    assert state.enabled is False and state.asked is True
    assert rig.hub.refresh_now() is not None and rig.feed.requests == []


def test_start_does_not_contact_feeds_while_off(rig: Rig) -> None:
    rig.hub.start()
    rig.hub.shutdown()
    assert rig.feed.requests == []


def test_refresh_in_the_background_notifies_when_done(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db, threaded=True)
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))

    assert rig.hub.refresh_async() is True
    assert rig.refreshed.wait(5)

    assert any(state.refreshing for state in rig.states)            # the page saw "refreshing"
    final = rig.states[-1]
    assert final.refreshing is False and final.last_report is not None
    assert len(final.last_report.new_items) == 2 and final.last_report.background_items == 1
    assert final.unread_for_you == 2            # Django is confirmed, the lodash gateway is a guess
    assert final.last_success is not None and final.last_success.tzinfo is timezone.utc
    assert rig.feed.urls == [CisaKevSource.URL]


def test_unread_for_you_count_drops_when_marked_read(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))
    rig.hub.refresh_now()

    confirmed, possible = rig.hub.items(for_you=True)
    assert (confirmed.relevance, possible.relevance) == (Relevance.AFFECTS_YOU, Relevance.POSSIBLE)
    rig.hub.store.mark_read([confirmed.id])

    assert rig.hub.state().unread_for_you == 1
    assert len(rig.hub.items(for_you=False)) == 3


def test_adding_a_project_matches_cached_items_and_checks_its_site(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.refresh_now()
    assert rig.hub.items(for_you=True) == []
    feed_requests = len(rig.feed.requests)

    rig.hub.add_project("Shop", str(OLD_SHOP), SHOP_URL)

    assert len(rig.hub.items(for_you=True)) == 2
    assert len(rig.feed.requests) == feed_requests                  # matched from the cache
    assert rig.sites.urls == [SHOP_URL]


def test_project_rows_join_scan_site_and_feed(rig: Rig) -> None:
    with closing(sqlite3.connect(rig.history)) as conn, conn:
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_date TEXT, target_path TEXT, "
            "total_issues INTEGER, critical_count INTEGER, high_count INTEGER, risk_score INTEGER)"
        )
        conn.execute(
            "INSERT INTO scans (scan_date, target_path, total_issues, critical_count, high_count, risk_score) "
            "VALUES ('2026-11-15T17:45:00', ?, 5, 1, 2, 80)", (str(OLD_SHOP),),
        )
    rig.settings.update(enabled=True, asked=True)
    rig.hub.add_project("Shop", str(OLD_SHOP), SHOP_URL)
    rig.hub.add_project("Patched", str(FIXTURES / "projects" / "patched_shop"))
    rig.hub.refresh_now()

    patched, shop = rig.hub.project_rows()

    assert shop.project.name == "Shop"
    assert shop.scan is not None and (shop.scan.critical, shop.scan.high) == (1, 2)
    assert shop.check is not None and shop.check.ok and shop.check.response_ms == 87
    assert shop.down_since is None
    assert shop.affecting == 1 and shop.packages == 5
    assert patched.scan is None and patched.check is None and patched.affecting == 0


def test_site_down_event_reaches_the_listeners(rig: Rig) -> None:
    rig.hub.add_project("Shop", str(OLD_SHOP), SHOP_URL)
    rig.sites.answers[SHOP_URL] = FetchError("connection refused")

    for _ in range(3):
        rig.hub.check_sites_now()

    events = [state.uptime_event for state in rig.states if state.uptime_event is not None]
    assert len(events) == 1 and events[0].project == "Shop"
    (row,) = rig.hub.project_rows()
    assert row.down_since is not None and row.check is not None and not row.check.ok


def test_removing_a_project_clears_its_matches_and_history(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.add_project("Shop", str(OLD_SHOP), SHOP_URL)
    rig.hub.refresh_now()

    rig.hub.remove_project("Shop")

    assert rig.hub.project_rows() == []
    assert rig.hub.items(for_you=True) == []
    assert rig.hub.uptime_store.history("Shop") == []


def test_digest_counts_what_is_new_since_the_last_visit(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))
    rig.hub.refresh_now()

    digest = rig.hub.digest(rig.hub.store.last_visit())

    assert digest.headline == "Since your last visit: 2 new  ·  1 of your projects is exposed"


def test_interval_and_sources_are_saved(rig: Rig) -> None:
    assert rig.hub.set_interval("120") == 120
    assert rig.hub.set_interval("1") == 15
    rig.hub.set_sources(KEV_ONLY + (SourceConfig("Extra", "https://extra.example/feed"),))

    config = rig.hub.config()
    assert config.interval_minutes == 15
    assert [source.name for source in config.sources] == ["CISA KEV", "Extra"]
    assert rig.hub.hosts() == ["extra.example", "www.cisa.gov"]


def test_broken_listener_is_dropped(rig: Rig) -> None:
    def broken(state: HubState) -> None:
        raise RuntimeError("page was destroyed")

    rig.hub.add_listener(broken)
    rig.hub.notify()
    rig.hub.notify()
    assert len(rig.states) == 2


# ---------------------------------------------------------------------------
# The digest line says when the projects were not checked
# ---------------------------------------------------------------------------

def test_digest_line_while_the_feed_is_off(rig: Rig) -> None:
    rig.hub.registry.add("Shop", str(OLD_SHOP))

    digest = rig.hub.digest(None)

    assert digest.headline == "Not checked: the Threat Feed is switched off."
    assert rig.hub.project_rows()[0].checked is False


def test_digest_line_before_the_first_download_and_after_it(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))
    assert rig.hub.digest(None).headline == "Not checked yet: the feed has not been downloaded."

    rig.hub.refresh_now()

    assert rig.hub.state().check is CheckState.CHECKED
    assert rig.hub.digest(None).headline.startswith("Since your last visit:")
    assert rig.hub.project_rows()[0].checked is True


def test_digest_line_when_every_source_failed(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))
    rig.hub.refresh_now()
    rig.feed.answers.clear()

    rig.hub.refresh_now()

    assert rig.hub.state().check is CheckState.UNREACHABLE
    assert rig.hub.digest(None).headline == (
        "Not checked: no source could be reached. Saved items are shown.  ·  1 of your projects is exposed"
    )


def test_digest_line_without_projects(rig: Rig) -> None:
    rig.settings.update(enabled=True, asked=True)
    rig.hub.refresh_now()

    assert rig.hub.digest(None).headline == "Not checked: add your projects on the My Projects page."


def test_digest_line_without_the_vulnerability_database(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, OSVDatabase(str(tmp_path / "missing.db")))
    rig.settings.update(enabled=True, asked=True)
    rig.hub.registry.add("Shop", str(OLD_SHOP))

    rig.hub.refresh_now()

    assert rig.hub.items(for_you=True)[0].relevance is Relevance.POSSIBLE      # guesses only
    assert rig.hub.digest(None).headline == "Not checked: update the vulnerability database in Settings."
    assert rig.hub.project_rows()[0].checked is False


# ---------------------------------------------------------------------------
# Partly checked: the CISA catalog failed, the news feeds did not
# ---------------------------------------------------------------------------

NEWS_URL = "https://news.example.org/feed/"
WITH_NEWS = KEV_ONLY + (SourceConfig("Example News", NEWS_URL, "en"),)
PARTLY = "Partly checked: CISA KEV could not be read."


def news_rig(tmp_path: Path, osv_db: OSVDatabase) -> Rig:
    rig = Rig(tmp_path, osv_db)
    rig.settings.update(enabled=True, asked=True, sources=WITH_NEWS)
    rig.feed.answers[NEWS_URL] = (FIXTURES / "feeds" / "news_rss.xml").read_bytes()
    rig.hub.registry.add("Patched", str(FIXTURES / "projects" / "patched_shop"))
    return rig


def test_failed_catalog_means_partly_checked(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = news_rig(tmp_path, osv_db)
    rig.feed.answers[CisaKevSource.URL] = FetchError("URLError: timed out")

    report = rig.hub.refresh_now()

    assert report is not None and report.sources_ok == 1 and not report.offline
    state = rig.hub.state()
    assert state.check is CheckState.PARTIAL and state.failed_catalogs == ("CISA KEV",)
    assert rig.hub.digest(None).headline == PARTLY
    assert rig.hub.digest(None).checked is False
    assert rig.hub.project_rows()[0].checked is False


def test_failed_news_source_still_counts_as_checked(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = news_rig(tmp_path, osv_db)
    del rig.feed.answers[NEWS_URL]

    report = rig.hub.refresh_now()

    assert report is not None and len(report.failures) == 1
    state = rig.hub.state()
    assert state.check is CheckState.CHECKED and state.failed_catalogs == ()
    assert rig.hub.digest(None).headline.startswith("Since your last visit:")


def test_partly_checked_ends_when_the_catalog_is_read_again(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = news_rig(tmp_path, osv_db)
    catalog = rig.feed.answers[CisaKevSource.URL]
    rig.hub.refresh_now()
    rig.feed.answers[CisaKevSource.URL] = FetchError("URLError: timed out")
    rig.hub.refresh_now()
    assert rig.hub.state().check is CheckState.PARTIAL

    rig.feed.answers[CisaKevSource.URL] = catalog
    rig.hub.refresh_now()

    assert rig.hub.state().check is CheckState.CHECKED


def test_partly_checked_survives_a_restart(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = news_rig(tmp_path, osv_db)
    rig.feed.answers[CisaKevSource.URL] = FetchError("URLError: timed out")
    rig.hub.refresh_now()

    restarted = Rig(tmp_path, osv_db)           # same files, no refresh in this session

    assert restarted.hub.state().last_report is None
    assert restarted.hub.digest(None).headline == PARTLY
