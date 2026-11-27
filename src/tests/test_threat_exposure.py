"""Read is not the same as fixed: what a project is exposed to, and the ways out."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, SqliteSeenFindingStore
from oranovix_guardian.core.language_manager import LanguageManager
from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.threat_intel.exposure import ExposureReport
from oranovix_guardian.threat_intel.hub import CheckState, ThreatIntelHub
from oranovix_guardian.threat_intel.models import AcceptedRisk, FeedItem, ProjectMatch, Relevance, StoredItem
from oranovix_guardian.threat_intel.projects import Project
from oranovix_guardian.threat_intel.relevance import RelevanceMatcher
from oranovix_guardian.threat_intel.settings import ThreatFeedSettings
from oranovix_guardian.threat_intel.sources import CisaKevSource, SourceConfig, SourceKind
from oranovix_guardian.threat_intel.store import FeedDatabase

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURES = Path(__file__).parent / "fixtures"
TRANSLATIONS = AppPaths.resource("translations")
KEV_ONLY = (SourceConfig("CISA KEV", CisaKevSource.URL, "en", True, SourceKind.KEV),)
DJANGO_CVE = "CVE-2019-14234"           # fixed in Django 2.2.4
DOT = "  ·  "
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class Rig:
    """A hub on temporary files, with a project whose pin can be changed."""

    def __init__(self, tmp_path: Path, osv_db: OSVDatabase, enabled: bool = True) -> None:
        self.channel = RecordingChannel()
        self.feed = FakeFetcher({CisaKevSource.URL: (FIXTURES / "feeds" / "kev.json").read_bytes()})
        settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
        settings.update(enabled=enabled, asked=True, sources=KEV_ONLY)
        self.hub = ThreatIntelHub(
            dispatch=lambda fn: fn(),
            alarm_center=AlarmCenter(
                store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")), channels=[self.channel],
            ),
            database=FeedDatabase(str(tmp_path / "feed.db")), settings=settings,
            fetcher=self.feed, uptime_fetcher=FakeFetcher(),
            matcher=RelevanceMatcher(osv_db), spawn=lambda work: work(),
        )
        self.folder = tmp_path / "shop"
        self.folder.mkdir()
        self.pin("2.2.0")
        self.hub.registry.add("Shop", str(self.folder))

    def pin(self, version: str) -> None:
        (self.folder / "requirements.txt").write_text(f"Django=={version}\n", encoding="utf-8")

    def affecting(self) -> StoredItem:
        (item,) = self.hub.store.items([Relevance.AFFECTS_YOU])
        return item

    def row_text(self) -> str:
        from oranovix_guardian.gui.pages.projects_page import ProjectsPage

        return ProjectsPage.feed_text(self.hub.project_rows()[0])[0]

    def headline(self) -> str:
        return self.hub.digest(None).headline


@pytest.fixture
def rig(tmp_path: Path, osv_db: OSVDatabase) -> Rig:
    rig = Rig(tmp_path, osv_db)
    rig.hub.refresh_now()
    return rig


@pytest.fixture(autouse=True)
def english() -> None:
    LanguageManager().set_language("en")


# ---------------------------------------------------------------------------
# Reading an item changes the notifications, not the exposure
# ---------------------------------------------------------------------------

def test_marking_the_item_read_keeps_the_project_exposed(rig: Rig) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    assert rig.hub.state().unread_for_you == 1
    rig.hub.store.mark_read([rig.affecting().id])

    row = rig.hub.project_rows()[0]
    assert rig.hub.state().unread_for_you == 0                      # the badge is about news
    assert row.affecting == 1
    assert ProjectsPage.feed_text(row) == ("1 affect it", "critical")


def test_mark_all_read_keeps_the_exposed_project_in_the_digest(rig: Rig) -> None:
    rig.hub.store.mark_all_read()

    later = datetime.now(timezone.utc) + timedelta(days=1)          # nothing is new any more
    digest = rig.hub.digest(later)

    assert digest.new_count == 0 and digest.exposed_count == 1
    assert digest.headline == "Nothing new since your last visit." + DOT + "1 of your projects is exposed"
    assert "- Shop: 1 item(s) affect it" in digest.text.splitlines()


def test_read_affecting_item_stays_in_the_for_you_tab(rig: Rig) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    rig.hub.store.mark_all_read()

    for show_read in (True, False):
        listed = rig.hub.items(for_you=True, show_read=show_read)
        assert [s.item.cve_ids for s in listed] == [(DJANGO_CVE,)]
        assert listed[0].read is True
        assert rig.hub.item_count(for_you=True, show_read=show_read) == 1
    assert ThreatFeedPage.match_lines(rig.affecting()) == [
        "Shop: Django 2.2.0 (CVE-2019-14234)  →  fixed in 2.2.4"
    ]


def test_show_read_switch_hides_only_read_guesses(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db)
    shutil.copytree(FIXTURES / "projects" / "old_shop", tmp_path / "old_shop")
    rig.hub.registry.add("Old", str(tmp_path / "old_shop"))         # brings a guess (lodash gateway)
    rig.hub.refresh_now()
    assert {s.relevance for s in rig.hub.items(for_you=True)} == {Relevance.AFFECTS_YOU, Relevance.POSSIBLE}

    rig.hub.store.mark_all_read()

    assert len(rig.hub.items(for_you=True, show_read=True)) == 2
    hidden = rig.hub.items(for_you=True, show_read=False)
    assert [s.relevance for s in hidden] == [Relevance.AFFECTS_YOU]
    assert rig.hub.item_count(for_you=True, show_read=False) == 1


# ---------------------------------------------------------------------------
# Way out 1: the dependency is upgraded
# ---------------------------------------------------------------------------

def test_upgrading_the_pin_clears_the_project_at_the_next_refresh(rig: Rig) -> None:
    assert rig.row_text() == "1 affect it"

    rig.pin("2.2.4")
    assert rig.row_text() == "1 affect it"          # nothing has looked at the manifest yet

    rig.hub.refresh_now()

    assert rig.row_text() == "Nothing"
    assert rig.hub.exposure().exposed == ()
    assert rig.headline().endswith("none of your projects is exposed")
    assert rig.hub.items(for_you=True) == []


def test_a_scan_is_a_check_too(rig: Rig) -> None:
    requests = len(rig.feed.requests)
    rig.pin("2.2.4")

    rig.hub.recheck_async()                         # what the app calls when a scan has finished

    assert rig.row_text() == "Nothing"
    assert len(rig.feed.requests) == requests       # without the network


def test_downgrading_again_exposes_the_project_again_without_a_second_alarm(rig: Rig) -> None:
    assert len(rig.channel.alarms) == 1
    rig.pin("2.2.4")
    rig.hub.refresh_now()
    rig.pin("2.2.0")
    rig.hub.refresh_now()

    assert rig.row_text() == "1 affect it"
    assert len(rig.channel.alarms) == 1


# ---------------------------------------------------------------------------
# Way out 2: the project is removed
# ---------------------------------------------------------------------------

def test_removing_the_project_ends_the_exposure_and_drops_its_notes(rig: Rig) -> None:
    rig.hub.accept_risk(rig.affecting().id, "legacy system")

    rig.hub.remove_project("Shop")

    assert rig.hub.project_rows() == [] and rig.hub.exposure().projects == ()
    assert rig.hub.accepted_risks() == {}
    assert rig.hub.digest(None).exposed_count == 0


# ---------------------------------------------------------------------------
# Way out 3: the risk is accepted, with a reason
# ---------------------------------------------------------------------------

def test_accepted_risk_is_shown_as_accepted(rig: Rig) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    item = rig.affecting()
    (note,) = rig.hub.accept_risk(item.id, "  internal tool,\n not reachable  ")

    assert note.reason == "internal tool, not reachable"
    row = rig.hub.project_rows()[0]
    assert (row.affecting, row.accepted) == (0, 1)
    assert ProjectsPage.feed_text(row) == ("1 accepted", "text3")       # grey, and not "Nothing"
    assert rig.hub.digest(None).exposed_count == 0
    assert "- Shop: 1 accepted" in rig.hub.digest(None).text.splitlines()

    risks = rig.hub.accepted_risks()
    assert ThreatFeedPage.match_lines(item, risks=risks) == []
    assert ThreatFeedPage.accepted_lines(item, risks) == [
        "Shop: Django 2.2.0 (CVE-2019-14234)  →  fixed in 2.2.4" + DOT
        + "risk accepted: internal tool, not reachable"
    ]
    assert [s.id for s in rig.hub.items(for_you=True)] == [item.id]      # still listed


def test_accepted_risk_does_not_alarm_again(rig: Rig) -> None:
    assert len(rig.channel.alarms) == 1
    rig.hub.accept_risk(rig.affecting().id, "legacy system")

    rig.hub.refresh_now()
    rig.hub.recheck_async()

    assert len(rig.channel.alarms) == 1


def test_risk_accepted_before_the_alarm_is_never_announced(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db)
    rig.hub.registry.remove("Shop")
    rig.hub.refresh_now()                           # the item is stored, no project yet
    item_id = FeedItem.make_id("CISA KEV", DJANGO_CVE)
    rig.hub.store.accept_risk(item_id, str(rig.folder), "decided beforehand")

    rig.hub.add_project("Shop", str(rig.folder))

    assert rig.hub.project_rows()[0].accepted == 1
    assert rig.channel.alarms == []


def test_accepting_needs_a_reason(rig: Rig) -> None:
    from oranovix_guardian.gui.threat_feed_dialogs import RiskDialog

    with pytest.raises(ValueError, match="reason"):
        rig.hub.accept_risk(rig.affecting().id, "   ")
    assert rig.hub.accepted_risks() == {}
    assert RiskDialog.valid_reason(" \n ") == ""
    assert len(RiskDialog.valid_reason("x" * 500)) == 200


def test_withdrawing_the_acceptance_exposes_the_project_again(rig: Rig) -> None:
    item = rig.affecting()
    rig.hub.accept_risk(item.id, "legacy system")

    rig.hub.withdraw_risk(item.id)

    assert rig.row_text() == "1 affect it"
    assert len(rig.channel.alarms) == 1             # it was announced once already


def test_accepted_risk_ends_with_the_upgrade(rig: Rig) -> None:
    rig.hub.accept_risk(rig.affecting().id, "legacy system")
    rig.pin("2.2.4")
    rig.hub.refresh_now()

    row = rig.hub.project_rows()[0]
    assert (row.affecting, row.accepted) == (0, 0) and rig.row_text() == "Nothing"


# ---------------------------------------------------------------------------
# "Nothing" needs a successful check
# ---------------------------------------------------------------------------

def test_nothing_is_said_only_after_a_successful_check(tmp_path: Path, osv_db: OSVDatabase) -> None:
    rig = Rig(tmp_path, osv_db)
    rig.pin("2.2.4")
    assert rig.hub.state().check is CheckState.NEVER
    assert rig.row_text() == "Not checked"
    assert "exposed" not in rig.headline()          # neither exposed nor clear is claimed

    rig.hub.refresh_now()
    assert rig.row_text() == "Nothing"

    rig.feed.answers.clear()                        # the next refresh reaches no source
    rig.hub.refresh_now()
    assert rig.row_text() == "Not checked"


def test_switched_off_feed_still_shows_what_is_known(rig: Rig) -> None:
    rig.hub.set_enabled(False)
    rig.hub.shutdown()

    assert rig.row_text() == "1 affect it"
    assert rig.headline() == "Not checked: the Threat Feed is switched off." + DOT + "1 of your projects is exposed"


# ---------------------------------------------------------------------------
# ExposureReport and the panel
# ---------------------------------------------------------------------------

SHOP = Project("Shop", "/srv/shop")
BLOG = Project("Blog", "/srv/blog")


def match(project: Project, severity: Severity, fix: str = "", package: str = "Django") -> ProjectMatch:
    return ProjectMatch(
        project=project.name, project_path=project.path, package=package, ecosystem="PyPI",
        version="2.2.0", advisory_id="CVE-2031-0001", severity=severity, fixed_version=fix,
    )


def stored(key: str, title: str, matches: tuple, exploited: bool = False, read: bool = False,
           published: Optional[datetime] = NOW) -> StoredItem:
    item = FeedItem(id=key, source="CISA KEV", title=title, url=f"https://example.org/{key}",
                    published=published, is_known_exploited=exploited)
    return StoredItem(item, NOW, read, Relevance.AFFECTS_YOU, matches)


def test_report_orders_the_worst_item_first_and_ignores_the_read_flag() -> None:
    items = [
        stored("a", "Critical but not exploited", (match(SHOP, Severity.CRITICAL),), read=True),
        stored("b", "Exploited, high", (match(SHOP, Severity.HIGH, fix="2.2.4"),), exploited=True, read=True),
        stored("c", "Medium", (match(SHOP, Severity.MEDIUM, fix="3.0.0"),)),
    ]

    report = ExposureReport.build(items, [SHOP, BLOG])

    shop = report.of(SHOP)
    assert [entry.stored.id for entry in shop.open] == ["b", "a", "c"]
    assert shop.worst is not None and shop.worst.stored.id == "b" and shop.first_fix == "2.2.4"
    assert [entry.project.name for entry in report.exposed] == ["Shop"]
    assert report.of(BLOG).exposed is False


def test_report_separates_accepted_items_per_project() -> None:
    item = stored("a", "Hits both", (match(SHOP, Severity.HIGH), match(BLOG, Severity.HIGH)))
    risk = AcceptedRisk("a", SHOP.path, "legacy")

    report = ExposureReport.build([item], [SHOP, BLOG], {risk.key: risk})

    assert report.of(SHOP).open == () and len(report.of(SHOP).accepted) == 1
    assert len(report.of(BLOG).open) == 1
    assert [entry.project.name for entry in report.exposed] == ["Blog"]


def test_guesses_and_unknown_projects_do_not_expose() -> None:
    guess = ProjectMatch("Shop", SHOP.path, "lodash", "npm", "4.17.21")
    gone = match(Project("Gone", "/srv/gone"), Severity.CRITICAL)
    report = ExposureReport.build([stored("a", "Guess", (guess, gone))], [SHOP])
    assert report.exposed == ()


def test_exposed_projects_panel_names_the_worst_item_and_the_first_fix() -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    items = [
        stored("b", "CVE-2031-0001: Exploited thing", (match(SHOP, Severity.HIGH, fix="2.2.4"),), exploited=True),
        stored("c", "Medium", (match(SHOP, Severity.MEDIUM, fix="3.0.0"),)),
        stored("d", "No fix yet", (match(BLOG, Severity.HIGH, package="oldlib"),)),
    ]

    lines = ProjectsPage.exposed_lines(ExposureReport.build(items, [SHOP, BLOG, Project("Fine", "/srv/fine")]))

    assert lines == [
        "Shop: CVE-2031-0001: Exploited thing  (Django 2.2.0, fixed in 2.2.4)  and 1 more",
        "Blog: No fix yet  (oldlib 2.2.0, no fixed version known)",
    ]


# ---------------------------------------------------------------------------
# Texts
# ---------------------------------------------------------------------------

NEW_KEYS = [
    "digest_headline", "digest_exposed", "digest_exposed_one", "digest_exposed_none", "digest_accepted",
    "tf_show_read", "tf_accept_risk", "tf_withdraw_risk", "tf_risk_title", "tf_risk_text",
    "tf_risk_reason", "tf_risk_reason_missing", "tf_risk_cancel", "tf_risk_accepted",
    "proj_feed_accepted", "proj_exposed_title", "proj_exposed_line", "proj_exposed_fix",
    "proj_exposed_no_fix", "proj_exposed_more",
]


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_exposure_texts_exist_in_every_language(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    assert [key for key in NEW_KEYS if not texts.get(key)] == []
    assert "{affecting}" not in texts["digest_headline"]            # no unread based number
    assert "{new}" in texts["digest_headline"] and "{count}" in texts["digest_exposed"]


@pytest.mark.parametrize("language", ["de", "ar"])
def test_headline_has_both_parts_in_other_languages(rig: Rig, language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    lm = LanguageManager()
    lm.set_language(language)
    try:
        headline = rig.headline()
    finally:
        lm.set_language("en")
    assert headline.endswith(DOT + texts["digest_exposed_one"])
    assert headline.startswith(texts["digest_headline"].split("{new}")[0])
