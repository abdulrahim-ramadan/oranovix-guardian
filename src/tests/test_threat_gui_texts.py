"""Texts of the Threat Feed and My Projects pages. No window is opened."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.hub import CheckState, HubState, ProjectRow
from oranovix_guardian.threat_intel.models import FeedItem, ProjectMatch, Relevance, SourceHealth, StoredItem
from oranovix_guardian.threat_intel.projects import Project, ScanSummary
from oranovix_guardian.threat_intel.service import RefreshReport
from oranovix_guardian.threat_intel.sources import SourceConfig
from oranovix_guardian.threat_intel.uptime import UptimeCheck

ROOT = Path(__file__).resolve().parents[2]
TRANSLATIONS = AppPaths.resource("translations")
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
SOURCES = [
    ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "threat_feed_page.py",
    ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "projects_page.py",
    ROOT / "src" / "oranovix_guardian" / "gui" / "threat_feed_dialogs.py",
    ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "settings_page.py",
    ROOT / "src" / "oranovix_guardian" / "threat_intel" / "alarms.py",
    ROOT / "src" / "oranovix_guardian" / "threat_intel" / "uptime.py",
]
KEY = re.compile(r"""['"]((?:tf|proj|up|digest)_[a-z_]+)['"]""")


def used_keys() -> Set[str]:
    keys: Set[str] = {"nav_threat_feed", "nav_projects"}
    for path in SOURCES:
        keys.update(KEY.findall(path.read_text(encoding="utf-8")))
    keys.update(f"tf_tab_{tab}" for tab in ("for_you", "all", "sources"))
    keys.update(f"tf_badge_{relevance.value}" for relevance in Relevance)
    keys.update(check.text_key for check in CheckState if check is not CheckState.CHECKED)
    keys.update(f"digest_{name}" for name in (
        "headline", "exposed", "exposed_one", "exposed_none", "accepted", "nothing_new", "affecting", "possible", "other", "more",
        "exploited", "fix", "no_fix", "projects", "project_line", "project_clear",
    ))
    return {key for key in keys if not key.endswith("_")}


@pytest.fixture
def english() -> Iterator[LanguageManager]:
    lm = LanguageManager()
    before = lm.current_lang
    lm.set_language("en")
    yield lm
    lm.set_language(before)


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_every_text_exists_in_every_language(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    missing = sorted(key for key in used_keys() if not texts.get(key))
    assert missing == [], f"{language}: {missing}"


@pytest.mark.parametrize("language", ["de", "ar"])
def test_translations_keep_the_placeholders(language: str) -> None:
    english_texts = json.loads((TRANSLATIONS / "en.json").read_text(encoding="utf-8"))
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    placeholder = re.compile(r"\{[a-z_]+\}")
    for key in used_keys():
        assert set(placeholder.findall(texts[key])) == set(placeholder.findall(english_texts[key])), key


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_consent_dialog_names_every_host(language: str) -> None:
    from oranovix_guardian.gui.threat_feed_dialogs import FeedConsentDialog

    lm = LanguageManager()
    before = lm.current_lang
    lm.set_language(language)
    try:
        text = FeedConsentDialog.consent_text(["www.cisa.gov", "wid.cert-bund.de"])
    finally:
        lm.set_language(before)
    assert "www.cisa.gov" in text and "wid.cert-bund.de" in text


def test_link_question_shows_the_domain(english: LanguageManager) -> None:
    from oranovix_guardian.gui.threat_feed_dialogs import LinkOpener

    title, text = LinkOpener.question("https://news.example.org/story?id=7")
    assert title == "Open link?"
    assert text == "This opens news.example.org in your browser."


def test_link_that_is_not_a_web_link_is_never_opened(english: LanguageManager) -> None:
    from oranovix_guardian.gui.threat_feed_dialogs import LinkOpener

    opened: List[str] = []
    assert LinkOpener.open(None, "javascript:alert(1)", browser=opened.append) is False
    assert opened == []


# ---------------------------------------------------------------------------
# Threat Feed page
# ---------------------------------------------------------------------------

MATCH = ProjectMatch(
    project="Shop", project_path="/srv/shop", package="Django", ecosystem="PyPI", version="2.2.0",
    advisory_id="CVE-2019-14234", severity=Severity.CRITICAL, fixed_version="2.2.4",
)


def stored(relevance: Relevance, matches: tuple = ()) -> StoredItem:
    item = FeedItem("id", "CISA KEV", "Title", "https://example.org/a",
                    datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc))
    return StoredItem(item, NOW, False, relevance, matches)


def state(**changes: object) -> HubState:
    values: Dict[str, Any] = dict(enabled=True, asked=True, refreshing=False, last_success=NOW,
                  unread_for_you=0, database_ready=True)
    values.update(changes)
    return HubState(**values)


def test_feed_row_shows_which_project_and_package_matched(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    lines = ThreatFeedPage.match_lines(stored(Relevance.AFFECTS_YOU, (MATCH,)))
    assert lines == ["Shop: Django 2.2.0 (CVE-2019-14234)  →  fixed in 2.2.4"]
    assert ThreatFeedPage.badge_text(Relevance.AFFECTS_YOU) == "AFFECTS YOU"
    assert ThreatFeedPage.meta_text(stored(Relevance.GENERAL)).startswith("CISA KEV  ·  2026-11-1")


def test_possible_match_is_labelled_as_a_guess(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    guess = ProjectMatch("Blog", "/srv/blog", "lodash", "npm", "4.17.21")
    lines = ThreatFeedPage.match_lines(stored(Relevance.POSSIBLE, (guess,)))
    assert lines == ["Possible match, verify:", "Blog: lodash 4.17.21"]
    assert ThreatFeedPage.match_lines(stored(Relevance.GENERAL)) == []


def test_page_says_when_the_last_successful_update_was(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    local = NOW.astimezone().strftime("%Y-%m-%d %H:%M")
    assert ThreatFeedPage.updated_text(state()) == f"Last successful update: {local}"
    assert ThreatFeedPage.updated_text(state(last_success=None)) == "Not updated yet"

    offline = RefreshReport(NOW + timedelta(hours=3), failures=("News: no route to host",))
    assert ThreatFeedPage.updated_text(state(last_report=offline)) == (
        f"Offline, showing saved items.  Last successful update: {local}"
    )


def test_notes_above_the_list(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    assert "My Projects" in ThreatFeedPage.note_text(state(), has_projects=False)
    assert "database is missing" in ThreatFeedPage.note_text(state(database_ready=False), has_projects=True)
    assert ThreatFeedPage.note_text(state(), has_projects=True) == ""


def test_source_status(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    on = SourceConfig("News", "https://news.example.org/feed")
    off = SourceConfig("News", "https://news.example.org/feed", enabled=False)
    assert ThreatFeedPage.source_status(on, SourceHealth("News", NOW)) == ("OK", "success")
    assert ThreatFeedPage.source_status(on, SourceHealth("News", None, "timed out", NOW)) == ("timed out", "error")
    assert ThreatFeedPage.source_status(on, SourceHealth("News")) == ("never", "text3")
    assert ThreatFeedPage.source_status(off, SourceHealth("News", NOW)) == ("disabled", "text3")


# ---------------------------------------------------------------------------
# My Projects page
# ---------------------------------------------------------------------------

def row(**changes: object) -> ProjectRow:
    values: Dict[str, Any] = dict(project=Project("Shop", "/srv/shop", "https://shop.example.org/"), scan=None,
                  check=None, down_since=None, affecting=0, packages=5, checked=True)
    values.update(changes)
    return ProjectRow(**values)


def test_project_scan_cell(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    assert ProjectsPage.scan_text(row()) == ("Never scanned", "text3")
    scanned = row(scan=ScanSummary(datetime(2026, 11, 15, 17, 45), 1, 2, 5, 80))
    assert ProjectsPage.scan_text(scanned) == ("2026-11-15 17:45\nCritical 1, High 2", "critical")
    clean = row(scan=ScanSummary(datetime(2026, 11, 15, 17, 45), 0, 0, 0, 0))
    assert ProjectsPage.scan_text(clean)[1] == "success"


def test_project_site_cell(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    url = "https://shop.example.org/"
    up = UptimeCheck("Shop", url, NOW, ok=True, status=200, response_ms=87)
    failed = UptimeCheck("Shop", url, NOW, ok=False, error="connection refused")

    assert ProjectsPage.site_text(row(project=Project("Lib", "/srv/lib"))) == ("No site", "text3")
    assert ProjectsPage.site_text(row()) == (f"{url}\nNot checked yet", "text3")
    assert ProjectsPage.site_text(row(check=up)) == (f"{url}\nUp (HTTP 200)", "success")
    assert ProjectsPage.response_text(row(check=up)) == "87 ms"
    assert ProjectsPage.site_text(row(check=failed)) == (f"{url}\nCheck failed: connection refused", "warning")
    assert ProjectsPage.response_text(row(check=failed)) == "—"

    down_text, level = ProjectsPage.site_text(row(check=failed, down_since=NOW))
    assert down_text.startswith(f"{url}\nDown since ") and level == "error"


def test_project_feed_badge(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    assert ProjectsPage.feed_text(row(affecting=2)) == ("2 affect it", "critical")
    assert ProjectsPage.feed_text(row()) == ("Nothing", "text3")
    assert ProjectsPage.path_text(row()).endswith("5 packages")


# ---------------------------------------------------------------------------
# "Not checked" is not "nothing affects you"
# ---------------------------------------------------------------------------

OFFLINE = RefreshReport(NOW, failures=("News: no route to host",))
NOT_CHECKED = [
    (dict(enabled=False), CheckState.OFF, "Not checked: the Threat Feed is switched off."),
    (dict(last_success=None), CheckState.NEVER, "Not checked yet: the feed has not been downloaded."),
    (dict(last_report=OFFLINE), CheckState.UNREACHABLE,
     "Not checked: no source could be reached. Saved items are shown."),
    (dict(has_projects=False), CheckState.NO_PROJECTS,
     "Not checked: add your projects on the My Projects page."),
    (dict(database_ready=False), CheckState.NO_DATABASE,
     "Not checked: update the vulnerability database in Settings."),
]


@pytest.mark.parametrize("changes, expected, text", NOT_CHECKED)
def test_for_you_tab_says_why_nothing_was_checked(
    english: LanguageManager, changes: Dict[str, Any], expected: CheckState, text: str
) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    current = state(**changes)
    assert current.check is expected and not current.checked
    assert ThreatFeedPage.empty_text(current, for_you=True) == text
    assert ThreatFeedPage.empty_text(current, for_you=False) == "No items yet. Press Refresh."


def test_nothing_affects_you_only_after_a_real_check(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    ok = state(last_report=RefreshReport(NOW, sources_ok=4))
    assert ok.check is CheckState.CHECKED
    assert ThreatFeedPage.empty_text(ok, for_you=True) == "Nothing affects your projects right now."
    # One source failed, the others answered: that still is a check.
    partly = state(last_report=RefreshReport(NOW, failures=("News: timed out",), sources_ok=3))
    assert partly.checked


def test_switched_off_wins_over_every_other_reason() -> None:
    assert state(enabled=False, last_success=None, database_ready=False).check is CheckState.OFF
    assert state(last_success=None, database_ready=False).check is CheckState.NEVER


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_not_checked_texts_differ_from_the_all_clear(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    reasons = [texts[check.text_key] for check in CheckState if check is not CheckState.CHECKED]
    assert len(set(reasons)) == 6
    assert texts["tf_empty_for_you"] not in reasons
    assert texts["proj_feed_unchecked"] != texts["proj_feed_clear"]


def test_project_feed_cell_says_not_checked(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.projects_page import ProjectsPage

    assert ProjectsPage.feed_text(row(checked=False)) == ("Not checked", "warning")
    assert ProjectsPage.feed_text(row(checked=False, affecting=1)) == ("1 affect it", "critical")


# ---------------------------------------------------------------------------
# Certificate errors in the Sources tab
# ---------------------------------------------------------------------------

def test_certificate_error_of_a_source_is_explained(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage
    from oranovix_guardian.threat_intel.fetcher import CertificateError

    on = SourceConfig("BSI", "https://wid.example.org/rss")
    technical = "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain"
    stored_error = str(CertificateError(technical))

    text, level = ThreatFeedPage.source_status(on, SourceHealth("BSI", None, stored_error, NOW))

    assert text == f"The certificate of this site is not trusted by your system.\n{technical}"
    assert level == "error"


@pytest.mark.parametrize("error", [
    "URLError: timed out", "The server answered with status 503.",
    "SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number", "The feed is not valid XML.",
])
def test_other_source_errors_are_shown_as_they_are(english: LanguageManager, error: str) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    on = SourceConfig("News", "https://news.example.org/feed")
    assert ThreatFeedPage.source_status(on, SourceHealth("News", None, error, NOW)) == (error, "error")


# ---------------------------------------------------------------------------
# Partly checked
# ---------------------------------------------------------------------------

def test_for_you_tab_says_partly_checked_when_the_catalog_failed(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    current = state(failed_catalogs=("CISA KEV",))

    assert current.check is CheckState.PARTIAL and not current.checked
    assert ThreatFeedPage.empty_text(current, for_you=True) == "Partly checked: CISA KEV could not be read."


def test_stronger_reasons_come_before_partly_checked() -> None:
    assert state(failed_catalogs=("CISA KEV",), database_ready=False).check is CheckState.NO_DATABASE
    assert state(failed_catalogs=("CISA KEV",), enabled=False).check is CheckState.OFF


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_partly_checked_names_the_source_in_every_language(language: str) -> None:
    lm = LanguageManager()
    before = lm.current_lang
    lm.set_language(language)
    try:
        text = state(failed_catalogs=("CISA KEV",)).not_checked_text(lm.t)
    finally:
        lm.set_language(before)
    assert "CISA KEV" in text and text != lm.t("tf_empty_for_you")


# ---------------------------------------------------------------------------
# No fixed version
# ---------------------------------------------------------------------------

NO_FIX = ProjectMatch(
    project="Shop", project_path="/srv/shop", package="oldlib", ecosystem="PyPI", version="1.0.0",
    advisory_id="CVE-2031-0001", severity=Severity.HIGH,
)


def test_affecting_item_without_a_fix_says_so(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    lines = ThreatFeedPage.match_lines(stored(Relevance.AFFECTS_YOU, (NO_FIX,)))
    assert lines == ["Shop: oldlib 1.0.0 (CVE-2031-0001)  →  no fixed version known"]


def test_a_guess_says_nothing_about_fixes(english: LanguageManager) -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    guess = ProjectMatch("Blog", "/srv/blog", "lodash", "npm", "4.17.21")
    assert ThreatFeedPage.match_lines(stored(Relevance.POSSIBLE, (guess,)))[1] == "Blog: lodash 4.17.21"


@pytest.mark.parametrize("language, text", [
    ("en", "no fixed version known"), ("de", "keine behobene Version bekannt"),
])
def test_no_fix_text_in_the_translations(language: str, text: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    assert texts["tf_match_no_fix"] == text == texts["digest_no_fix"]


# ---------------------------------------------------------------------------
# Read state: only the user marks an affecting item as read
# ---------------------------------------------------------------------------

class FakePage:
    """The parts of the page that ``_open`` and ``on_shown`` touch. No window."""

    def __init__(self) -> None:
        self.marked: List[str] = []
        self.visits = 0
        page = self

        class Store:
            def set_last_visit(self) -> None:
                page.visits += 1

            def __getattr__(self, name: str) -> Any:
                raise AssertionError(f"the page must not call store.{name} here")

        class Hub:
            store = Store()

        self._hub = Hub()

    def _mark_read(self, item_id: str) -> None:
        self.marked.append(item_id)


def test_opening_the_page_marks_nothing_as_read() -> None:
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    page = FakePage()
    ThreatFeedPage.on_shown(page)       # type: ignore[arg-type]

    assert page.visits == 1 and page.marked == []


@pytest.mark.parametrize("relevance, marked", [
    (Relevance.AFFECTS_YOU, []), (Relevance.POSSIBLE, ["id"]), (Relevance.GENERAL, ["id"]),
])
def test_opening_a_link_never_marks_an_affecting_item_as_read(
    monkeypatch: pytest.MonkeyPatch, relevance: Relevance, marked: List[str]
) -> None:
    from oranovix_guardian.gui import threat_feed_dialogs
    from oranovix_guardian.gui.pages.threat_feed_page import ThreatFeedPage

    monkeypatch.setattr(threat_feed_dialogs.LinkOpener, "open", classmethod(lambda cls, master, url: True))
    page = FakePage()
    page.read_when_opened = ThreatFeedPage.read_when_opened     # type: ignore[attr-defined]

    ThreatFeedPage._open(page, stored(relevance, (MATCH,) if relevance is Relevance.AFFECTS_YOU else ()))  # type: ignore[arg-type]

    assert page.marked == marked
