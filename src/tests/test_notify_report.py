"""Daily report: what it contains, what it never contains, and how it is rendered."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Callable, Dict, List

import pytest

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.notify.report import DailyReport, ProjectAliases, ReportOptions, ReportState
from oranovix_guardian.notify.render import ReportRenderer
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.models import Relevance

from notify_fakes import FORBIDDEN, HOSTILE_TITLE, full_state, integrity_event, sentinel_event, stored

UTC = timezone.utc
NOW = datetime(2026, 11, 22, 8, tzinfo=UTC)
SINCE = NOW - timedelta(hours=24)


def report(state: ReportState = None, **options: bool) -> DailyReport:  # type: ignore[assignment]
    return DailyReport.build(state or full_state(), now=NOW, since=SINCE, options=ReportOptions(**options))


def outputs(rep: DailyReport, lang: str = "en") -> Dict[str, str]:
    lm = LanguageManager()
    previous = lm.current_lang
    lm.set_language(lang)
    try:
        renderer = ReportRenderer.for_current_language()
        return {"text": renderer.text(rep), "telegram": renderer.telegram_html(rep),
                "email": renderer.email_html(rep), "subject": renderer.subject(rep)}
    finally:
        lm.set_language(previous)


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

def test_feed_part_counts_and_lists_items_that_affect_projects() -> None:
    rep = report()
    assert rep.feed_new == 3
    titles = [hit.title for hit in rep.feed_hits]
    assert titles == ["Django SQL injection", HOSTILE_TITLE]          # the general item is only counted
    assert rep.feed_hits[0].cve_ids == ("CVE-2026-1111",)
    assert rep.feed_hits[0].projects == ("shop",)


def test_uptime_part_has_the_host_only() -> None:
    rep = report()
    assert [(s.project, s.host) for s in rep.sites] == [("blog", "blog.example.com")]


def test_sentinel_counts_per_severity_and_top_rules_without_addresses() -> None:
    rep = report()
    assert rep.sentinel_by_severity == {"CRITICAL": 1, "HIGH": 9, "MEDIUM": 1}
    assert rep.sentinel_top_rules[0] == ("LS101", 9)
    assert rep.sentinel_networks == ()


def test_include_network_shows_only_truncated_networks() -> None:
    rep = report(include_network=True)
    networks = dict(rep.sentinel_networks)
    assert networks == {"198.51.100.0/24": 9, "2001:db8:85a3::/48": 1, "203.0.113.0/24": 1}


def test_live_defense_part_lists_only_high_and_critical_relative_paths() -> None:
    rep = report()
    assert rep.integrity_by_severity == {"CRITICAL": 1, "HIGH": 1, "LOW": 1}
    assert rep.integrity_paths == (("CRITICAL", "app/views.py"), ("HIGH", "config/.env"))


def test_an_absolute_path_in_an_event_is_reduced_to_its_name() -> None:
    state = full_state()
    state = ReportState(**{**state.__dict__, "integrity_events": [
        integrity_event("C:/Users/alice/secret/notes.txt", Severity.CRITICAL),
        integrity_event("../../outside/key.pem", Severity.HIGH),
    ]})
    rep = report(state)
    assert rep.integrity_paths == (("CRITICAL", "notes.txt"), ("HIGH", "key.pem"))


def test_last_scan_has_date_project_and_counts() -> None:
    scan = report().last_scan
    assert scan is not None and scan.project == "shop" and scan.counts["CRITICAL"] == 2


def test_only_events_since_the_last_report_are_counted() -> None:
    state = full_state()
    old = sentinel_event("LS101", Severity.HIGH, at=SINCE - timedelta(minutes=1), hits=50)
    state = ReportState(**{**state.__dict__, "sentinel_events": [*state.sentinel_events, old]})
    assert report(state).sentinel_by_severity["HIGH"] == 9


def test_building_is_pure() -> None:
    state = full_state()
    assert report(state) == report(state)


# ---------------------------------------------------------------------------
# Hide project names
# ---------------------------------------------------------------------------

def test_hidden_project_names_get_stable_letters() -> None:
    aliases = ProjectAliases({})
    first = DailyReport.build(full_state(), now=NOW, since=SINCE, options=ReportOptions(hide_projects=True), aliases=aliases)
    assert first.feed_hits[0].projects == ("Project A",)
    assert first.feed_hits[1].projects == ("Project B",)
    assert first.sites[0].project == "Project B"
    assert first.last_scan is not None and first.last_scan.project == "Project A"
    again = DailyReport.build(full_state(), now=NOW, since=SINCE, options=ReportOptions(hide_projects=True),
                              aliases=ProjectAliases(aliases.mapping))
    assert again == first
    for text in outputs(first).values():
        assert "shop" not in text and "blog" not in text


def test_aliases_continue_after_z() -> None:
    aliases = ProjectAliases({})
    names = [aliases.alias(f"p{n}") for n in range(28)]
    assert names[0] == "Project A" and names[25] == "Project Z" and names[26] == "Project AA"
    assert len(set(names)) == 28


# ---------------------------------------------------------------------------
# Data minimisation: the DSGVO line
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lang", ["en", "de", "ar"])
@pytest.mark.parametrize("include_network", [False, True])
def test_no_secret_ip_snippet_or_path_reaches_any_output(lang: str, include_network: bool) -> None:
    rendered = outputs(report(include_network=include_network), lang)
    for name, text in rendered.items():
        unescaped = html.unescape(text)
        for forbidden in FORBIDDEN:
            assert forbidden not in text, (name, forbidden)
            assert forbidden not in unescaped, (name, forbidden)
        assert not re.search(r"\b198\.51\.100\.(?!0/24)\d+", unescaped), name
        assert not re.search(r"\b203\.0\.113\.(?!0/24)\d+", unescaped), name


def test_the_report_serialised_has_no_secret_either() -> None:
    text = json.dumps(report().to_json())
    for forbidden in FORBIDDEN:
        assert forbidden not in text


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: List[str] = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.scripts += tag == "script"


def test_telegram_html_uses_only_allowed_tags_and_escapes_values() -> None:
    telegram = outputs(report())["telegram"]
    parser = _Tags()
    parser.feed(telegram)
    assert set(parser.tags) <= {"b", "i", "code", "a"}
    assert parser.scripts == 0
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;/b&gt;" in telegram
    assert "<script>" not in telegram


def test_telegram_tags_are_balanced_on_every_line() -> None:
    """Splitting happens at line boundaries, so no tag may span two lines."""
    for line in outputs(report())["telegram"].splitlines():
        for tag in ("b", "i", "code", "a"):
            assert line.count(f"<{tag}>") + line.count(f"<{tag} ") == line.count(f"</{tag}>"), line


def test_email_html_escapes_the_hostile_title() -> None:
    email_html = outputs(report())["email"]
    parser = _Tags()
    parser.feed(email_html)
    assert parser.scripts == 0
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;/b&gt;" in email_html


def test_text_output_is_plain() -> None:
    text = outputs(report())["text"]
    assert "<b>" not in text and HOSTILE_TITLE in text


def test_a_link_only_for_web_addresses() -> None:
    state = full_state()
    items = [stored("Bad link", Relevance.AFFECTS_YOU, ("shop",), url="javascript:alert(1)")]
    rep = report(ReportState(**{**state.__dict__, "feed_items": items}))
    for text in outputs(rep).values():
        assert "javascript:" not in text


@pytest.mark.parametrize("lang,word", [("en", "daily report"), ("de", "Tagesbericht"), ("ar", "التقرير اليومي")])
def test_subject_is_translated_with_the_date(lang: str, word: str) -> None:
    subject = outputs(report(), lang)["subject"]
    assert word in subject and "22.11.2026" in subject and subject.startswith("Oranovix Guardian")
    assert "\n" not in subject and "\r" not in subject


def test_arabic_email_is_right_to_left() -> None:
    assert 'dir="rtl"' in outputs(report(), "ar")["email"]
    assert 'dir="rtl"' not in outputs(report(), "en")["email"]


@pytest.mark.parametrize("lang", ["en", "de", "ar"])
def test_rule_names_are_translated(lang: str) -> None:
    lm = LanguageManager()
    previous = lm.current_lang
    lm.set_language(lang)
    try:
        expected = lm.t("ls_rule_ls101")
    finally:
        lm.set_language(previous)
    assert expected in outputs(report(), lang)["text"]


def test_a_quiet_day_says_so() -> None:
    empty = ReportState(feed_items=[], projects=[], feed_checked=True, sites=[], sentinel_events=[],
                        integrity_events=[], last_scan=None)
    text = outputs(DailyReport.build(empty, now=NOW, since=SINCE, options=ReportOptions()))["text"]
    assert LanguageManager().t("nt_report_quiet") in text


def test_every_new_text_exists_in_all_three_languages() -> None:
    from pathlib import Path
    folder = Path(__file__).resolve().parents[1] / "oranovix_guardian" / "translations"
    keys: Dict[str, set] = {}
    for lang in ("en", "de", "ar"):
        data = json.loads((folder / f"{lang}.json").read_text(encoding="utf-8"))
        keys[lang] = {key for key in data if key.startswith("nt_")}
    assert keys["en"] and keys["en"] == keys["de"] == keys["ar"]
