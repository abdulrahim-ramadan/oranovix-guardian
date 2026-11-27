"""DigestBuilder: the text and HTML it produces."""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel import digest as digest_module
from oranovix_guardian.threat_intel.digest import DigestBuilder, DigestTexts
from oranovix_guardian.threat_intel.models import FeedItem, ProjectMatch, Relevance, StoredItem
from oranovix_guardian.threat_intel.projects import Project

VISIT = datetime(2026, 11, 15, 8, 0, tzinfo=timezone.utc)
AFTER = VISIT + timedelta(hours=5)
BEFORE = VISIT - timedelta(days=2)

SHOP = Project("Shop", "/srv/shop", "https://shop.example.org/")
BLOG = Project("Blog", "/srv/blog")

DJANGO_MATCH = ProjectMatch(
    project="Shop", project_path="/srv/shop", package="Django", ecosystem="PyPI",
    version="2.2.0", advisory_id="CVE-2019-14234", severity=Severity.CRITICAL,
    fixed_version="2.2.4", file_path="/srv/shop/requirements.txt", line=2,
)
NAME_MATCH = ProjectMatch(project="Blog", project_path="/srv/blog", package="lodash", ecosystem="npm", version="4.17.21")


def stored(
    key: str, title: str, relevance: Relevance = Relevance.GENERAL,
    first_seen: datetime = AFTER, matches: tuple = (), exploited: bool = False,
    published: Optional[datetime] = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc),
    url: str = "",
) -> StoredItem:
    item = FeedItem(
        id=key, source="CISA KEV" if exploited else "Example News", title=title,
        url=url or f"https://news.example.org/{key}", published=published,
        is_known_exploited=exploited,
    )
    return StoredItem(item, first_seen, False, relevance, matches)


def sample() -> List[StoredItem]:
    return [
        stored("general-1", "Ransomware gang hits hospital chain"),
        stored("kev-1", "CVE-2019-14234: Django SQL Injection Vulnerability",
               Relevance.AFFECTS_YOU, matches=(DJANGO_MATCH,), exploited=True),
        stored("possible-1", "Lodash Enterprise Gateway bypass", Relevance.POSSIBLE, matches=(NAME_MATCH,)),
        stored("old-1", "Seen before the last visit", Relevance.AFFECTS_YOU,
               first_seen=BEFORE, matches=(DJANGO_MATCH,)),
    ]


def test_headline_counts_new_and_affecting_items() -> None:
    digest = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT)

    assert digest.headline == "Since your last visit: 3 new  ·  1 of your projects is exposed"
    assert (digest.new_count, digest.affecting_count, digest.possible_count) == (3, 1, 1)
    assert digest.text.splitlines()[0] == digest.headline


def test_plain_text_output() -> None:
    digest = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT)

    assert digest.text == (
        "Since your last visit: 3 new  ·  1 of your projects is exposed\n"
        "\n"
        "Affects your projects (1)\n"
        "- CVE-2019-14234: Django SQL Injection Vulnerability [CISA KEV, 2026-11-14] (exploited in the wild)\n"
        "  https://news.example.org/kev-1\n"
        "  Shop: Django 2.2.0 (CVE-2019-14234), fixed in 2.2.4\n"
        "\n"
        "Possible matches, verify (1)\n"
        "- Lodash Enterprise Gateway bypass [Example News, 2026-11-14]\n"
        "  https://news.example.org/possible-1\n"
        "  Blog: lodash 4.17.21\n"
        "\n"
        "Other news (1)\n"
        "- Ransomware gang hits hospital chain [Example News, 2026-11-14]\n"
        "\n"
        "Your projects\n"
        "- Shop: 2 item(s) affect it\n"          # the one seen before the visit still counts
        "- Blog: nothing affects it\n"
    )


def test_items_seen_before_since_are_left_out() -> None:
    digest = DigestBuilder.build(sample(), [SHOP], VISIT)
    assert "Seen before the last visit" not in digest.text
    assert "Seen before the last visit" not in digest.html


def test_without_since_every_item_counts() -> None:
    digest = DigestBuilder.build(sample(), [SHOP], None)
    assert digest.new_count == 4 and digest.affecting_count == 2


def test_nothing_new() -> None:
    digest = DigestBuilder.build(sample(), [SHOP], AFTER + timedelta(days=1))
    assert digest.new_count == 0
    # Nothing is new, but the project is still exposed to what was seen before.
    assert digest.headline == "Nothing new since your last visit.  ·  1 of your projects is exposed"
    assert digest.exposed_count == 1
    assert digest.text == digest.headline + "\n\nYour projects\n- Shop: 2 item(s) affect it\n"


def test_no_items_and_no_projects() -> None:
    digest = DigestBuilder.build([], [], None)
    assert digest.text == "Nothing new since your last visit.\n"
    assert digest.html == "<h2>Nothing new since your last visit.</h2>\n"


def test_other_news_is_cut_after_ten() -> None:
    items = [stored(f"g{n}", f"Headline {n:02d}", published=None) for n in range(14)]
    digest = DigestBuilder.build(items, [], None)

    listed = [line for line in digest.text.splitlines() if line.startswith("- Headline")]
    assert len(listed) == 10
    assert "and 4 more" in digest.text and "Other news (14)" in digest.text
    assert "<p>and 4 more</p>" in digest.html


def test_html_output_has_links_and_sections() -> None:
    digest = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT)

    assert digest.html.startswith("<h2>Since your last visit: 3 new  ·  1 of your projects is exposed</h2>\n")
    assert "<h3>Affects your projects (1)</h3>" in digest.html
    assert (
        '<li><a href="https://news.example.org/kev-1">CVE-2019-14234: Django SQL Injection '
        "Vulnerability [CISA KEV, 2026-11-14] (exploited in the wild)</a>"
        "<br><small>Shop: Django 2.2.0 (CVE-2019-14234), fixed in 2.2.4</small></li>"
    ) in digest.html
    assert "<li>Blog: nothing affects it</li>" in digest.html


def test_html_escapes_everything_and_never_links_a_script() -> None:
    hostile = [
        stored("x", '<img src=x onerror=alert(1)> & "quotes"', Relevance.AFFECTS_YOU,
               matches=(ProjectMatch("<b>Shop</b>", "/srv/shop", "pkg<script>", version="1"),)),
        stored("y", "Bad link", url="javascript:alert(1)"),
        stored("z", "Quote in link", url='https://news.example.org/a"onmouseover="x'),
    ]
    digest = DigestBuilder.build(hostile, [Project("<i>P</i>", "/p")], None)

    assert "<img" not in digest.html and "<script>" not in digest.html and "<b>" not in digest.html
    assert "&lt;img src=x onerror=alert(1)&gt; &amp; &quot;quotes&quot;" in digest.html
    assert "javascript:" not in digest.html
    assert "<li>Bad link [Example News, 2026-11-14]</li>" in digest.html
    assert 'href="https://news.example.org/a&quot;onmouseover=&quot;x"' in digest.html
    assert "&lt;i&gt;P&lt;/i&gt;" in digest.html


def test_same_input_gives_the_same_digest() -> None:
    first = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT)
    second = DigestBuilder.build(list(reversed(sample())), [SHOP, BLOG], VISIT)
    assert first == second


def test_wording_can_be_translated() -> None:
    german = {
        "digest_headline": "Seit Ihrem letzten Besuch: {new} neu",
        "digest_exposed_one": "1 Ihrer Projekte ist betroffen",
        "digest_affecting": "Betrifft Ihre Projekte",
    }
    texts = DigestTexts.translated(lambda key: german.get(key, key))

    digest = DigestBuilder.build(sample(), [SHOP], VISIT, texts)

    assert digest.headline == "Seit Ihrem letzten Besuch: 3 neu  ·  1 Ihrer Projekte ist betroffen"
    assert "Betrifft Ihre Projekte (1)" in digest.text
    assert "Other news (1)" in digest.text              # untranslated keys stay English


def test_module_sends_nothing() -> None:
    source = inspect.getsource(digest_module)
    for forbidden in ("smtplib", "urllib.request", "socket", "telegram", "requests", "open("):
        assert forbidden not in source


def test_not_checked_replaces_the_headline_and_calls_no_project_clear() -> None:
    reason = "Not checked: the Threat Feed is switched off."
    digest = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT, not_checked=reason)

    # Not checked, but what is already known about the projects is still said.
    assert digest.headline == reason + "  ·  1 of your projects is exposed" and digest.checked is False
    assert digest.text.splitlines()[0] == digest.headline
    assert "Shop: 2 item(s) affect it" in digest.text
    assert "nothing affects it" not in digest.text and "nothing affects it" not in digest.html
    assert f"<h2>{digest.headline}</h2>" in digest.html

    nothing = DigestBuilder.build([], [SHOP], VISIT, not_checked=reason)
    assert nothing.headline == reason and "Nothing new" not in nothing.text
    assert DigestBuilder.build([], [SHOP], VISIT).checked is True


def test_affecting_item_without_a_fix_says_so() -> None:
    no_fix = ProjectMatch(
        project="Shop", project_path="/srv/shop", package="oldlib", ecosystem="PyPI",
        version="1.0.0", advisory_id="CVE-2031-0001", severity=Severity.HIGH,
    )
    items = [stored("kev-2", "CVE-2031-0001: oldlib", Relevance.AFFECTS_YOU, matches=(no_fix,), exploited=True)]

    digest = DigestBuilder.build(items, [SHOP], VISIT)

    assert "  Shop: oldlib 1.0.0 (CVE-2031-0001), no fixed version known" in digest.text.splitlines()
    assert "no fixed version known" in digest.html
    guess = DigestBuilder.build(sample(), [SHOP, BLOG], VISIT)
    assert "  Blog: lodash 4.17.21" in guess.text.splitlines()
