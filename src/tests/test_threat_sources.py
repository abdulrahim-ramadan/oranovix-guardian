"""Feed sources against fixtures. The fetcher is a fake: no network."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.fetcher import FetchError, FetchResponse
from oranovix_guardian.threat_intel.models import CacheValidators, FeedError, PackageRef
from oranovix_guardian.threat_intel.settings import ThreatFeedConfig, ThreatFeedSettings
from oranovix_guardian.threat_intel.sources import (
    CisaKevSource,
    DownloadedFeedSource,
    RssSource,
    SourceCatalog,
    SourceConfig,
    SourceKind,
)

FEEDS = Path(__file__).parent / "fixtures" / "feeds"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
RSS_URL = "https://news.example.org/feed/"
ATOM_URL = "https://advisories.example.org/atom.xml"


def rss(url: str = RSS_URL) -> RssSource:
    return RssSource("Example News", url, "en", clock=lambda: NOW)


def kev() -> CisaKevSource:
    return CisaKevSource(clock=lambda: NOW)


def fixture(name: str) -> bytes:
    return (FEEDS / name).read_bytes()


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def test_kev_entries_become_known_exploited_items() -> None:
    source = kev()
    items = source.fetch(FakeFetcher({CisaKevSource.URL: fixture("kev.json")}))

    assert [item.cve_ids for item in items] == [
        ("CVE-2099-1111",), ("CVE-2019-14234",), ("CVE-2099-2222",),      # newest first
    ]
    django = items[1]
    assert django.title == "CVE-2019-14234: Django SQL Injection Vulnerability"
    assert django.url == "https://nvd.nist.gov/vuln/detail/CVE-2019-14234"
    assert django.published == datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert django.is_known_exploited
    assert django.severity_hint is Severity.HIGH
    assert PackageRef("", "Django") in django.packages
    assert django.source == "CISA KEV"
    assert source.health.ok and source.health.last_success == NOW


def test_kev_ransomware_entry_is_critical_and_html_is_stripped() -> None:
    items = kev().fetch(FakeFetcher({CisaKevSource.URL: fixture("kev.json")}))
    gateway = items[0]
    assert gateway.severity_hint is Severity.CRITICAL
    assert gateway.title == "CVE-2099-1111: Example Corp Gateway Authentication Bypass Vulnerability"


def test_kev_keeps_all_entries_newest_first() -> None:
    entries = ",".join(
        '{"cveID": "CVE-2099-%04d", "vulnerabilityName": "n", "dateAdded": "2026-%02d-%02d"}'
        % (number, 1 + number % 12, 1 + number % 28)
        for number in range(1000, 1300)
    )
    body = ('{"vulnerabilities": [%s]}' % entries).encode()

    items = kev().fetch(FakeFetcher({CisaKevSource.URL: body}))

    assert len(items) == 300
    assert items[0].published is not None and items[-1].published is not None
    assert items[0].published >= items[-1].published


@pytest.mark.parametrize("body", [b"<html>blocked</html>", b"[]", b'{"vulnerabilities": "none"}'])
def test_kev_rejects_a_document_that_is_not_the_catalog(body: bytes) -> None:
    source = kev()
    with pytest.raises(FeedError):
        source.fetch(FakeFetcher({CisaKevSource.URL: body}))
    assert not source.health.ok
    assert source.health.last_error and source.health.last_error_at == NOW


# ---------------------------------------------------------------------------
# RSS and Atom
# ---------------------------------------------------------------------------

def test_rss_items_are_read() -> None:
    items = rss().fetch(FakeFetcher({RSS_URL: fixture("news_rss.xml")}))

    assert [item.title for item in items] == [
        "Django fixes SQL injection exploited in the wild",
        "[UPDATE] [hoch] Linux Kernel: Mehrere Schwachstellen",
        "Plain http link",
    ]
    first = items[0]
    assert first.url == "https://news.example.org/django-sql-injection"
    assert first.published == datetime(2026, 11, 16, 9, 42, 4, tzinfo=timezone.utc)
    assert first.cve_ids == ("CVE-2019-14234",)
    assert first.source == "Example News"
    assert not first.is_known_exploited


def test_rss_summary_has_no_markup_and_no_article_body() -> None:
    first = rss().fetch(FakeFetcher({RSS_URL: fixture("news_rss.xml")}))[0]
    assert first.summary == "Attackers exploit CVE-2019-14234 in Django."
    assert "full article" not in first.summary


def test_rss_time_zone_is_converted_and_a_bad_date_is_none() -> None:
    items = rss().fetch(FakeFetcher({RSS_URL: fixture("news_rss.xml")}))
    assert items[1].published == datetime(2026, 11, 15, 12, 34, 21, tzinfo=timezone.utc)
    assert items[2].published is None


def test_rss_rating_in_the_headline_becomes_the_severity_hint() -> None:
    items = rss().fetch(FakeFetcher({RSS_URL: fixture("news_rss.xml")}))
    assert items[1].severity_hint is Severity.HIGH
    assert items[0].severity_hint is None


def test_rss_entry_with_a_script_link_is_dropped() -> None:
    items = rss().fetch(FakeFetcher({RSS_URL: fixture("news_rss.xml")}))
    assert all(item.url.startswith(("https://", "http://")) for item in items)
    assert "Click here" not in [item.title for item in items]


def test_atom_entries_are_read() -> None:
    source = RssSource("Example Advisories", ATOM_URL, "en", clock=lambda: NOW)
    items = source.fetch(FakeFetcher({ATOM_URL: fixture("news_atom.xml")}))

    assert [item.title for item in items] == [
        "lodash prototype pollution advisory", "Entry with xhtml content",
    ]
    first, second = items
    assert first.url == "https://advisories.example.org/2001"          # the alternate link
    assert first.published == datetime(2026, 11, 14, 8, 30, tzinfo=timezone.utc)
    assert first.summary == "Versions before 4.17.19 are affected (CVE-2099-0101, cve-2099-0102)."
    assert first.cve_ids == ("CVE-2099-0101", "CVE-2099-0102")
    assert second.url == "https://advisories.example.org/2002"
    assert second.published == datetime(2026, 11, 13, 11, 0, tzinfo=timezone.utc)
    assert second.summary == "Short note."


def test_same_entry_keeps_its_id_between_downloads() -> None:
    fetcher = FakeFetcher({RSS_URL: fixture("news_rss.xml")})
    assert [i.id for i in rss().fetch(fetcher)] == [i.id for i in rss().fetch(fetcher)]


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<rss version="2.0"><channel><item><title>&lol3;</title><link>https://example.org/a</link></item></channel></rss>"""

EXTERNAL_ENTITY = b"""<?xml version="1.0"?>
<!DOCTYPE rss [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<rss version="2.0"><channel><item><title>&xxe;</title><link>https://example.org/a</link></item></channel></rss>"""

EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE rss SYSTEM "https://evil.example/feed.dtd">
<rss version="2.0"><channel><item><title>t</title><link>https://example.org/a</link></item></channel></rss>"""


@pytest.mark.parametrize("body", [BILLION_LAUGHS, EXTERNAL_ENTITY, EXTERNAL_DTD])
def test_hostile_xml_is_rejected(body: bytes) -> None:
    source = rss()
    fetcher = FakeFetcher({RSS_URL: body})

    with pytest.raises(FeedError, match="forbidden XML"):
        source.fetch(fetcher)

    assert fetcher.urls == [RSS_URL]            # nothing else was requested
    assert "forbidden XML" in source.health.last_error


@pytest.mark.parametrize("body", [b"", b"<rss><channel>", b"<html><body>Blocked</body></html>", b"\xff\xfe\x00"])
def test_broken_feed_is_rejected(body: bytes) -> None:
    with pytest.raises(FeedError):
        rss().fetch(FakeFetcher({RSS_URL: body}))


def test_at_most_200_items_per_source() -> None:
    entries = "".join(
        f"<item><title>Item {n}</title><link>https://example.org/{n}</link></item>" for n in range(450)
    )
    body = f'<rss version="2.0"><channel>{entries}</channel></rss>'.encode()

    items = rss().fetch(FakeFetcher({RSS_URL: body}))

    assert len(items) == 200 == DownloadedFeedSource.MAX_ITEMS
    assert items[0].title == "Item 0"


# ---------------------------------------------------------------------------
# Download rules and health
# ---------------------------------------------------------------------------

def test_oversize_response_is_refused_and_noted() -> None:
    source = rss()
    fetcher = FakeFetcher({RSS_URL: FetchError("The answer is larger than 5242880 bytes.")})

    with pytest.raises(FeedError, match="larger"):
        source.fetch(fetcher)

    assert "larger" in source.health.last_error and source.health.last_success is None


def test_feed_over_plain_http_is_never_requested() -> None:
    source = rss("http://news.example.org/feed/")
    fetcher = FakeFetcher({"http://news.example.org/feed/": fixture("news_rss.xml")})

    with pytest.raises(FeedError, match="https"):
        source.fetch(fetcher)

    assert fetcher.requests == []


def test_error_status_is_a_failure() -> None:
    source = rss()
    with pytest.raises(FeedError, match="503"):
        source.fetch(FakeFetcher({RSS_URL: FetchResponse(status=503)}))
    assert not source.health.ok


def test_validators_are_remembered_and_304_counts_as_success() -> None:
    source = rss()
    fetcher = FakeFetcher({RSS_URL: FetchResponse(200, fixture("news_rss.xml"), '"v7"', "Mon, 16 Nov 2026 09:00:00 GMT")})
    assert len(source.fetch(fetcher)) == 3
    assert source.validators == CacheValidators('"v7"', "Mon, 16 Nov 2026 09:00:00 GMT")

    fetcher.answers[RSS_URL] = FetchResponse(status=304)
    assert source.fetch(fetcher) == []

    assert fetcher.requests[-1] == (RSS_URL, '"v7"', "Mon, 16 Nov 2026 09:00:00 GMT")
    assert source.health.ok


def test_health_recovers_after_a_later_success() -> None:
    times = iter([
        datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 16, 13, 0, tzinfo=timezone.utc),
    ])
    source = RssSource("Example News", RSS_URL, clock=lambda: next(times))
    fetcher = FakeFetcher({})

    with pytest.raises(FeedError):
        source.fetch(fetcher)
    assert not source.health.ok

    fetcher.answers[RSS_URL] = fixture("news_rss.xml")
    source.fetch(fetcher)
    assert source.health.ok
    assert source.health.last_error == "no route to host"      # still shown as the last error


def test_one_failing_source_does_not_stop_the_others() -> None:
    sources: List[DownloadedFeedSource] = [rss("https://down.example.org/feed"), kev(), rss()]
    fetcher = FakeFetcher({CisaKevSource.URL: fixture("kev.json"), RSS_URL: fixture("news_rss.xml")})

    collected = []
    for source in sources:
        try:
            collected.extend(source.fetch(fetcher))
        except FeedError:
            continue

    assert len(collected) == 6
    assert [source.health.ok for source in sources] == [False, True, True]


# ---------------------------------------------------------------------------
# Source list in settings
# ---------------------------------------------------------------------------

def test_default_sources() -> None:
    by_name = {config.name: config for config in SourceCatalog.DEFAULTS}
    assert list(by_name) == ["CISA KEV", "BleepingComputer", "The Hacker News", "BSI CERT-Bund"]
    assert by_name["CISA KEV"].kind is SourceKind.KEV
    assert by_name["BSI CERT-Bund"].language == "de"
    assert all(config.url.startswith("https://") and config.enabled for config in by_name.values())
    assert SourceCatalog.hosts(SourceCatalog.DEFAULTS) == [
        "feeds.feedburner.com", "wid.cert-bund.de", "www.bleepingcomputer.com", "www.cisa.gov",
    ]


def test_source_list_from_json_drops_what_is_not_https() -> None:
    configs = SourceCatalog.from_json([
        {"name": "Good", "url": "https://good.example/feed", "language": "DE"},
        {"name": "Plain", "url": "http://plain.example/feed"},
        {"name": "Script", "url": "javascript:alert(1)"},
        {"name": "", "url": "https://noname.example/feed"},
        {"name": "Good", "url": "https://duplicate.example/feed"},
        {"name": "Off", "url": "https://off.example/feed", "enabled": False},
        "nonsense",
    ])
    assert configs == (
        SourceConfig("Good", "https://good.example/feed", "de"),
        SourceConfig("Off", "https://off.example/feed", "en", enabled=False),
    )
    assert SourceCatalog.hosts(configs) == ["good.example"]


def test_edited_source_list_must_be_valid() -> None:
    text = SourceCatalog.to_text(SourceCatalog.DEFAULTS)
    assert SourceCatalog.parse_text(text) == SourceCatalog.DEFAULTS
    with pytest.raises(ValueError):
        SourceCatalog.parse_text("{not json")
    with pytest.raises(ValueError):
        SourceCatalog.parse_text('[{"name": "Plain", "url": "http://plain.example/feed"}]')


def test_catalog_builds_the_right_source_class() -> None:
    kev_source, news = (SourceCatalog.build(config) for config in SourceCatalog.DEFAULTS[:2])
    assert isinstance(kev_source, CisaKevSource) and isinstance(news, RssSource)
    assert news.url == "https://www.bleepingcomputer.com/feed/"


def test_feed_is_off_by_default(tmp_path: Path) -> None:
    settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
    config = settings.load()
    assert config == ThreatFeedConfig()
    assert config.enabled is False and config.asked is False
    assert config.interval_minutes == 60
    assert config.sources == SourceCatalog.DEFAULTS


def test_settings_round_trip_keeps_other_entries(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"theme": "dark"}', encoding="utf-8")
    settings = ThreatFeedSettings(str(path))

    settings.update(enabled=True, asked=True, interval_minutes=5)

    config = settings.load()
    assert config.enabled and config.asked
    assert config.interval_minutes == 15                    # lower bound
    assert '"theme": "dark"' in path.read_text(encoding="utf-8")
