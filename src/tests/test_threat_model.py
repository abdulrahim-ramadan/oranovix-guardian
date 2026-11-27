"""Threat Feed data model and the HTTP fetcher (with a fake opener, no network)."""
from __future__ import annotations

import io
import socket
import ssl
import sys
import types
import urllib.error
import urllib.request
import urllib.response
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.fetcher import (
    CertificateError,
    FetchError,
    Fetcher,
    FetchResponse,
    HttpFetcher,
    TlsTrust,
)
from oranovix_guardian.threat_intel.models import FeedItem, FeedSource, PackageRef, Relevance, SourceHealth
from oranovix_guardian.threat_intel.sanitize import SafeUrl, TextCleaner


# ---------------------------------------------------------------------------
# FeedItem
# ---------------------------------------------------------------------------

def test_id_depends_on_source_and_key_only() -> None:
    first = FeedItem.build("News", "guid-1", "Title", "https://example.org/a")
    again = FeedItem.build("News", "guid-1", "Another title", "https://example.org/b")
    other_source = FeedItem.build("Other", "guid-1", "Title", "https://example.org/a")

    assert first is not None and again is not None and other_source is not None
    assert first.id == again.id
    assert first.id != other_source.id
    assert len(first.id) == 32


def test_url_is_the_key_when_the_entry_has_no_guid() -> None:
    item = FeedItem.build("News", "", "Title", "https://example.org/a")
    assert item is not None
    assert item.id == FeedItem.make_id("News", "https://example.org/a")


def test_html_is_stripped_from_title_and_summary() -> None:
    item = FeedItem.build(
        "News", "g",
        "<b>Patch</b> now: <script>alert(1)</script>Django &amp; friends",
        "https://example.org/a",
        summary="&lt;p&gt;Fixes <a href='javascript:x'>CVE-2024-27351</a>&lt;/p&gt;&lt;img src=x onerror=y&gt;",
    )
    assert item is not None
    assert item.title == "Patch now: Django & friends"
    assert item.summary == "Fixes CVE-2024-27351"
    assert item.cve_ids == ("CVE-2024-27351",)


def test_title_and_summary_are_capped() -> None:
    item = FeedItem.build("News", "g", "t" * 500, "https://example.org/a", summary="s" * 5000)
    assert item is not None
    assert len(item.title) == TextCleaner.TITLE_LIMIT == 200
    assert len(item.summary) == TextCleaner.SUMMARY_LIMIT == 400


@pytest.mark.parametrize("link", [
    "javascript:alert(1)", "file:///etc/passwd", "ftp://example.org/x", "data:text/html,x",
    "//example.org/x", "https://", "", "https://exa mple.org/",
])
def test_item_with_a_link_that_is_not_http_is_dropped(link: str) -> None:
    assert FeedItem.build("News", "g", "Title", link) is None


def test_http_and_https_links_are_kept() -> None:
    assert FeedItem.build("News", "g", "Title", "http://example.org/a") is not None
    assert FeedItem.build("News", "g", "Title", "https://example.org/a") is not None


def test_item_without_title_is_dropped() -> None:
    assert FeedItem.build("News", "g", "<p> </p>", "https://example.org/a") is None


def test_published_is_stored_in_utc() -> None:
    local = datetime(2026, 11, 16, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    item = FeedItem.build("News", "g", "Title", "https://example.org/a", published=local)
    assert item is not None
    assert item.published == datetime(2026, 11, 16, 10, 0, tzinfo=timezone.utc)


def test_packages_and_flags_are_kept() -> None:
    item = FeedItem.build(
        "KEV", "CVE-2019-14234", "Django SQL injection", "https://example.org/a",
        cve_ids=["cve-2019-14234"], packages=[PackageRef("", "Django"), PackageRef("PyPI", " ")],
        is_known_exploited=True, severity_hint=Severity.HIGH,
    )
    assert item is not None
    assert item.cve_ids == ("CVE-2019-14234",)
    assert item.packages == (PackageRef("", "Django"),)
    assert item.is_known_exploited and item.severity_hint is Severity.HIGH


def test_relevance_orders_affects_you_first() -> None:
    ordered = sorted(Relevance, key=lambda r: r.rank)
    assert ordered == [Relevance.AFFECTS_YOU, Relevance.POSSIBLE, Relevance.GENERAL]


def test_text_direction_marks_are_removed() -> None:
    assert TextCleaner.plain("safe\u202egnp.exe") == "safegnp.exe"


@pytest.mark.parametrize("link", [
    "https://user:pw@evil.example@ok.example/", "https://user@ok.example/",
    "https://@ok.example/", "http://ok.example:pw@evil.example/",
])
def test_link_with_credentials_is_refused(link: str) -> None:
    assert SafeUrl.clean(link) == ""
    assert FeedItem.build("News", "g", "Title", link) is None


def test_at_sign_in_the_path_is_fine() -> None:
    assert SafeUrl.clean("https://ok.example/users/@alice") == "https://ok.example/users/@alice"


def test_safe_url_host() -> None:
    assert SafeUrl.host("https://News.Example.org:8443/a?b") == "news.example.org"
    assert SafeUrl.is_https("https://example.org/") and not SafeUrl.is_https("http://example.org/")


# ---------------------------------------------------------------------------
# FeedSource with a fake fetcher
# ---------------------------------------------------------------------------

class OneLineSource(FeedSource):
    """Smallest possible source: every line of the body is a headline."""

    def __init__(self) -> None:
        super().__init__("Lines", "https://feeds.example.org/lines", "en")
        self._health = SourceHealth(self.name)

    @property
    def health(self) -> SourceHealth:
        return self._health

    def fetch(self, fetcher: Fetcher) -> List[FeedItem]:
        response = fetcher.get(self.url)
        if response.unchanged:
            return []
        lines = response.body.decode("utf-8").splitlines()
        items = [FeedItem.build(self.name, line, line, f"https://example.org/{n}")
                 for n, line in enumerate(lines)]
        return [item for item in items if item is not None]


def test_source_reads_through_the_injected_fetcher() -> None:
    source = OneLineSource()
    fetcher = FakeFetcher({source.url: b"first\nsecond"})

    items = source.fetch(fetcher)

    assert [item.title for item in items] == ["first", "second"]
    assert fetcher.urls == ["https://feeds.example.org/lines"]
    assert source.host == "feeds.example.org"


def test_source_returns_nothing_when_unchanged() -> None:
    source = OneLineSource()
    assert source.fetch(FakeFetcher({source.url: FetchResponse(status=304)})) == []


# ---------------------------------------------------------------------------
# HttpFetcher
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body: bytes, headers: Optional[Dict[str, str]] = None, status: int = 200) -> None:
        self._body = io.BytesIO(body)
        self.status = status
        self.headers = Message()
        for name, value in (headers or {}).items():
            self.headers[name] = value

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class RecordingOpener:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.requests: List[urllib.request.Request] = []
        self.timeouts: List[float] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> Any:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_request_carries_user_agent_and_timeout() -> None:
    opener = RecordingOpener(FakeResponse(b"hello", {"ETag": '"v1"', "Last-Modified": "Mon, 16 Nov 2026 09:00:00 GMT"}))
    response = HttpFetcher(opener=opener).get("https://example.org/feed")

    request = opener.requests[0]
    assert request.get_method() == "GET"
    assert request.get_header("User-agent") == "OranovixGuardian"
    assert opener.timeouts == [10.0]
    assert request.data is None
    assert response.ok and response.body == b"hello"
    assert response.etag == '"v1"'
    assert response.last_modified == "Mon, 16 Nov 2026 09:00:00 GMT"


def test_validators_are_sent_and_304_means_unchanged() -> None:
    not_modified = urllib.error.HTTPError("https://example.org/feed", 304, "Not Modified", Message(), None)
    opener = RecordingOpener(not_modified)

    response = HttpFetcher(opener=opener).get(
        "https://example.org/feed", etag='"v1"', last_modified="Mon, 16 Nov 2026 09:00:00 GMT"
    )

    request = opener.requests[0]
    assert request.get_header("If-none-match") == '"v1"'
    assert request.get_header("If-modified-since") == "Mon, 16 Nov 2026 09:00:00 GMT"
    assert response.unchanged and response.body == b""


def test_error_status_is_returned_not_raised() -> None:
    gone = urllib.error.HTTPError("https://example.org/feed", 503, "Unavailable", Message(), None)
    response = HttpFetcher(opener=RecordingOpener(gone)).get("https://example.org/feed")
    assert response.status == 503 and not response.ok


@pytest.mark.parametrize("url", ["http://example.org/feed", "file:///etc/passwd", "ftp://example.org/", "https://"])
def test_only_https_is_requested(url: str) -> None:
    opener = RecordingOpener(FakeResponse(b"x"))
    with pytest.raises(FetchError):
        HttpFetcher(opener=opener).get(url)
    assert opener.requests == []


def test_oversize_answer_is_refused() -> None:
    opener = RecordingOpener(FakeResponse(b"x" * 101))
    with pytest.raises(FetchError, match="larger"):
        HttpFetcher(max_bytes=100, opener=opener).get("https://example.org/feed")


def test_oversize_answer_is_refused_by_its_declared_length() -> None:
    opener = RecordingOpener(FakeResponse(b"", {"Content-Length": str(6 * 1024 * 1024)}))
    with pytest.raises(FetchError, match="larger"):
        HttpFetcher(opener=opener).get("https://example.org/feed")


def test_default_cap_is_five_megabytes() -> None:
    assert HttpFetcher.MAX_BYTES == 5 * 1024 * 1024


def test_connection_failure_becomes_fetch_error() -> None:
    opener = RecordingOpener(urllib.error.URLError("name not resolved"))
    with pytest.raises(FetchError, match="name not resolved"):
        HttpFetcher(opener=opener).get("https://example.org/feed")


def test_redirect_to_plain_http_is_refused() -> None:
    fetcher = HttpFetcher()
    with pytest.raises(FetchError):
        fetcher._check_url("http://example.org/feed")


def test_uptime_mode_allows_http_and_cuts_long_answers() -> None:
    opener = RecordingOpener(FakeResponse(b"x" * 500))
    response = HttpFetcher(allow_http=True, max_bytes=100, truncate=True, opener=opener).get("http://example.org/")
    assert response.ok and len(response.body) == 100


# ---------------------------------------------------------------------------
# Feed fetches never reach internal addresses (DNS and HTTPS are faked)
# ---------------------------------------------------------------------------

PUBLIC = "93.184.215.14"
DNS: Dict[str, List[str]] = {
    "localhost": ["127.0.0.1", "::1"],
    "feeds.example.org": [PUBLIC],
    "mirror.example.org": ["93.184.215.15"],
    "split.example.org": [PUBLIC, "10.0.0.7"],
    "metadata.example.org": ["169.254.169.254"],
    "tailnet.example.org": ["100.100.100.100"],
}


def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> List[Any]:
    host = host.strip("[]")
    addresses = DNS.get(host, [host])     # an IP literal resolves to itself
    result = []
    for address in addresses:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        result.append((family, socket.SOCK_STREAM, 6, "", (address, port)))
    return result


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket.socket, "connect", _forbidden)


def _forbidden(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("network access during a test")


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/feed", "https://localhost/feed", "https://10.0.0.5/feed",
    "https://169.254.169.254/latest/meta-data/", "https://[::1]/feed",
    "https://[::ffff:127.0.0.1]/feed", "https://0.0.0.0/feed",
    "https://100.64.0.1/feed", "https://100.100.100.100/feed", "https://[fd7a:115c:a1e0::1]/feed",
    "https://192.0.0.8/feed", "https://198.18.0.1/feed",
])
def test_internal_hosts_are_refused(fake_dns: None, url: str) -> None:
    opener = RecordingOpener(FakeResponse(b"x"))
    with pytest.raises(FetchError, match="internal address"):
        HttpFetcher(public_only=True, opener=opener).get(url)
    assert opener.requests == []


def test_host_with_public_and_private_addresses_is_refused(fake_dns: None) -> None:
    opener = RecordingOpener(FakeResponse(b"x"))
    with pytest.raises(FetchError, match="10.0.0.7"):
        HttpFetcher(public_only=True, opener=opener).get("https://split.example.org/feed")
    assert opener.requests == []


def test_unresolvable_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_such_host(*args: Any, **kwargs: Any) -> Any:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", no_such_host)
    with pytest.raises(FetchError, match="could not be resolved"):
        HttpFetcher(public_only=True, opener=RecordingOpener(FakeResponse(b"x"))).get("https://nowhere.example/")


def test_name_that_resolves_into_carrier_nat_space_is_refused(fake_dns: None) -> None:
    opener = RecordingOpener(FakeResponse(b"x"))
    with pytest.raises(FetchError, match="100.100.100.100"):
        HttpFetcher(public_only=True, opener=opener).get("https://tailnet.example.org/feed")
    assert opener.requests == []


def test_public_host_is_fetched(fake_dns: None) -> None:
    opener = RecordingOpener(FakeResponse(b"feed"))
    assert HttpFetcher(public_only=True, opener=opener).get("https://feeds.example.org/feed").body == b"feed"


def test_without_the_option_local_hosts_stay_allowed(fake_dns: None) -> None:
    # uptime checks of the user's own (maybe local) sites
    opener = RecordingOpener(FakeResponse(b"ok"))
    fetcher = HttpFetcher(allow_http=True, truncate=True, opener=opener)
    assert fetcher.get("http://127.0.0.1:8000/").ok


class FakeHttps:
    """Stands in for urllib's HTTPS handler: answers from a table, opens no socket."""

    def __init__(self, answers: Dict[str, Any]) -> None:
        self.answers = answers
        self.urls: List[str] = []
        self.contexts: List[Any] = []

    def __call__(self, handler: Any, request: urllib.request.Request) -> Any:
        url = request.full_url
        self.urls.append(url)
        self.contexts.append(getattr(handler, "_context", None))
        status, body, headers = self.answers[url]
        message = Message()
        for name, value in headers.items():
            message[name] = value
        response = urllib.response.addinfourl(io.BytesIO(body), message, url, status)
        response.msg = "Found" if status in (301, 302) else "OK"    # type: ignore[attr-defined]
        return response


def https(monkeypatch: pytest.MonkeyPatch, answers: Dict[str, Any]) -> FakeHttps:
    fake = FakeHttps(answers)
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open",
                        lambda handler, request: fake(handler, request))
    return fake


def test_redirect_to_an_internal_address_is_refused(fake_dns: None, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = https(monkeypatch, {
        "https://feeds.example.org/feed": (302, b"", {"Location": "https://169.254.169.254/latest/meta-data/"}),
        "https://169.254.169.254/latest/meta-data/": (200, b"secret", {}),
    })
    with pytest.raises(FetchError, match="internal address"):
        HttpFetcher(public_only=True).get("https://feeds.example.org/feed")
    assert fake.urls == ["https://feeds.example.org/feed"]


def test_redirect_to_a_name_that_resolves_internally_is_refused(fake_dns: None, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = https(monkeypatch, {
        "https://feeds.example.org/feed": (301, b"", {"Location": "https://metadata.example.org/"}),
    })
    with pytest.raises(FetchError, match="internal address"):
        HttpFetcher(public_only=True).get("https://feeds.example.org/feed")
    assert fake.urls == ["https://feeds.example.org/feed"]


def test_redirect_to_another_public_host_works(fake_dns: None, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = https(monkeypatch, {
        "https://feeds.example.org/feed": (302, b"", {"Location": "https://mirror.example.org/feed.xml"}),
        "https://mirror.example.org/feed.xml": (200, b"<rss/>", {}),
    })
    response = HttpFetcher(public_only=True).get("https://feeds.example.org/feed")
    assert response.ok and response.body == b"<rss/>"
    assert fake.urls == ["https://feeds.example.org/feed", "https://mirror.example.org/feed.xml"]


def test_feed_refresh_refuses_a_source_on_an_internal_address(
    fake_dns: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oranovix_guardian.threat_intel.projects import ProjectRegistry
    from oranovix_guardian.threat_intel.service import ThreatFeedService
    from oranovix_guardian.threat_intel.settings import ThreatFeedSettings
    from oranovix_guardian.threat_intel.sources import SourceConfig
    from oranovix_guardian.threat_intel.store import FeedDatabase, ThreatStore

    fake = https(monkeypatch, {})
    database = FeedDatabase(str(tmp_path / "feed.db"))
    settings = ThreatFeedSettings(str(tmp_path / "settings.json"))
    settings.update(enabled=True, asked=True,
                    sources=(SourceConfig("Inside", "https://localhost/rss"),))

    report = ThreatFeedService(ThreatStore(database), ProjectRegistry(database), settings).refresh()

    assert len(report.failures) == 1 and "internal address" in report.failures[0]
    assert fake.urls == []


# ---------------------------------------------------------------------------
# TLS trust: the system store, never without verification
# ---------------------------------------------------------------------------

class FakeTruststore(types.ModuleType):
    """Stands in for the truststore package and remembers what it built."""

    def __init__(self, verifying: bool = True) -> None:
        super().__init__("truststore")
        self.built: List[ssl.SSLContext] = []
        self._verifying = verifying

    def SSLContext(self, protocol: int) -> ssl.SSLContext:      # noqa: N802 (name of the real class)
        context = ssl.SSLContext(protocol)
        if not self._verifying:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.built.append(context)
        return context


def assert_verifies(context: ssl.SSLContext) -> None:
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED


def test_context_comes_from_the_system_trust_store(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTruststore()
    monkeypatch.setitem(sys.modules, "truststore", fake)

    context = TlsTrust.context()

    assert fake.built == [context]
    assert_verifies(context)


def test_context_falls_back_to_certifi_without_truststore(monkeypatch: pytest.MonkeyPatch) -> None:
    import certifi

    asked: List[str] = []
    real_where = certifi.where
    monkeypatch.setitem(sys.modules, "truststore", None)        # import raises ImportError
    monkeypatch.setattr(certifi, "where", lambda: asked.append("where") or real_where())

    context = TlsTrust.context()

    assert asked == ["where"]
    assert_verifies(context)
    assert context.cert_store_stats()["x509_ca"] > 50           # the bundle was loaded


def test_context_still_verifies_without_truststore_and_certifi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "truststore", None)
    monkeypatch.setitem(sys.modules, "certifi", None)

    assert_verifies(TlsTrust.context())


def test_verification_is_switched_back_on_whatever_the_store_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "truststore", FakeTruststore(verifying=False))

    assert_verifies(TlsTrust.context())


def test_requests_and_redirects_use_the_same_verifying_context(
    fake_dns: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_store = FakeTruststore()
    monkeypatch.setitem(sys.modules, "truststore", fake_store)
    fake = https(monkeypatch, {
        "https://feeds.example.org/feed": (302, b"", {"Location": "https://mirror.example.org/feed.xml"}),
        "https://mirror.example.org/feed.xml": (200, b"<rss/>", {}),
    })

    assert HttpFetcher(public_only=True).get("https://feeds.example.org/feed").ok

    (context,) = fake_store.built
    assert fake.contexts == [context, context]
    assert_verifies(context)


def test_certificate_failure_is_its_own_error() -> None:
    untrusted = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain"
    )
    opener = RecordingOpener(urllib.error.URLError(untrusted))

    with pytest.raises(CertificateError) as caught:
        HttpFetcher(opener=opener).get("https://example.org/feed")

    text = str(caught.value)
    assert CertificateError.is_text_of(text)
    assert "self-signed certificate in certificate chain" in CertificateError.detail_of(text)


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("timed out"),
    urllib.error.URLError(ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")),
    ConnectionResetError("reset"),
])
def test_other_failures_are_not_certificate_errors(failure: Exception) -> None:
    with pytest.raises(FetchError) as caught:
        HttpFetcher(opener=RecordingOpener(failure)).get("https://example.org/feed")

    assert not isinstance(caught.value, CertificateError)
    assert not CertificateError.is_text_of(str(caught.value))
