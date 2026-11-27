"""Access log parsing: formats, hostile lines, client address."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from oranovix_guardian.log_sentinel.entry import ClientAddressResolver, NetworkList, parse_ip
from oranovix_guardian.log_sentinel.parsers import (
    MAX_LINE,
    JsonFieldMap,
    JsonLinesParser,
    LogFormat,
    LogFormatDetector,
    LogTime,
    NginxCombinedParser,
    parse_lines,
)

COMBINED = (
    '203.0.113.7 - - [16/Nov/2026:12:30:05 +0100] "GET /blog/hello-world/?page=2 HTTP/1.1" '
    '200 5120 "https://example.org/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)
COMMON = '198.51.100.4 - frank [16/Nov/2026:12:30:06 -0500] "POST /admin/login/ HTTP/1.1" 302 0'


def combined(ip: str = "203.0.113.7", request: str = "GET / HTTP/1.1", status: str = "200",
             size: str = "512", referer: str = "-", agent: str = "curl/8.0", extra: str = "") -> str:
    line = f'{ip} - - [16/Nov/2026:12:30:05 +0000] "{request}" {status} {size} "{referer}" "{agent}"'
    return line + (f' "{extra}"' if extra else "")


# ---------------------------------------------------------------------------
# Combined and common
# ---------------------------------------------------------------------------

def test_nginx_combined_line() -> None:
    entry = NginxCombinedParser().parse(COMBINED)

    assert entry is not None
    assert entry.client_ip == "203.0.113.7" and entry.peer_ip == ""
    assert (entry.method, entry.path, entry.query, entry.protocol) == ("GET", "/blog/hello-world/", "page=2", "HTTP/1.1")
    assert (entry.status, entry.size) == (200, 5120)
    assert entry.referer == "https://example.org/"
    assert entry.user_agent.startswith("Mozilla/5.0")
    assert entry.time == datetime(2026, 11, 16, 11, 30, 5, tzinfo=timezone.utc)
    assert entry.raw_length == len(COMBINED)


def test_apache_common_line() -> None:
    entry = NginxCombinedParser().parse(COMMON)

    assert entry is not None
    assert (entry.method, entry.path, entry.status, entry.size) == ("POST", "/admin/login/", 302, 0)
    assert entry.referer == "" and entry.user_agent == ""
    assert entry.time is not None and entry.time.utcoffset() == timedelta(hours=-5)


def test_dashes_for_status_and_size() -> None:
    entry = NginxCombinedParser().parse(combined(status="-", size="-", agent="-"))
    assert entry is not None and (entry.status, entry.size, entry.user_agent) == (0, 0, "")


def test_ipv6_client() -> None:
    entry = NginxCombinedParser().parse(combined(ip="2001:db8:85a3::8a2e:370:7334"))
    assert entry is not None and entry.client_ip == "2001:db8:85a3::8a2e:370:7334"


@pytest.mark.parametrize("agent, expected", [
    ('Mozilla/5.0 \\"quoted\\" thing', 'Mozilla/5.0 "quoted" thing'),          # Apache
    ("Mozilla/5.0 \\x22quoted\\x22 thing", 'Mozilla/5.0 "quoted" thing'),      # nginx
])
def test_quoted_quotes_inside_the_user_agent(agent: str, expected: str) -> None:
    entry = NginxCombinedParser().parse(combined(agent=agent))
    assert entry is not None and entry.user_agent == expected and entry.status == 200


def test_request_line_that_is_not_http() -> None:
    entry = NginxCombinedParser().parse(combined(request="\\x16\\x03\\x01\\x00", status="400"))
    assert entry is not None and entry.method == "" and entry.status == 400
    assert entry.path.startswith("\x16")


def test_binary_garbage_is_counted_and_reading_goes_on() -> None:
    parser = NginxCombinedParser()
    garbage = bytes(range(256)).decode("latin-1") * 3
    lines = [COMBINED, garbage, "", "not a log line", COMMON, "{broken json"]

    entries = parse_lines(parser, lines)

    assert [e.path for e in entries] == ["/blog/hello-world/", "/admin/login/"]
    assert (parser.stats.lines, parser.stats.parsed, parser.stats.malformed) == (5, 2, 3)


def test_hostile_one_megabyte_line_is_fast() -> None:
    # A request line that never closes its quote, with escapes and quotes inside.
    filler = ("A\\\"" * 10 + "%27" * 10 + " ") * 1 + "B" * 50
    line = '203.0.113.9 - - [16/Nov/2026:12:30:05 +0000] "GET /' + filler * (1024 * 1024 // len(filler) + 1)
    assert len(line) >= 1024 * 1024
    parser = NginxCombinedParser()

    started = time.perf_counter()
    entry = parser.parse(line)
    elapsed = time.perf_counter() - started

    assert entry is None and parser.stats.oversize == 1 and parser.stats.malformed == 1
    assert elapsed < 0.2


def test_long_but_complete_line_keeps_its_length() -> None:
    long_query = "q=" + "x" * (MAX_LINE * 2)
    line = combined(request=f"GET /search?{long_query} HTTP/1.1")
    entry = NginxCombinedParser().parse(line)
    # The cap cuts the line before the status, so it cannot be read; it is counted.
    assert entry is None


def test_forwarded_for_is_ignored_without_trusted_proxies() -> None:
    entry = NginxCombinedParser().parse(combined(ip="10.0.0.2", extra="198.51.100.66"))
    assert entry is not None and entry.client_ip == "10.0.0.2"


def test_forwarded_for_is_used_behind_a_trusted_proxy() -> None:
    parser = NginxCombinedParser(ClientAddressResolver(["10.0.0.0/8"]))
    entry = parser.parse(combined(ip="10.0.0.2", extra="198.51.100.66, 10.0.0.9"))
    assert entry is not None and entry.client_ip == "198.51.100.66" and entry.peer_ip == "10.0.0.2"


# ---------------------------------------------------------------------------
# JSON lines
# ---------------------------------------------------------------------------

def test_json_lines_with_default_fields() -> None:
    line = json.dumps({
        "time_iso8601": "2026-11-16T12:30:05+00:00", "remote_addr": "203.0.113.7",
        "request_method": "GET", "request_uri": "/shop/?q=shoes", "status": "404",
        "body_bytes_sent": 153, "http_referer": "", "http_user_agent": "Mozilla/5.0",
    })
    entry = JsonLinesParser().parse(line)

    assert entry is not None
    assert (entry.method, entry.path, entry.query, entry.status, entry.size) == ("GET", "/shop/", "q=shoes", 404, 153)
    assert entry.time == datetime(2026, 11, 16, 12, 30, 5, tzinfo=timezone.utc)


def test_json_lines_caddy_layout() -> None:
    line = json.dumps({
        "ts": 1794832205.5, "status": 200, "size": 42,
        "request": {"remote_ip": "2001:db8::1", "method": "GET", "uri": "/api/items?id=3",
                    "headers": {"User-Agent": ["Go-http-client/1.1"]}},
    })
    entry = JsonLinesParser().parse(line)
    assert entry is not None
    assert (entry.client_ip, entry.path, entry.query, entry.user_agent) == ("2001:db8::1", "/api/items", "id=3", "Go-http-client/1.1")


def test_json_field_mapping_is_configurable() -> None:
    fields = JsonFieldMap.from_settings({"client_ip": "src", "path": ["target"], "status": "code"})
    line = json.dumps({"src": "203.0.113.7", "target": "/x", "code": 403, "method": "GET"})
    entry = JsonLinesParser(fields).parse(line)
    assert entry is not None and (entry.client_ip, entry.path, entry.status) == ("203.0.113.7", "/x", 403)


@pytest.mark.parametrize("line", ['{"remote_addr": "1.2.3.4"}', "[1, 2]", '{"a": ', "plain text", "{}"])
def test_json_line_without_the_needed_fields_is_malformed(line: str) -> None:
    parser = JsonLinesParser()
    assert parser.parse(line) is None and parser.stats.malformed == 1


# ---------------------------------------------------------------------------
# Detection, time, addresses
# ---------------------------------------------------------------------------

def test_detector_picks_the_format_from_the_first_lines() -> None:
    detector = LogFormatDetector()
    json_line = json.dumps({"remote_addr": "203.0.113.7", "request": "GET / HTTP/1.1", "status": 200})
    assert detector.detect([COMBINED, COMMON, "junk"]) is LogFormat.COMBINED
    assert detector.detect([json_line] * 5 + [COMBINED]) is LogFormat.JSON
    assert detector.detect(["junk"] * 30) is LogFormat.COMBINED
    assert isinstance(detector.parser_for(LogFormat.AUTO, [json_line]), JsonLinesParser)


@pytest.mark.parametrize("value, expected", [
    ("16/Nov/2026:12:30:05 +0000", datetime(2026, 11, 16, 12, 30, 5, tzinfo=timezone.utc)),
    ("2026-11-16T12:30:05Z", datetime(2026, 11, 16, 12, 30, 5, tzinfo=timezone.utc)),
    (1794832205, datetime.fromtimestamp(1794832205, tz=timezone.utc)),
    ("1794832205000", datetime.fromtimestamp(1794832205, tz=timezone.utc)),
])
def test_time_formats(value: object, expected: datetime) -> None:
    assert LogTime.parse(value) == expected


@pytest.mark.parametrize("value", ["16/Okt/2026:12:30:05 +0000", "31/Feb/2026:00:00:00 +0000", "x" * 500, None])
def test_bad_times_are_none(value: object) -> None:
    assert LogTime.parse(value) is None


def test_ip_parsing_and_networks() -> None:
    assert str(parse_ip("[2001:db8::1]")) == "2001:db8::1"
    assert str(parse_ip("203.0.113.5:4711")) == "203.0.113.5"
    assert str(parse_ip("::ffff:203.0.113.5")) == "203.0.113.5"
    assert parse_ip("nonsense") is None
    networks = NetworkList(["10.0.0.0/8", "2001:db8::/32", "not-an-ip"])
    assert networks.contains("10.1.2.3") and networks.contains("2001:db8::5")
    assert not networks.contains("11.0.0.1") and networks.invalid == ["not-an-ip"]
