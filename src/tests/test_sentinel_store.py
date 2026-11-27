"""Event store, privacy rules, CSV export and the PDF section. Everything in tmp_path."""
from __future__ import annotations

import csv
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.log_sentinel.entry import AccessLogEntry
from oranovix_guardian.log_sentinel.events import EventFactory, EventState, SecurityEvent
from oranovix_guardian.log_sentinel.export import AttackReport, CsvCell, EventExporter
from oranovix_guardian.log_sentinel.privacy import HIDDEN, HashKeyProvider, IpAnonymizer, RequestRedactor
from oranovix_guardian.log_sentinel.rules import AttackCategory, Detection, Reason
from oranovix_guardian.log_sentinel.store import EventFilter, SecurityEventStore
from oranovix_guardian.scanner_engine.base import Severity

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
KEY = bytes(range(32))


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture(autouse=True)
def english() -> None:
    LanguageManager().set_language("en")


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> SecurityEventStore:
    return SecurityEventStore(str(tmp_path / "events.db"), clock)


def detection(ip: str = "203.0.113.57", rule: str = "LS101", severity: Severity = Severity.HIGH,
              path: str = "/item", query: str = "id=1' union select 1,2--", seconds: float = 0,
              status: int = 404) -> Detection:
    entry = AccessLogEntry(NOW + timedelta(seconds=seconds), ip, "GET", path, query, status, 153)
    return Detection(rule, AttackCategory.SQL_INJECTION, severity, entry, evidence="union select 1",
                     reasons=(Reason.of("ls_reason_pattern", evidence="union select 1"),),
                     normalized=f"{path}?{query}" if query else path)


def event(ip: str = "203.0.113.57", keep_full: bool = False, **changes: object) -> SecurityEvent:
    return EventFactory(IpAnonymizer(KEY, keep_full)).build(detection(ip, **changes), "/var/log/nginx/access.log")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address, short", [
    ("203.0.113.57", "203.0.113.0"),
    ("2001:db8:85a3:1:2:3:4:5", "2001:db8:85a3::"),
    ("::ffff:198.51.100.9", "198.51.100.0"),
    ("[2001:db8::1]", "2001:db8::"),
    ("not an address", "?"),
])
def test_addresses_are_truncated(address: str, short: str) -> None:
    assert IpAnonymizer.truncate(address) == short


def test_events_keep_the_short_address_and_a_hash_by_default() -> None:
    first, again, neighbour = event("203.0.113.57"), event("203.0.113.57"), event("203.0.113.58")

    assert first.ip == "203.0.113.0" and neighbour.ip == "203.0.113.0"
    assert first.ip_hash == again.ip_hash != neighbour.ip_hash          # repeats still counted apart
    assert "203.0.113.57" not in repr(first)


def test_full_address_only_when_switched_on() -> None:
    assert event("203.0.113.57", keep_full=True).ip == "203.0.113.57"


def test_hash_depends_on_the_key() -> None:
    assert IpAnonymizer(KEY).hash("203.0.113.57") != IpAnonymizer(b"x" * 32).hash("203.0.113.57")
    with pytest.raises(ValueError):
        IpAnonymizer(b"short")


class MemoryKeys:
    def __init__(self, available: bool = True) -> None:
        self.value = ""
        self.available = available

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return self.available


def test_hash_key_lives_in_the_credential_store(store: SecurityEventStore) -> None:
    keys = MemoryKeys()
    first = HashKeyProvider(keys, store).key()
    assert len(first) == 32 and keys.value and HashKeyProvider(keys, store).key() == first

    fallback = HashKeyProvider(MemoryKeys(available=False), store).key()
    assert fallback == store.key() and len(fallback) == 32       # kept beside the events


@pytest.mark.parametrize("query, expected", [
    ("token=abc123&page=2", f"token={HIDDEN}&page=2"),
    ("password=hunter2", f"password={HIDDEN}"),
    ("api_key=sk_live_1&q=x", f"api_key={HIDDEN}&q=x"),
    ("sessionid=9f8e7d&x=1", f"sessionid={HIDDEN}&x=1"),
    ("Authorization=Bearer%20abc&a=1", f"Authorization={HIDDEN}&a=1"),
    ("jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", f"jwt={HIDDEN}"),
    ("next=/home&q=keyboard", "next=/home&q=keyboard"),
])
def test_secret_query_values_are_hidden(query: str, expected: str) -> None:
    assert RequestRedactor.target("/x", query) == f"/x?{expected}"


def test_tokens_in_free_text_are_hidden_and_long_requests_cut() -> None:
    text = RequestRedactor.text("GET /api?x=1 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln Bearer abcdefghijkl")
    assert "eyJ" not in text and "abcdefghijkl" not in text
    assert len(RequestRedactor.text("x" * 1000)) == 300


def test_event_request_is_cut_and_redacted() -> None:
    long_event = event(query="token=SECRET123&" + "a=" + "b" * 500)
    assert len(long_event.request) <= 300
    assert "SECRET123" not in long_event.request and HIDDEN in long_event.request
    assert long_event.request.startswith("GET /item?token=")


def test_secrets_in_the_evidence_are_hidden_too() -> None:
    entry = AccessLogEntry(NOW, "203.0.113.5", "GET", "/x", "password=hunter2'--", 404, 0)
    found = Detection("LS101", AttackCategory.SQL_INJECTION, Severity.HIGH, entry,
                      evidence="password=hunter2'--", reasons=(Reason.of("ls_reason_pattern", evidence="password=hunter2'--"),))
    built = EventFactory(IpAnonymizer(KEY)).build(found)
    assert "hunter2" not in built.evidence and "hunter2" not in built.reason_text()


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def test_events_are_stored_and_read_back(store: SecurityEventStore) -> None:
    (stored,) = store.add([event()])

    (read,) = store.events()
    assert stored.id == read.id > 0
    assert (read.rule_id, read.severity, read.ip, read.status, read.state) == (
        "LS101", Severity.HIGH, "203.0.113.0", 404, EventState.OPEN)
    assert read.reason_text() == "Matched: union select 1"
    assert read.source == "/var/log/nginx/access.log"


def test_the_same_attack_in_one_window_is_one_event(store: SecurityEventStore) -> None:
    store.add([event()])
    store.add([replace(event(seconds=60), hits=4)])
    store.add([event(seconds=700)])                     # next window

    events = store.events()
    assert [e.hits for e in events] == [1, 5]
    assert events[1].last_time == NOW + timedelta(seconds=60)


def test_an_acknowledged_event_is_not_counted_up(store: SecurityEventStore) -> None:
    (first,) = store.add([event()])
    store.acknowledge([first.id])
    store.add([event(seconds=30)])
    assert [(e.state, e.hits) for e in store.events()] == [(EventState.OPEN, 1), (EventState.ACKNOWLEDGED, 1)]


def test_filters_counts_and_acknowledge_all(store: SecurityEventStore) -> None:
    store.add([
        event(), event(ip="198.51.100.1", rule="LS102", severity=Severity.MEDIUM),
        event(ip="192.0.2.9", rule="LS301", severity=Severity.CRITICAL),
        event(ip="192.0.2.10", rule="LS110", severity=Severity.LOW),
    ])

    assert store.open_count() == 2
    assert store.count(EventFilter(severities=(Severity.MEDIUM,))) == 1
    assert sorted(e.rule_id for e in store.events(EventFilter(rule_ids=("LS101", "LS102")))) == ["LS101", "LS102"]
    assert store.rule_ids() == ["LS101", "LS102", "LS110", "LS301"]
    assert store.counts_per_rule() == {"LS101": 1, "LS102": 1, "LS110": 1, "LS301": 1}
    assert store.counts_per_day() == {"2026-11-16": 4}

    assert store.acknowledge_all(EventFilter(severities=(Severity.CRITICAL,))) == 1
    assert store.open_count() == 1
    assert store.acknowledge_all() == 3 and store.open_count() == 0


def test_top_attackers_are_grouped_by_hash_and_shown_short(store: SecurityEventStore) -> None:
    store.add([replace(event("203.0.113.57"), hits=40), event("203.0.113.58", severity=Severity.CRITICAL, rule="LS202")])
    store.add([event("203.0.113.57", rule="LS102", severity=Severity.MEDIUM)])

    attackers = store.top_attackers()

    assert [(a.ip, a.hits, a.events, a.worst) for a in attackers] == [
        ("203.0.113.0", 1, 1, Severity.CRITICAL), ("203.0.113.0", 41, 2, Severity.HIGH),
    ]
    assert attackers[0].ip_hash != attackers[1].ip_hash


def test_retention_removes_old_events(store: SecurityEventStore, clock: Clock) -> None:
    store.add([event()])
    clock.now = NOW + timedelta(days=20)
    store.add([event(seconds=20 * 86400)])

    clock.now = NOW + timedelta(days=31)
    assert store.purge() == 1
    assert len(store.events()) == 1
    assert store.purge(retention_days=5) == 1 and store.events() == []


def test_switching_full_addresses_off_truncates_the_stored_ones(store: SecurityEventStore) -> None:
    store.add([event("203.0.113.57", keep_full=True), event("2001:db8:85a3:1::9", keep_full=True)])

    assert store.forget_full_addresses() == 2
    assert sorted(e.ip for e in store.events()) == ["2001:db8:85a3::", "203.0.113.0"]


# ---------------------------------------------------------------------------
# CSV and PDF
# ---------------------------------------------------------------------------

def test_csv_export(tmp_path: Path, store: SecurityEventStore) -> None:
    store.add([event(), event(ip="198.51.100.1", rule="LS108", severity=Severity.HIGH, query="x==cmd|calc")])
    path = tmp_path / "events.csv"

    count = EventExporter.to_csv(store.events(), str(path))

    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle, delimiter=";"))
    assert count == 2
    assert rows[0][:5] == ["Time", "Severity", "Rule", "Attack", "Address"]
    assert {row[4] for row in rows[1:]} == {"203.0.113.0", "198.51.100.0"}
    assert all("203.0.113.57" not in cell for row in rows for cell in row)


@pytest.mark.parametrize("value, written", [
    ("=HYPERLINK(\"http://x\")", "'=HYPERLINK(\"http://x\")"),
    ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
    ("-2+3", "'-2+3"), ("@SUM(1)", "'@SUM(1)"), ("GET /x", "GET /x"),
])
def test_csv_cells_never_become_formulas(value: str, written: str) -> None:
    assert CsvCell.safe(value) == written


def test_pdf_section_with_attacks(tmp_path: Path, store: SecurityEventStore) -> None:
    from oranovix_guardian.reports.pdf_generator import PDFReportGenerator
    from oranovix_guardian.scanner_engine.base import ScanResult

    store.add([event(), event(ip="192.0.2.9", rule="LS301", severity=Severity.CRITICAL)])
    report = AttackReport.from_store(store)
    assert report.per_severity == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert [e.severity for e in report.events] == [Severity.CRITICAL, Severity.HIGH]

    rows = PDFReportGenerator.attack_rows(report, LanguageManager().t)
    assert rows[0][1:4] == ("CRITICAL", "A planted file is being requested: possible web shell in use", "192.0.2.0")

    result = ScanResult(target_path=str(tmp_path), scan_id="test", started_at=datetime(2026, 11, 16, 12, 0), finished_at=datetime(2026, 11, 16, 12, 1))
    out = PDFReportGenerator().generate(result, str(tmp_path / "report.pdf"), attacks=report)
    assert Path(out).stat().st_size > 1000


def test_no_section_without_events(tmp_path: Path, store: SecurityEventStore) -> None:
    assert AttackReport.from_store(store).empty
