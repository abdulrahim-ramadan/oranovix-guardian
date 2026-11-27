"""ThreatStore in a temporary SQLite file."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import pytest

from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.models import (
    CacheValidators,
    FeedItem,
    PackageRef,
    ProjectMatch,
    Relevance,
    SourceHealth,
)
from oranovix_guardian.threat_intel.store import FeedDatabase, ThreatStore, Timestamp

START = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def forward(self, **delta: float) -> None:
        self.now += timedelta(**delta)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> ThreatStore:
    return ThreatStore(FeedDatabase(str(tmp_path / "feed.db")), clock)


def item(key: str, title: str = "", published: Optional[datetime] = START, **extra) -> FeedItem:
    built = FeedItem.build("News", key, title or f"Headline {key}", f"https://example.org/{key}",
                           published=published, **extra)
    assert built is not None
    return built


MATCH = ProjectMatch(
    project="shop", project_path="/srv/shop", package="Django", ecosystem="PyPI",
    version="2.2.0", advisory_id="GHSA-fixt-ure1-0001", severity=Severity.CRITICAL,
    fixed_version="2.2.4", file_path="/srv/shop/requirements.txt", line=2,
)


def test_database_is_created_where_asked(tmp_path: Path) -> None:
    ThreatStore(FeedDatabase(str(tmp_path / "data" / "feed.db")))
    assert (tmp_path / "data" / "feed.db").is_file()
    assert FeedDatabase.default_path().name == "feed.db"


def test_item_round_trip(store: ThreatStore) -> None:
    original = item(
        "a", summary="Short text", cve_ids=["CVE-2019-14234"],
        packages=[PackageRef("", "Django")], is_known_exploited=True, severity_hint=Severity.HIGH,
    )
    assert store.add([original]) == [original]

    (stored,) = store.items()
    assert stored.item == original
    assert stored.first_seen == START
    assert stored.read is False
    assert stored.relevance is Relevance.GENERAL and stored.matches == ()


def test_items_are_deduplicated_by_id(store: ThreatStore, clock: Clock) -> None:
    store.add([item("a"), item("a"), item("b")])
    store.mark_read([item("a").id])
    clock.forward(hours=1)

    new = store.add([item("a", title="Corrected headline"), item("c")])

    assert [i.title for i in new] == ["Headline c"]
    assert store.count() == 3
    again = store.get(item("a").id)
    assert again is not None
    assert again.item.title == "Corrected headline"
    assert again.read is True and again.first_seen == START


def test_mark_read_and_unread_counts_per_relevance(store: ThreatStore) -> None:
    a, b, c, d = (item(key) for key in "abcd")
    store.add([a, b, c, d])
    store.set_relevance({
        a.id: (Relevance.AFFECTS_YOU, [MATCH]),
        b.id: (Relevance.POSSIBLE, []),
        c.id: (Relevance.POSSIBLE, []),
    })
    assert store.unread_counts() == {
        Relevance.AFFECTS_YOU: 1, Relevance.POSSIBLE: 2, Relevance.GENERAL: 1,
    }
    assert store.unread_for_you() == 3

    store.mark_read([b.id])
    assert store.unread_counts()[Relevance.POSSIBLE] == 1

    store.mark_read([b.id], read=False)
    store.mark_all_read([Relevance.AFFECTS_YOU, Relevance.POSSIBLE])
    assert store.unread_counts() == {
        Relevance.AFFECTS_YOU: 0, Relevance.POSSIBLE: 0, Relevance.GENERAL: 1,
    }


def test_relevance_and_matches_are_stored(store: ThreatStore) -> None:
    a = item("a")
    store.add([a])
    store.set_relevance({a.id: (Relevance.AFFECTS_YOU, [MATCH])})

    stored = store.get(a.id)
    assert stored is not None
    assert stored.relevance is Relevance.AFFECTS_YOU
    assert stored.matches == (MATCH,)
    assert stored.matches[0].confirmed


def test_items_that_affect_the_user_come_first_then_newest(store: ThreatStore) -> None:
    old = item("old", published=START - timedelta(days=3))
    new = item("new", published=START + timedelta(minutes=1))
    undated = item("undated", published=None)
    hit = item("hit", published=START - timedelta(days=30))
    store.add([old, new, undated, hit])
    store.set_relevance({hit.id: (Relevance.AFFECTS_YOU, [MATCH])})

    assert [s.item.title for s in store.items()] == [
        "Headline hit", "Headline new", "Headline undated", "Headline old",
    ]
    assert [s.item.title for s in store.items([Relevance.AFFECTS_YOU, Relevance.POSSIBLE])] == ["Headline hit"]
    assert store.items([]) == []
    assert len(store.items(limit=2)) == 2


def test_unread_only_filter(store: ThreatStore) -> None:
    store.add([item("a"), item("b")])
    store.mark_read([item("a").id])
    assert [s.item.title for s in store.items(unread_only=True)] == ["Headline b"]


def test_items_not_listed_for_90_days_are_removed(store: ThreatStore, clock: Clock) -> None:
    store.add([item("gone"), item("still-listed")])
    store.mark_alarmed(item("gone").id, "/srv/shop")
    clock.forward(days=60)
    store.add([item("still-listed")])
    clock.forward(days=31)                  # "gone" was last listed 91 days ago

    assert store.purge() == 1

    assert [s.item.title for s in store.items()] == ["Headline still-listed"]
    assert not store.was_alarmed(item("gone").id, "/srv/shop")


def test_item_listed_89_days_ago_is_kept(store: ThreatStore, clock: Clock) -> None:
    store.add([item("a")])
    clock.forward(days=89)
    assert store.purge() == 0 and store.count() == 1
    assert ThreatStore.RETENTION_DAYS == 90


def test_new_since(store: ThreatStore, clock: Clock) -> None:
    store.add([item("before")])
    clock.forward(hours=2)
    visit = clock.now
    clock.forward(hours=2)
    store.add([item("after"), item("before")])

    assert [s.item.title for s in store.new_since(visit)] == ["Headline after"]
    assert len(store.new_since(None)) == 2


def test_last_visit(store: ThreatStore, clock: Clock) -> None:
    assert store.last_visit() is None
    store.set_last_visit()
    assert store.last_visit() == START
    store.set_last_visit(START + timedelta(days=1))
    assert store.last_visit() == START + timedelta(days=1)


def test_alarm_memory_is_per_item_and_project(store: ThreatStore) -> None:
    assert not store.was_alarmed("item", "/srv/shop")
    store.mark_alarmed("item", "/srv/shop")
    store.mark_alarmed("item", "/srv/shop")
    assert store.was_alarmed("item", "/srv/shop")
    assert not store.was_alarmed("item", "/srv/blog")


def test_source_state_and_last_successful_update(store: ThreatStore) -> None:
    assert store.last_success() is None
    store.save_source(SourceHealth("KEV", START), CacheValidators('"v1"', "Mon, 16 Nov 2026 09:00:00 GMT"))
    store.save_source(
        SourceHealth("News", START - timedelta(hours=5), "timed out", START + timedelta(hours=1)),
        CacheValidators(),
    )

    states = store.source_states()
    assert states["KEV"] == (SourceHealth("KEV", START), CacheValidators('"v1"', "Mon, 16 Nov 2026 09:00:00 GMT"))
    assert states["News"][0].last_error == "timed out" and not states["News"][0].ok
    assert store.last_success() == START


def test_cached_items_survive_a_restart_offline(tmp_path: Path, clock: Clock) -> None:
    path = str(tmp_path / "feed.db")
    first = ThreatStore(FeedDatabase(path), clock)
    first.add([item("a"), item("b")])
    first.save_source(SourceHealth("News", START), CacheValidators())

    clock.forward(days=2)
    reopened = ThreatStore(FeedDatabase(path), clock)

    assert len(reopened.items()) == 2
    assert reopened.last_success() == START


def test_timestamps_sort_as_text() -> None:
    moments: List[datetime] = [
        START, START + timedelta(microseconds=5), START + timedelta(seconds=1),
        datetime(2026, 11, 16, 14, 0, tzinfo=timezone(timedelta(hours=2))),    # same as START
    ]
    texts = [Timestamp.text(m) or "" for m in moments]
    assert sorted(texts) == [texts[0], texts[3], texts[1], texts[2]]
    assert Timestamp.parse(texts[3]) == START
    assert Timestamp.parse("garbage") is None and Timestamp.text(None) is None
