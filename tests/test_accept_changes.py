"""Accepting changes: the baseline moves on, events close, later changes alarm again."""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import List

import pytest

from core.alarm_center import Alarm, AlarmCenter, AlarmChannel, SqliteSeenFindingStore
from live_defense.base import ChangeType
from live_defense.baseline import Baseline, BaselineError
from live_defense.file_integrity import FileIntegrityMonitor


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


def write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def modify(path: Path, text: str) -> None:
    before = path.stat().st_mtime_ns
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    site = tmp_path / "site"
    write(site / "shop" / "settings.py", "DEBUG = False\n")
    write(site / "shop" / "views.py", "x = 1\n")
    write(site / "README.md", "# Shop\n")
    return site


@pytest.fixture
def channel() -> RecordingChannel:
    return RecordingChannel()


@pytest.fixture
def baseline(root: Path, tmp_path: Path) -> Baseline:
    created = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())
    created.create()
    return created


@pytest.fixture
def monitor(baseline: Baseline, tmp_path: Path, channel: RecordingChannel) -> FileIntegrityMonitor:
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    return FileIntegrityMonitor(baseline, alarm_center=center, file_scanner=lambda path: [])


def test_accept_clears_the_event_and_a_later_change_alarms_again(
    monitor: FileIntegrityMonitor, baseline: Baseline, root: Path, channel: RecordingChannel
) -> None:
    settings = root / "shop" / "settings.py"
    modify(settings, "DEBUG = True\n")
    (event,) = monitor.check()
    assert len(channel.alarms) == 1                     # HIGH: toast

    assert monitor.accept([event.event_id]) == 1

    assert monitor.open_events() == []
    assert baseline.verify().ok                         # re-signed
    assert monitor.check(full=True) == []              # nothing left to report

    modify(settings, "DEBUG = True\nALLOWED_HOSTS = ['*']\n")
    (again,) = monitor.check()
    assert again.change is ChangeType.MODIFIED
    assert again.old_sha256 == event.new_sha256         # compared with the accepted state
    assert len(channel.alarms) == 2


def test_accept_one_leaves_the_others_open(monitor: FileIntegrityMonitor, root: Path) -> None:
    modify(root / "shop" / "views.py", "x = 2\n")
    write(root / "new.txt")
    events = {e.relative_path: e for e in monitor.check()}

    monitor.accept([events["new.txt"].event_id])

    assert [e.relative_path for e in monitor.open_events()] == ["shop/views.py"]


def test_accept_all(monitor: FileIntegrityMonitor, baseline: Baseline, root: Path) -> None:
    modify(root / "shop" / "views.py", "x = 2\n")
    write(root / "new.txt")
    (root / "README.md").unlink()
    monitor.check()

    assert monitor.accept_all() == 3

    assert monitor.open_events() == []
    assert sorted(baseline.entries()) == ["new.txt", "shop/settings.py", "shop/views.py"]
    assert monitor.check(full=True) == []


def test_accepting_a_deleted_file_removes_it_from_the_baseline(
    monitor: FileIntegrityMonitor, baseline: Baseline, root: Path
) -> None:
    (root / "README.md").unlink()
    (event,) = monitor.check()

    monitor.accept([event.event_id])

    assert "README.md" not in baseline.entries()


def test_accept_closes_every_event_of_that_file(monitor: FileIntegrityMonitor, root: Path) -> None:
    views = root / "shop" / "views.py"
    modify(views, "x = 2\n")
    (first,) = monitor.check()
    modify(views, "x = 3\n")
    monitor.check()
    assert len(monitor.open_events()) == 2

    monitor.accept([first.event_id])

    assert monitor.open_events() == []


def test_accept_takes_the_state_on_disk_now(
    monitor: FileIntegrityMonitor, baseline: Baseline, root: Path
) -> None:
    views = root / "shop" / "views.py"
    modify(views, "x = 2\n")
    (event,) = monitor.check()
    modify(views, "x = 3 # changed again before accepting\n")

    monitor.accept([event.event_id])

    import hashlib
    assert baseline.entries()["shop/views.py"].sha256 == hashlib.sha256(views.read_bytes()).hexdigest()


def test_unaccepted_event_stays_open(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "new.txt")
    monitor.check()

    for _ in range(3):
        monitor.check()

    assert [e.relative_path for e in monitor.open_events()] == ["new.txt"]


def test_unknown_ids_change_nothing(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "new.txt")
    monitor.check()

    assert monitor.accept(["NEW|other.txt||abc"]) == 0
    assert len(monitor.open_events()) == 1


def test_tamper_event_cannot_be_accepted(
    monitor: FileIntegrityMonitor, baseline: Baseline
) -> None:
    with closing(sqlite3.connect(baseline.db_path)) as conn:
        conn.execute(f"UPDATE {baseline._table} SET size = size + 1")
        conn.commit()
    (event,) = monitor.check()

    assert monitor.accept([event.event_id]) == 0
    assert monitor.accept_all() == 0
    assert [e.change for e in monitor.open_events()] == [ChangeType.TAMPERED]


def test_accept_refuses_a_tampered_baseline(
    monitor: FileIntegrityMonitor, baseline: Baseline, root: Path
) -> None:
    write(root / "new.txt")
    (event,) = monitor.check()
    with closing(sqlite3.connect(baseline.db_path)) as conn:
        conn.execute(f"DELETE FROM {baseline._table} WHERE path = 'README.md'")
        conn.commit()

    with pytest.raises(BaselineError, match="modified outside the app"):
        monitor.accept([event.event_id])


def test_new_ignore_pattern_closes_matching_events(
    monitor: FileIntegrityMonitor, root: Path
) -> None:
    write(root / "cache" / "page.html")
    write(root / "notes.txt")
    monitor.check()

    monitor.set_ignore_patterns(["cache/"])

    assert [e.relative_path for e in monitor.open_events()] == ["notes.txt"]
    assert monitor.check() == []
