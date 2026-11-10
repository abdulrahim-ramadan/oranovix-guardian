"""AlarmCenter tests with a temporary SQLite store and a recording channel."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from core.alarm_center import (
    Alarm,
    AlarmCenter,
    AlarmChannel,
    AlarmLevel,
    SqliteSeenFindingStore,
)
from scanner_engine.base import Issue, Severity
from scanner_engine.categories import IssueCategory


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class CriticalOnlyChannel(RecordingChannel):
    levels = frozenset({AlarmLevel.CRITICAL})


def issue(severity: Severity, path: str = "/project/app.py", line: int = 3) -> Issue:
    return Issue(
        "SEC001", "Hardcoded Secret", "description", severity, path, line,
        category=IssueCategory.SECRET,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "alarms.db")


def test_critical_reaches_every_channel(db_path: str) -> None:
    toast, sound = RecordingChannel(), CriticalOnlyChannel()
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [toast, sound])

    alarm = center.notify([issue(Severity.CRITICAL)], "/project")

    assert alarm is not None and alarm.level is AlarmLevel.CRITICAL
    assert len(toast.alarms) == 1 and len(sound.alarms) == 1
    assert "app.py" in alarm.message and "3" in alarm.message
    assert alarm.counts_by_language == {"Python": 1}


def test_high_reaches_toast_only(db_path: str) -> None:
    toast, sound = RecordingChannel(), CriticalOnlyChannel()
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [toast, sound])

    alarm = center.notify([issue(Severity.HIGH)], "/project")

    assert alarm is not None and alarm.level is AlarmLevel.HIGH
    assert len(toast.alarms) == 1 and sound.alarms == []


def test_medium_and_low_raise_nothing(db_path: str) -> None:
    toast = RecordingChannel()
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [toast])

    assert center.notify([issue(Severity.MEDIUM), issue(Severity.LOW, line=9)]) is None
    assert toast.alarms == []


def test_same_finding_never_alarms_twice_even_after_restart(db_path: str) -> None:
    first = AlarmCenter(SqliteSeenFindingStore(db_path), [RecordingChannel()])
    assert first.notify([issue(Severity.CRITICAL)], "/project") is not None
    assert first.notify([issue(Severity.CRITICAL)], "/project") is None

    restarted = AlarmCenter(SqliteSeenFindingStore(db_path), [RecordingChannel()])
    assert restarted.notify([issue(Severity.CRITICAL)], "/project") is None
    assert restarted.notify([issue(Severity.CRITICAL, line=4)], "/project") is not None


def test_finding_id_is_stable_and_position_sensitive() -> None:
    base = AlarmCenter.finding_id(issue(Severity.CRITICAL), "/project")
    assert base == AlarmCenter.finding_id(issue(Severity.HIGH), "/project")
    assert base != AlarmCenter.finding_id(issue(Severity.CRITICAL, line=4), "/project")
    assert len(base) == 40


def test_new_finding_alarms_then_rescan_shows_banner_only(db_path: str) -> None:
    loud = CriticalOnlyChannel()
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [loud])
    findings = [issue(Severity.CRITICAL), issue(Severity.CRITICAL, line=8)]

    assert center.notify(findings, "/project") is not None
    assert len(loud.alarms) == 1

    assert center.notify(findings, "/project") is None
    assert len(loud.alarms) == 1
    assert "2" in AlarmCenter.open_critical_banner(findings)


def test_banner_is_empty_without_criticals() -> None:
    assert AlarmCenter.open_critical_banner([issue(Severity.HIGH)]) == ""


def test_fixed_then_reintroduced_finding_alarms_again(db_path: str) -> None:
    loud = CriticalOnlyChannel()
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [loud])
    finding = [issue(Severity.CRITICAL)]

    assert center.notify(finding, "/project") is not None
    assert center.notify([], "/project") is None          # fixed: scan is clean
    assert center.notify(finding, "/project") is not None  # reintroduced
    assert len(loud.alarms) == 2


def test_partial_report_does_not_forget_other_findings(db_path: str) -> None:
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [RecordingChannel()])
    finding = [issue(Severity.CRITICAL)]

    assert center.notify(finding, "/project") is not None
    assert center.notify([], "/project", full_scan=False) is None
    assert center.notify(finding, "/project") is None


def test_scan_of_another_root_does_not_forget_findings(db_path: str) -> None:
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [RecordingChannel()])
    finding = [issue(Severity.CRITICAL)]

    assert center.notify(finding, "/project") is not None
    assert center.notify([], "/other-project") is None
    assert center.notify(finding, "/project") is None


def test_store_upgrades_a_table_created_without_scan_root(db_path: str) -> None:
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE alarmed_findings ("
            "finding_id TEXT PRIMARY KEY, first_alarmed_at TEXT NOT NULL)"
        )
    center = AlarmCenter(SqliteSeenFindingStore(db_path), [RecordingChannel()])
    assert center.notify([issue(Severity.CRITICAL)], "/project") is not None
