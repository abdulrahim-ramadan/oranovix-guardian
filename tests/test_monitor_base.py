"""Monitor base: thread lifecycle, report delivery and alarms."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import List

from core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from live_defense.base import ChangeType, IntegrityEvent, Monitor, MonitorReport
from scanner_engine.base import Issue, Severity
from scanner_engine.categories import IssueCategory


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class ScriptedMonitor(Monitor):
    """Returns prepared events; signals each finished cycle."""

    def __init__(self, root: str, events: List[IntegrityEvent], **kwargs) -> None:
        super().__init__(root, **kwargs)
        self._events = events
        self.cycles = 0
        self.cycle_done = threading.Event()
        self.fail = False

    def check(self) -> List[IntegrityEvent]:
        self.cycles += 1
        self.cycle_done.set()
        if self.fail:
            raise RuntimeError("disk unreadable")
        events, self._events = self._events, []
        return events


def event(root: str, severity: Severity = Severity.CRITICAL, new_sha: str = "b" * 64) -> IntegrityEvent:
    return IntegrityEvent(
        change=ChangeType.MODIFIED, severity=severity, root=root,
        relative_path="app/settings.py", reasons=("Sensitive configuration file changed",),
        old_sha256="a" * 64, new_sha256=new_sha,
    )


def test_start_then_stop_ends_the_thread(tmp_path: Path) -> None:
    reports: List[MonitorReport] = []
    monitor = ScriptedMonitor(str(tmp_path), [], interval_seconds=3600, on_report=reports.append)

    monitor.start()
    assert monitor.cycle_done.wait(5)
    assert monitor.is_running

    assert monitor.stop() is True
    assert monitor.is_running is False
    assert monitor.cycles == 1                      # the long interval was interrupted
    assert len(reports) == 1


def test_start_twice_runs_one_thread(tmp_path: Path) -> None:
    monitor = ScriptedMonitor(str(tmp_path), [], interval_seconds=3600)

    monitor.start()
    first = monitor._thread
    monitor.start()

    assert monitor._thread is first
    assert monitor.stop()


def test_stop_without_start_is_harmless(tmp_path: Path) -> None:
    assert ScriptedMonitor(str(tmp_path), []).stop() is True


def test_report_carries_the_new_events(tmp_path: Path) -> None:
    reports: List[MonitorReport] = []
    planted = event(str(tmp_path))
    monitor = ScriptedMonitor(str(tmp_path), [planted], interval_seconds=3600, on_report=reports.append)

    monitor.start()
    monitor.cycle_done.wait(5)
    monitor.stop()

    assert reports[0].new_events == (planted,)
    assert reports[0].error == ""


def test_a_failing_cycle_is_reported_and_the_thread_survives(tmp_path: Path) -> None:
    reports: List[MonitorReport] = []
    monitor = ScriptedMonitor(str(tmp_path), [], interval_seconds=3600, on_report=reports.append)
    monitor.fail = True

    monitor.start()
    monitor.cycle_done.wait(5)
    assert monitor.is_running
    monitor.stop()

    assert reports[0].error == "RuntimeError: disk unreadable"


def test_interval_has_a_lower_bound(tmp_path: Path) -> None:
    monitor = ScriptedMonitor(str(tmp_path), [], interval_seconds=0)

    assert monitor.interval == Monitor.MIN_INTERVAL_SECONDS
    monitor.interval = 45
    assert monitor.interval == 45


def test_alarms_use_partial_view_and_state_key(tmp_path: Path) -> None:
    channel = RecordingChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    monitor = ScriptedMonitor(str(tmp_path), [], alarm_center=center)
    finding = Issue(
        rule_id="B307", title="Use of eval()", description="", severity=Severity.HIGH,
        file_path=str(tmp_path / "app" / "settings.py"), line_number=4,
        category=IssueCategory.CODE_EXEC,
    )
    first = event(str(tmp_path))
    first.findings.append(finding)

    alarm = monitor.raise_alarms([first])

    assert alarm is not None and alarm.level is AlarmLevel.CRITICAL
    assert len(alarm.finding_ids) == 2              # the event and its finding
    assert finding.finding_key == first.state_key
    # Same state again: silent. A second change (new hash): alarms again.
    assert monitor.raise_alarms([event(str(tmp_path))]) is None
    assert monitor.raise_alarms([event(str(tmp_path), new_sha="c" * 64)]) is not None


def test_partial_view_does_not_forget_other_findings(tmp_path: Path) -> None:
    channel = RecordingChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    monitor = ScriptedMonitor(str(tmp_path), [], alarm_center=center)
    monitor.raise_alarms([event(str(tmp_path))])

    # An empty cycle must not make the earlier alarm fire again later.
    monitor.raise_alarms([])
    assert monitor.raise_alarms([event(str(tmp_path))]) is None


def test_event_issue() -> None:
    planted = IntegrityEvent(
        change=ChangeType.NEW, severity=Severity.CRITICAL, root="/srv/site",
        relative_path="media/uploads/shell.php", reasons=("Web shell signature", "Executable in upload folder"),
        new_sha256="f" * 64, line_number=3,
    )

    issue = planted.to_issue()

    assert issue.rule_id == "FIM001"
    assert issue.category is IssueCategory.INTEGRITY
    assert issue.title == "New file: Web shell signature"
    assert issue.description == "Web shell signature; Executable in upload folder"
    assert issue.line_number == 3
    assert Path(issue.file_path) == Path("/srv/site/media/uploads/shell.php")
    assert planted.event_id == "NEW|media/uploads/shell.php||" + "f" * 64
