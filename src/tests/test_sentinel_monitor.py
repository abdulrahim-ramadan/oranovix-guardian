"""The monitor: tailing, rotation, limits, alarms and the planted file link."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Sequence

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from oranovix_guardian.live_defense.base import ChangeType, IntegrityEvent
from oranovix_guardian.log_sentinel.events import EventFactory, MemorySink
from oranovix_guardian.log_sentinel.monitor import (
    IntegrityPlantedPaths,
    LogSentinelMonitor,
    PlantedFile,
    PlantedPathProvider,
    SentinelConfig,
    WatchedLog,
)
from oranovix_guardian.log_sentinel.privacy import IpAnonymizer
from oranovix_guardian.log_sentinel.tail import LogTailer, TailStateStore
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory

START = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
KEY = b"k" * 32


def line(seconds: float, path: str = "/", status: int = 200, ip: str = "203.0.113.7",
         method: str = "GET", size: int = 2048, agent: str = "Mozilla/5.0") -> str:
    moment = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{moment}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"\n'


def sqli(seconds: float, status: int = 404, ip: str = "198.51.100.23") -> str:
    return line(seconds, "/item?id=1%27%20UNION%20SELECT%201,2,3--", status, ip)


def append(path: Path, *lines: str) -> None:
    with open(path, "a", encoding="utf-8", newline="") as handle:
        handle.writelines(lines)


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class SoundChannel(RecordingChannel):
    levels = frozenset({AlarmLevel.CRITICAL})


class Rig:
    def __init__(self, tmp_path: Path, logs: Sequence[Path] = (), planted: Optional[PlantedPathProvider] = None,
                 **config: object) -> None:
        self.tmp = tmp_path
        self.logs = list(logs) or [tmp_path / "access.log"]
        for log in self.logs:
            log.touch()
        self.sink = MemorySink()
        self.toast = RecordingChannel()
        self.sound = SoundChannel()
        self.alarm_center = AlarmCenter(
            store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")), channels=[self.toast, self.sound],
        )
        self.state = TailStateStore(str(tmp_path / "state.db"))
        self.config = SentinelConfig(logs=tuple(WatchedLog(str(log)) for log in self.logs), **config)  # type: ignore[arg-type]
        self.planted = planted
        self.monitor = self.build()

    def build(self) -> LogSentinelMonitor:
        return LogSentinelMonitor(
            self.config, self.sink, EventFactory(IpAnonymizer(KEY)), self.state, self.alarm_center,
            planted=self.planted, clock=lambda: START,
        )

    def cycle(self):
        return self.monitor.run_cycle()

    def rules(self) -> List[str]:
        return [event.rule_id for event in self.sink.events]


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    rig = Rig(tmp_path)
    rig.cycle()                     # first run: positions at the (empty) end
    return rig


# ---------------------------------------------------------------------------
# Tailing
# ---------------------------------------------------------------------------

def test_first_run_starts_at_the_end_of_the_log(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(sqli(0) * 50, encoding="utf-8")
    rig = Rig(tmp_path, [log])

    report = rig.cycle()

    assert report.new_events == () and report.files[0].bytes_read == 0
    append(log, sqli(10))
    assert rig.cycle().files[0].parsed == 1 and rig.rules() == ["LS101"]


def test_backfill_reads_the_last_bytes_once(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(line(0, "/old") * 100 + sqli(1) * 3, encoding="utf-8")
    rig = Rig(tmp_path, [log], backfill_bytes=len(sqli(1)) * 3 + 20)

    report = rig.cycle()

    assert report.files[0].parsed == 3 and report.files[0].malformed == 0     # the cut line is skipped
    assert [e.hits for e in report.new_events] == [3]
    assert rig.cycle().files[0].parsed == 0


def test_offset_survives_a_restart(rig: Rig) -> None:
    append(rig.logs[0], sqli(0), sqli(1))
    rig.cycle()
    rig.monitor = rig.build()                     # the app was closed and opened again

    append(rig.logs[0], line(700, "/item?id=1%20AND%20SLEEP(5)", ip="192.0.2.9"))
    report = rig.cycle()

    assert report.files[0].parsed == 1            # only the new line
    assert [e.rule_id for e in report.new_events] == ["LS101"]


def test_rotation_is_followed(rig: Rig) -> None:
    log = rig.logs[0]
    append(log, line(0), line(1))
    rig.cycle()
    os.replace(log, rig.tmp / "access.log.1")      # logrotate: rename, then a new file
    append(log, sqli(2))

    report = rig.cycle()

    assert report.files[0].rotated is True
    assert report.files[0].parsed == 1 and rig.rules() == ["LS101"]


def test_truncation_is_followed(rig: Rig) -> None:
    log = rig.logs[0]
    append(log, line(0) * 20)
    rig.cycle()
    log.write_text(sqli(5), encoding="utf-8")         # copytruncate: same file, shorter

    report = rig.cycle()

    assert report.files[0].truncated is True and rig.rules() == ["LS101"]


def test_a_line_still_being_written_waits(rig: Rig) -> None:
    log = rig.logs[0]
    whole = sqli(0)
    append(log, whole[:30])
    assert rig.cycle().files[0].lines == 0
    append(log, whole[30:])
    assert rig.cycle().files[0].lines == 1


def test_missing_log_is_reported_not_fatal(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.logs[0].unlink()
    assert rig.cycle().files[0].missing is True


def test_cycle_reads_at_most_the_cap_and_continues_next_time(rig: Rig) -> None:
    rig.monitor = LogSentinelMonitor(
        SentinelConfig(logs=rig.config.logs, max_bytes_per_cycle=10_000), rig.sink,
        EventFactory(IpAnonymizer(KEY)), rig.state, clock=lambda: START,
    )
    append(rig.logs[0], *(line(n * 0.01, f"/p/{n}") for n in range(1000)))

    first = rig.cycle().files[0]
    assert first.bytes_read <= 10_000 and first.pending > 0

    total = first.lines
    for _ in range(100):
        report = rig.cycle().files[0]
        total += report.lines
        if report.pending == 0:
            break
    assert total == 1000


def test_cap_is_shared_by_all_logs(tmp_path: Path) -> None:
    logs = [tmp_path / "a.log", tmp_path / "b.log"]
    rig = Rig(tmp_path, logs, max_bytes_per_cycle=5000)
    rig.cycle()
    for log in logs:
        append(log, *(line(n, f"/x/{n}") for n in range(200)))

    report = rig.cycle()

    assert sum(f.bytes_read for f in report.files) <= 5000


@pytest.mark.slow
def test_hundred_thousand_lines_in_under_fifteen_seconds(rig: Rig) -> None:
    """5.6 s was measured on a busy machine, against the former 5 s limit; 15 s leaves room for that."""
    lines = []
    for n in range(100_000):
        if n % 1000 == 0:
            lines.append(sqli(n * 0.01, ip=f"198.51.100.{n % 200}"))
        else:
            lines.append(line(n * 0.01, f"/blog/post-{n % 500}/?page={n % 7}", ip=f"203.0.113.{n % 250}"))
    append(rig.logs[0], *lines)

    started = time.perf_counter()
    parsed = 0
    for _ in range(20):
        report = rig.cycle().files[0]
        parsed += report.parsed
        if report.pending == 0:
            break
    elapsed = time.perf_counter() - started

    assert parsed == 100_000
    assert elapsed < 15.0, f"{elapsed:.2f} s"
    assert sum(e.hits for e in rig.sink.events if e.rule_id == "LS101") == 100


def test_unknown_lines_are_counted(rig: Rig) -> None:
    append(rig.logs[0], line(0), "garbage\n", "\x00\x01\x02\n", line(1))
    report = rig.cycle().files[0]
    assert (report.lines, report.parsed, report.malformed) == (4, 2, 2)


# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

def test_one_alarm_per_rule_address_and_ten_minutes(rig: Rig) -> None:
    append(rig.logs[0], *(sqli(n) for n in range(50)))
    rig.cycle()
    append(rig.logs[0], *(sqli(100 + n) for n in range(50)))      # same window, next cycle
    rig.cycle()

    assert len(rig.toast.alarms) == 1
    assert rig.toast.alarms[0].worst_issue.category is IssueCategory.ATTACK
    assert rig.toast.alarms[0].level is AlarmLevel.HIGH and rig.sound.alarms == []   # HIGH: no sound

    append(rig.logs[0], sqli(700))                                  # the next ten minutes
    rig.cycle()
    assert len(rig.toast.alarms) == 2


def test_events_of_one_window_are_folded(rig: Rig) -> None:
    append(rig.logs[0], *(sqli(n) for n in range(50)))
    report = rig.cycle()
    (event,) = report.new_events
    assert event.hits == 50 and event.last_time == START + timedelta(seconds=49)


def test_critical_alarms_with_sound_and_low_ones_not_at_all(rig: Rig) -> None:
    append(rig.logs[0], *(line(n, "/missing", 404, size=153) for n in range(3)))
    append(rig.logs[0], sqli(10, status=200))                       # answered with a real page
    append(rig.logs[0], line(20, "/wp-login.php", 404, ip="192.0.2.50"))
    rig.cycle()

    severities = {e.rule_id: e.severity for e in rig.sink.events}
    assert severities == {"LS101": Severity.CRITICAL, "LS110": Severity.LOW}
    assert [a.level for a in rig.sound.alarms] == [AlarmLevel.CRITICAL]
    assert len(rig.toast.alarms) == 1


def test_an_answered_attack_alarms_again_at_the_higher_level(rig: Rig) -> None:
    append(rig.logs[0], *(line(n, "/missing", 404, size=153) for n in range(3)), sqli(5))
    rig.cycle()
    append(rig.logs[0], sqli(6, status=200))
    rig.cycle()
    assert [a.level for a in rig.toast.alarms] == [AlarmLevel.HIGH, AlarmLevel.CRITICAL]


def test_the_monitor_runs_in_its_thread_and_reports(tmp_path: Path) -> None:
    import threading

    rig = Rig(tmp_path)
    reports = []
    done = threading.Event()

    def listener(report) -> None:
        reports.append(report)
        done.set()

    monitor = LogSentinelMonitor(rig.config, rig.sink, EventFactory(IpAnonymizer(KEY)), rig.state,
                                 on_sentinel_report=listener)
    monitor.start()
    try:
        assert done.wait(5)
    finally:
        assert monitor.stop(5)
    assert reports and reports[0].error == "" and monitor.interval == 10


# ---------------------------------------------------------------------------
# A planted file that is being requested
# ---------------------------------------------------------------------------

class FakePlanted(PlantedPathProvider):
    def __init__(self, files: Sequence[PlantedFile] = ()) -> None:
        self.files = list(files)
        self.calls = 0

    def planted_files(self) -> Sequence[PlantedFile]:
        self.calls += 1
        return self.files


SHELL = PlantedFile("NEW|shop/media/uploads/2026/x.php||abc", "shop/media/uploads/2026/x.php",
                    "/media/uploads/2026/x.php", Severity.CRITICAL)


def test_requesting_a_planted_file_is_critical_once(tmp_path: Path) -> None:
    provider = FakePlanted([SHELL])
    rig = Rig(tmp_path, planted=provider)
    rig.cycle()
    append(rig.logs[0],
           line(0, "/media/uploads/2026/x.php?cmd=id", 200, ip="192.0.2.66"),
           line(5, "/media/uploads/2026/X.php", 200, ip="192.0.2.67"))

    rig.cycle()

    linked = [e for e in rig.sink.events if e.rule_id == "LS301"]
    assert len(linked) == 1
    assert linked[0].severity is Severity.CRITICAL
    assert linked[0].evidence == "shop/media/uploads/2026/x.php <- GET /media/uploads/2026/x.php"
    assert linked[0].reasons[0].kwargs() == {"file": "shop/media/uploads/2026/x.php", "status": "200"}
    assert [a.level for a in rig.sound.alarms] == [AlarmLevel.CRITICAL]
    assert provider.calls == 2                  # once per cycle, not per line


@pytest.mark.parametrize("status", [403, 404, 500])
def test_a_refused_request_for_the_planted_file_is_not_linked(tmp_path: Path, status: int) -> None:
    rig = Rig(tmp_path, planted=FakePlanted([SHELL]))
    rig.cycle()
    append(rig.logs[0], line(0, "/media/uploads/2026/x.php", status))
    rig.cycle()
    assert "LS301" not in rig.rules()


def test_encoded_request_for_the_planted_file_is_linked(tmp_path: Path) -> None:
    rig = Rig(tmp_path, planted=FakePlanted([SHELL]))
    rig.cycle()
    append(rig.logs[0], line(0, "/media/uploads/2026/%78.php", 200))
    rig.cycle()
    assert "LS301" in rig.rules()


def test_link_works_without_a_provider(rig: Rig) -> None:
    append(rig.logs[0], line(0, "/media/uploads/2026/x.php", 200))
    rig.cycle()
    assert rig.rules() == []


def integrity_event(relative: str, change: ChangeType = ChangeType.NEW,
                    severity: Severity = Severity.CRITICAL) -> IntegrityEvent:
    return IntegrityEvent(change, severity, "/srv/shop", relative, ("new file",), new_sha256="abc")


def test_integrity_events_become_planted_files() -> None:
    provider = IntegrityPlantedPaths(lambda: [
        integrity_event("shop/media/uploads/2026/x.php"),
        integrity_event("shop/static/css/site.css", ChangeType.MODIFIED, Severity.MEDIUM),     # a deploy
        integrity_event("shop/static/js/app.js", ChangeType.MODIFIED, Severity.HIGH),
        integrity_event("shop/views.py", ChangeType.MODIFIED, Severity.HIGH),                  # not public
        integrity_event("shop/uploads/old.php", ChangeType.DELETED),
        integrity_event("shop/uploads/cat.jpg.phtml", ChangeType.NEW, Severity.MEDIUM),
    ])

    files = provider.planted_files()

    assert [(f.relative_path, f.url_suffix) for f in files] == [
        ("shop/media/uploads/2026/x.php", "/media/uploads/2026/x.php"),
        ("shop/static/js/app.js", "/static/js/app.js"),
        ("shop/uploads/cat.jpg.phtml", "/uploads/cat.jpg.phtml"),
    ]


def test_a_broken_provider_does_not_stop_the_monitor() -> None:
    def broken() -> List[IntegrityEvent]:
        raise RuntimeError("monitor stopped")
    assert IntegrityPlantedPaths(broken).planted_files() == []


def test_tailer_state_is_its_own_file(tmp_path: Path) -> None:
    store = TailStateStore(str(tmp_path / "positions.db"))
    log = tmp_path / "x.log"
    log.write_text("a\n", encoding="utf-8")
    LogTailer(str(log), store).read(100)
    assert (tmp_path / "positions.db").exists()
    assert store.get(str(log)) is not None


def test_attack_alarm_names_the_web_log() -> None:
    from oranovix_guardian.core.alarm_center import AlarmCenter as Center
    from oranovix_guardian.core.language_manager import LanguageManager
    from oranovix_guardian.scanner_engine.base import Issue

    LanguageManager().set_language("en")
    issue = Issue("LS101", "SQL injection attempt", "", Severity.HIGH, "/var/log/nginx/access.log", 0,
                  category=IssueCategory.ATTACK)
    assert Center.language_label(issue) == "Web log"


def test_live_defense_controller_offers_its_open_events(tmp_path: Path) -> None:
    from oranovix_guardian.live_defense.controller import LiveDefenseController, LiveDefenseSettings

    controller = LiveDefenseController(lambda fn: fn(), settings=LiveDefenseSettings(str(tmp_path / "s.json")))
    assert controller.open_events() == []           # not running: nothing to link
    assert IntegrityPlantedPaths(controller.open_events).planted_files() == []
