"""Attacking Log Sentinel itself: evasions, hostile input, rotation, volume, a benign day,
a guessed password and a web shell in use. Payloads are built here at runtime."""
from __future__ import annotations

import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from oranovix_guardian.live_defense.baseline import Baseline
from oranovix_guardian.live_defense.file_integrity import FileIntegrityMonitor
from oranovix_guardian.log_sentinel.entry import AccessLogEntry
from oranovix_guardian.log_sentinel.events import EventFactory, MemorySink
from oranovix_guardian.log_sentinel.monitor import IntegrityPlantedPaths, LogSentinelMonitor, PlantedPathProvider, SentinelConfig, WatchedLog
from oranovix_guardian.log_sentinel.privacy import IpAnonymizer
from oranovix_guardian.log_sentinel.rules import RequestAnalyzer
from oranovix_guardian.log_sentinel.tail import TailStateStore
from oranovix_guardian.scanner_engine.base import Severity

START = datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc)


def log_line(seconds: float, ip: str, method: str, target: str, status: int, size: int,
             agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0", referer: str = "-") -> str:
    moment = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{moment}] "{method} {target} HTTP/1.1" {status} {size} "{referer}" "{agent}"\n'


class Recorder(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class Sound(Recorder):
    levels = frozenset({AlarmLevel.CRITICAL})


class Watch:
    """A monitor on a log in tmp_path, with recording alarm channels."""

    def __init__(self, tmp_path: Path, planted: Optional[PlantedPathProvider] = None, **config: object) -> None:
        self.log = tmp_path / "access.log"
        self.log.write_text("", encoding="utf-8")
        self.sink = MemorySink()
        self.toast, self.sound = Recorder(), Sound()
        self.monitor = LogSentinelMonitor(
            SentinelConfig(logs=(WatchedLog(str(self.log)),), **config),  # type: ignore[arg-type]
            self.sink, EventFactory(IpAnonymizer(b"z" * 32)), TailStateStore(str(tmp_path / "state.db")),
            AlarmCenter(store=SqliteSeenFindingStore(str(tmp_path / "alarms.db")), channels=[self.toast, self.sound]),
            planted=planted,
        )
        self.monitor.run_cycle()

    def append(self, lines: List[str]) -> None:
        with open(self.log, "a", encoding="utf-8", newline="") as handle:
            handle.writelines(lines)

    def drain(self, cycles: int = 50) -> None:
        for _ in range(cycles):
            if self.monitor.run_cycle().files[0].pending == 0:
                return

    def above(self, severity: Severity) -> List[str]:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return [f"{e.rule_id} {e.severity.value} {e.request}" for e in self.sink.events
                if order.index(e.severity) > order.index(severity)]


# ---------------------------------------------------------------------------
# 1. SQL injection behind every disguise at once
# ---------------------------------------------------------------------------

def disguise(payload: str, rounds: int) -> str:
    text = payload
    for _ in range(rounds):
        text = quote(text, safe="")
    return text


def mixed(text: str) -> str:
    return "".join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(text))


@pytest.mark.parametrize("payload", [
    "1'/**/" + mixed("union") + "/**/" + mixed("select") + "/**/1,2,3#",
    "1'/*!50000" + mixed("union") + "*//*!50000" + mixed("select") + "*/1,2,3-- -",
    "1' " + mixed("or") + "/**/'x'='x",
    "1)" + mixed("or") + "(1=1)-- ",
    "1' " + mixed("and") + "/**/" + mixed("sleep") + "(5)#",
    "1;" + mixed("waitfor") + " " + mixed("delay") + " '0:0:5'--",
    "-1 " + mixed("union") + "\n" + mixed("select") + " null,@@version",          # a newline between
    "1'" + "／**／" + mixed("union") + " " + mixed("select") + " 1,2",     # full width slashes
])
@pytest.mark.parametrize("rounds", [1, 2, 3])
def test_sql_injection_with_double_encoding_case_and_comment_tricks(payload: str, rounds: int) -> None:
    entry = AccessLogEntry(START, "198.51.100.23", "GET", "/item", "id=" + disguise(payload, rounds), 404, 153)
    assert "LS101" in {d.rule_id for d in RequestAnalyzer().analyze(entry)}, (payload, rounds)


# ---------------------------------------------------------------------------
# 2. A hostile 1 MB line in a live log
# ---------------------------------------------------------------------------

def test_four_layers_of_encoding_are_one_too_many() -> None:
    """Known limit: three rounds of decoding. A fourth layer stays encoded (and would not
    work against a server that decodes once or twice either)."""
    payload = disguise("1' " + "union" + " " + "select" + " 1,2--", 4)
    entry = AccessLogEntry(START, "198.51.100.23", "GET", "/item", "id=" + payload, 404, 153)
    assert "LS101" not in {d.rule_id for d in RequestAnalyzer().analyze(entry)}


def test_one_megabyte_line_in_the_log_is_skipped_quickly(tmp_path: Path) -> None:
    watch = Watch(tmp_path)
    hostile = '203.0.113.9 - - [17/Nov/2026:08:00:00 +0000] "GET /' + ('%27\\"' * 200_000) + "\n"
    watch.append([hostile, log_line(1, "198.51.100.5", "GET", "/item?id=1%27%20or%20%271%27=%271", 404, 153)])

    started = time.perf_counter()
    report = watch.monitor.run_cycle()
    elapsed = time.perf_counter() - started

    assert elapsed < 0.5
    assert (report.files[0].lines, report.files[0].malformed) == (2, 1)
    assert [e.rule_id for e in watch.sink.events] == ["LS101"]          # the next line still counts


# ---------------------------------------------------------------------------
# 3. Rotation in the middle of reading
# ---------------------------------------------------------------------------

def test_log_rotated_while_being_read(tmp_path: Path) -> None:
    watch = Watch(tmp_path, max_bytes_per_cycle=4000)
    first = [log_line(n, "203.0.113.5", "GET", f"/page/{n}", 200, 900) for n in range(100)]
    watch.append(first)
    partial = watch.monitor.run_cycle().files[0]
    assert partial.pending > 0                                          # still reading the old file

    os.replace(watch.log, tmp_path / "access.log.1")
    watch.append([log_line(200, "198.51.100.7", "GET", "/.env", 404, 153)])
    read = partial.lines
    for _ in range(20):
        report = watch.monitor.run_cycle().files[0]
        read += report.lines
        if report.pending == 0 and read > len(first):
            break

    assert read == len(first) + 1                   # the rest of the old file, then the new one
    assert [e.rule_id for e in watch.sink.events] == ["LS109"]


def test_rotation_to_another_name_starts_the_new_file(tmp_path: Path) -> None:
    """Known limit: only "<name>.1" is looked for; a date suffix loses the unread rest."""
    watch = Watch(tmp_path, max_bytes_per_cycle=4000)
    watch.append([log_line(n, "203.0.113.5", "GET", f"/page/{n}", 200, 900) for n in range(100)])
    watch.monitor.run_cycle()
    os.replace(watch.log, tmp_path / "access.log-20261117")
    watch.append([log_line(200, "198.51.100.7", "GET", "/.env", 404, 153)])

    report = watch.monitor.run_cycle().files[0]

    assert report.rotated and report.parsed == 1


# ---------------------------------------------------------------------------
# 4. Fifty thousand addresses
# ---------------------------------------------------------------------------

def test_fifty_thousand_addresses_through_the_monitor(tmp_path: Path) -> None:
    watch = Watch(tmp_path)
    lines = [log_line(n * 0.01, f"10.{n // 65536}.{n // 256 % 256}.{n % 256}", "GET", f"/x/{n % 50}", 404, 153)
             for n in range(50_000)]
    watch.append(lines)

    started = time.perf_counter()
    watch.drain()
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0
    assert watch.sink.events == []          # one miss per address is nobody's attack
    engine = watch.monitor._files[0].engine
    assert engine.tracked() <= 50_000


# ---------------------------------------------------------------------------
# 5. A benign day: 5,000 realistic lines, nothing above LOW
# ---------------------------------------------------------------------------

def benign_day(count: int = 5000) -> List[str]:
    rng = random.Random(1117)
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]
    slugs = ["union-select-the-best-candidates", "how-to-select-a-union", "etc-passwd-guide", "script-writing-101",
             "why-or-1-equals-1-is-funny", "drop-table-tennis-tips", "sleep-better-in-winter", "admin-tips"]
    searches = ["O'Brien", "rock 'n' roll", "salt & pepper", "c# vs java", "what's new?", "50% off",
                "javascript: the good parts", "prompt (engineering)", "id card", "select union rep"]
    admin = ["/admin/", "/admin/shop/order/", "/admin/shop/order/?status__exact=paid&o=-2",
             "/admin/shop/order/{n}/change/", "/admin/shop/product/?q=O%27Brien", "/admin/auth/user/{n}/change/",
             "/admin/jsi18n/", "/admin/shop/order/{n}/history/"]
    lines = []
    for n in range(count):
        second = n * 17.0          # one day
        ip = f"203.0.113.{rng.randrange(1, 254)}"
        kind = rng.random()
        if kind < 0.25:
            target, status, size = f"/blog/{rng.choice(slugs)}/", 200, 9000 + rng.randrange(900)
        elif kind < 0.40:
            target = "/search/?q=" + quote(rng.choice(searches)).replace("%20", "+")
            status, size = 200, 7000 + rng.randrange(500)
        elif kind < 0.55:
            target = rng.choice(admin).format(n=rng.randrange(1, 500))
            status, size = (302, 0) if rng.random() < 0.05 else (200, 12000 + rng.randrange(4000))
            ip = "198.51.100.10"        # the shop owner
        elif kind < 0.75:
            target = rng.choice(["/static/js/script-v2.js", "/static/css/site.css?v=4", "/static/admin/js/core.js",
                                 "/media/uploads/2026/11/photo.jpg", "/favicon.ico"])
            status, size = 200, 30000 + rng.randrange(9000)
        elif kind < 0.80:
            target, status, size = f"/old/link-{rng.randrange(40)}/", 404, 1532      # old links, now and then
        elif kind < 0.85:
            # a customer mistypes the password once or twice, then gets in
            target, status, size = "/accounts/login/?next=/checkout/", 200, 4310 + rng.randrange(20)
            lines.append(log_line(second, ip, "POST", target, status, size, rng.choice(browsers[:3])))
            target, status, size = "/accounts/login/?next=/checkout/", 302, 0
            lines.append(log_line(second + 4, ip, "POST", target, status, size, rng.choice(browsers[:3])))
            continue
        elif kind < 0.90:
            data = quote("data:image/png;base64," + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(400)), safe="")
            target, status, size = f"/editor/preview/?img={data}", 200, 512
        else:
            target = f"/shop/?category={rng.randrange(1, 30)}&page={rng.randrange(1, 9)}&sort=-price"
            status, size = 200, 20000 + rng.randrange(3000)
        lines.append(log_line(second, ip, "GET", target, status, size, rng.choice(browsers)))
    # the uptime monitor every minute, all day
    lines += [log_line(n * 60, "192.0.2.200", "GET", "/health/", 200, 2, "UptimeRobot/2.0") for n in range(1440)]
    lines.sort(key=lambda text: text.split("[", 1)[1][:20])
    return lines


def test_a_benign_day_raises_nothing_above_low(tmp_path: Path) -> None:
    watch = Watch(tmp_path)
    day = benign_day()
    assert len(day) >= 5000
    watch.append(day)

    watch.drain()

    assert watch.above(Severity.LOW) == []
    assert watch.toast.alarms == [] and watch.sound.alarms == []


# ---------------------------------------------------------------------------
# 6. Brute force, then a redirect
# ---------------------------------------------------------------------------

def test_brute_force_followed_by_a_302_is_critical_with_sound(tmp_path: Path) -> None:
    watch = Watch(tmp_path)
    attacker = "198.51.100.66"
    lines = [log_line(n * 3, attacker, "POST", "/admin/login/?next=/admin/", 200, 4310 + n % 9) for n in range(12)]
    lines.append(log_line(40, attacker, "POST", "/admin/login/?next=/admin/", 302, 0))
    lines.append(log_line(41, attacker, "GET", "/admin/", 200, 21880))
    watch.append(lines)

    watch.drain()

    rules = {e.rule_id: e.severity for e in watch.sink.events}
    assert rules == {"LS201": Severity.HIGH, "LS202": Severity.CRITICAL}
    assert [a.level for a in watch.sound.alarms] == [AlarmLevel.CRITICAL]


# ---------------------------------------------------------------------------
# 7. A web shell planted in uploads and then requested
# ---------------------------------------------------------------------------

class Keys:
    value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


def test_planted_file_in_uploads_requested_after_it_appears(tmp_path: Path) -> None:
    site = tmp_path / "shop"
    (site / "media" / "uploads").mkdir(parents=True)
    (site / "shop").mkdir()
    (site / "shop" / "views.py").write_text("def index(request):\n    return None\n", encoding="utf-8")
    baseline = Baseline(str(site), str(tmp_path / "integrity.db"), Keys())
    baseline.create()
    integrity = FileIntegrityMonitor(baseline, file_scanner=lambda path: [])
    watch = Watch(tmp_path, planted=IntegrityPlantedPaths(integrity.open_events))

    # A request for the path before the file exists: 404, nothing to link.
    watch.append([log_line(0, "198.51.100.90", "GET", "/media/uploads/avatar.php", 404, 153)])
    watch.drain()
    assert "LS301" not in {e.rule_id for e in watch.sink.events}

    # The file appears; the integrity monitor reports it.
    shell = site / "media" / "uploads" / "avatar.php"
    shell.write_text("<?php echo 'hello'; ?>\n", encoding="utf-8")
    events = integrity.check(full=True)
    assert any(e.relative_path == "media/uploads/avatar.php" for e in events)

    # Now it is served.
    watch.append([log_line(60, "198.51.100.90", "POST", "/media/uploads/avatar.php?c=id", 200, 48)])
    watch.drain()

    linked = [e for e in watch.sink.events if e.rule_id == "LS301"]
    assert len(linked) == 1 and linked[0].severity is Severity.CRITICAL
    assert "media/uploads/avatar.php" in linked[0].evidence
    assert any(a.level is AlarmLevel.CRITICAL and a.worst_issue.rule_id == "LS301" for a in watch.sound.alarms)
