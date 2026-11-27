"""Rules over time, with made-up timestamps and a fake clock. No sleeping."""
from __future__ import annotations

import tracemalloc
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pytest

from oranovix_guardian.log_sentinel.behaviour import BehaviourConfig, BruteForceRule, IpStateTable, SentinelEngine
from oranovix_guardian.log_sentinel.entry import AccessLogEntry
from oranovix_guardian.log_sentinel.rules import Detection
from oranovix_guardian.scanner_engine.base import Severity

START = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
ATTACKER = "198.51.100.23"


class FakeClock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now


def request(path: str, status: int, seconds: float = 0, ip: str = ATTACKER, method: str = "GET",
            size: int = 2048, timed: bool = True) -> AccessLogEntry:
    when = START + timedelta(seconds=seconds) if timed else None
    target, _, query = path.partition("?")
    return AccessLogEntry(when, ip, method, target, query, status, size, user_agent="Mozilla/5.0")


def run(engine: SentinelEngine, entries: List[AccessLogEntry]) -> List[Detection]:
    return [detection for entry in entries for detection in engine.process(entry)]


def rule_ids(detections: List[Detection]) -> List[str]:
    return [d.rule_id for d in detections]


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

def failed_logins(count: int, start: float = 0, every: float = 10, ip: str = ATTACKER,
                  path: str = "/admin/login/", size: Optional[int] = None) -> List[AccessLogEntry]:
    # Django shows the form again with an error: 200, about the same size each time.
    return [request(path, 200, start + n * every, ip, "POST", (size or 4310) + n % 5) for n in range(count)]


def test_ten_failed_logins_in_five_minutes_are_high() -> None:
    engine = SentinelEngine()
    detections = run(engine, failed_logins(9))
    assert detections == []

    (detection,) = run(engine, failed_logins(1, start=95))

    assert (detection.rule_id, detection.severity) == ("LS201", Severity.HIGH)
    assert detection.reasons[0].kwargs() == {"count": "10", "path": "/admin/login", "minutes": "5"}


def test_failures_spread_over_more_than_five_minutes_are_not_counted_together() -> None:
    engine = SentinelEngine()
    assert run(engine, failed_logins(12, every=40)) == []          # 12 tries over 8 minutes


def test_401_and_403_count_as_failures() -> None:
    engine = SentinelEngine()
    entries = [request("/api/token/", 401 if n % 2 else 403, n, method="POST") for n in range(10)]
    assert rule_ids(run(engine, entries)) == ["LS201"]


def test_a_redirect_after_the_brute_force_is_critical() -> None:
    engine = SentinelEngine()
    run(engine, failed_logins(10))

    (success,) = run(engine, [request("/admin/login/", 302, 120, method="POST", size=0)])

    assert (success.rule_id, success.severity) == ("LS202", Severity.CRITICAL)
    assert success.reasons[0].key == "ls_reason_login_success"
    assert run(engine, [request("/admin/login/", 302, 130, method="POST", size=0)]) == []   # once


def test_a_200_of_another_size_after_the_brute_force_is_critical() -> None:
    engine = SentinelEngine()
    run(engine, [request("/api/login", 200, n, method="POST", size=44) for n in range(10)])   # {"error": ...}

    (success,) = run(engine, [request("/api/login", 200, 30, method="POST", size=612)])          # {"token": ...}

    assert success.rule_id == "LS202"


def test_a_normal_login_is_not_judged() -> None:
    engine = SentinelEngine()
    entries = failed_logins(2) + [request("/admin/login/", 302, 30, method="POST", size=0)]
    assert run(engine, entries) == []


def test_other_addresses_and_other_pages_are_counted_apart() -> None:
    engine = SentinelEngine()
    entries = failed_logins(5) + failed_logins(5, ip="203.0.113.9") + failed_logins(5, path="/accounts/login/")
    assert run(engine, entries) == []


def test_login_paths() -> None:
    assert BruteForceRule.is_login("/admin/login") and BruteForceRule.is_login("/wp-login.php")
    assert BruteForceRule.is_login("/api/v1/auth/token") and BruteForceRule.is_login("/accounts/login")
    assert not BruteForceRule.is_login("/blog/how-i-login-faster-guide") and not BruteForceRule.is_login("/catalog")


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def test_31_missing_paths_in_two_minutes_are_medium_and_101_are_high() -> None:
    engine = SentinelEngine(config=BehaviourConfig(flood_enabled=False))
    probes = [request(f"/probe-{n}.php", 404, n * 0.5) for n in range(110)]

    detections = [d for d in run(engine, probes) if d.rule_id == "LS203"]

    assert [(d.severity, d.reasons[0].kwargs()["count"]) for d in detections] == [
        (Severity.MEDIUM, "31"), (Severity.HIGH, "101"),
    ]


def test_slow_scan_stays_below_the_threshold() -> None:
    engine = SentinelEngine()
    probes = [request(f"/probe-{n}", 404, n * 5) for n in range(60)]     # one every 5 seconds
    assert run(engine, probes) == []


def test_the_same_missing_path_counts_once() -> None:
    engine = SentinelEngine()
    assert run(engine, [request("/favicon.ico", 404, n) for n in range(100)]) == []


# ---------------------------------------------------------------------------
# Floods
# ---------------------------------------------------------------------------

def test_more_than_300_requests_a_minute_is_medium_once() -> None:
    engine = SentinelEngine()
    entries = [request("/", 200, n * 0.1) for n in range(400)]           # 600 a minute

    detections = run(engine, entries)

    assert [(d.rule_id, d.severity) for d in detections] == [("LS204", Severity.MEDIUM)]


def test_flood_limit_is_configurable_and_can_be_off() -> None:
    entries = [request("/", 200, n * 0.5) for n in range(80)]
    assert rule_ids(run(SentinelEngine(config=BehaviourConfig(flood_per_minute=60)), entries)) == ["LS204"]
    assert run(SentinelEngine(config=BehaviourConfig(flood_enabled=False)), entries * 10) == []


# ---------------------------------------------------------------------------
# Allowlist, missing times, memory
# ---------------------------------------------------------------------------

def test_allowlisted_addresses_are_ignored_entirely() -> None:
    engine = SentinelEngine(allowlist=["198.51.100.0/24", "2001:db8::/32"])
    entries = failed_logins(20) + [request("/?q=%27%20or%201=1--", 200, 1)]
    entries += [request("/", 200, n * 0.05, ip="2001:db8::7") for n in range(500)]

    assert run(engine, entries) == []
    assert engine.skipped == len(entries)


def test_entries_without_a_time_use_the_clock() -> None:
    clock = FakeClock()
    engine = SentinelEngine(clock=clock)
    entries = [request("/admin/login/", 401, ip=ATTACKER, method="POST", timed=False) for _ in range(10)]
    assert rule_ids(run(engine, entries)) == ["LS201"]


def test_state_is_dropped_after_the_window() -> None:
    engine = SentinelEngine()
    for n in range(500):
        engine.process(request("/x", 404, n * 0.1, ip=f"203.0.113.{n % 250}"))
    assert engine.tracked() == 250

    engine.process(request("/x", 200, 3600, ip="192.0.2.1"))
    engine.prune()

    assert engine.tracked() == 1
    assert [rule.tracked for rule in engine.behaviour_rules] == [0, 0, 1]     # only the flood rule saw 192.0.2.1


def test_tracked_addresses_are_capped() -> None:
    engine = SentinelEngine(config=BehaviourConfig(max_tracked=1000))
    for n in range(5000):
        engine.process(request("/x", 404, n * 0.001, ip=f"10.{n // 65536}.{n // 256 % 256}.{n % 256}"))
    assert engine.tracked() == 1000


def test_fifty_thousand_addresses_stay_bounded_in_memory() -> None:
    engine = SentinelEngine()
    tracemalloc.start()
    try:
        for n in range(60_000):
            ip = f"10.{n // 65536}.{n // 256 % 256}.{n % 256}"
            engine.process(request(f"/missing-{n % 7}", 404, n * 0.001, ip=ip))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert engine.tracked() == 50_000
    assert peak < 200 * 1024 * 1024


def test_state_table_evicts_the_oldest_first() -> None:
    table: IpStateTable[list] = IpStateTable(list, cap=2)
    table.get("a", START)
    table.get("b", START)
    table.get("a", START)           # a is fresh again
    table.get("c", START)
    assert table.peek("b") is None and table.peek("a") is not None and len(table) == 2


@pytest.mark.parametrize("threshold", [1, 3])
def test_brute_force_threshold_is_configurable(threshold: int) -> None:
    engine = SentinelEngine(config=BehaviourConfig(brute_force_threshold=threshold))
    expected = max(2, threshold)
    assert rule_ids(run(engine, failed_logins(expected - 1))) == []
    assert rule_ids(run(engine, failed_logins(1, start=60))) == ["LS201"]
