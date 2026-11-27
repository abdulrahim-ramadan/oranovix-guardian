"""
Rules over time: brute force, path scans and floods.

They keep a little state per client address. That state is dropped as
soon as its window has passed, and no rule ever tracks more than
``MAX_TRACKED`` addresses, so a log with millions of addresses cannot
eat the memory.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Deque, Dict, Generic, Iterable, List, Optional, Sequence, Set, Tuple, TypeVar

from oranovix_guardian.scanner_engine.base import Severity

from .entry import AccessLogEntry, NetworkList
from .normalize import NormalizedRequest
from .rules import AttackCategory, Detection, Reason, RequestAnalyzer

Clock = Callable[[], datetime]
State = TypeVar("State")
MAX_TRACKED = 50_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IpStateTable(Generic[State]):
    """Per-address state, oldest first. Bounded in time and in size."""

    def __init__(self, factory: Callable[[], State], cap: int = MAX_TRACKED) -> None:
        self._factory = factory
        self._cap = cap
        self._states: "OrderedDict[str, Tuple[datetime, State]]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._states)

    def get(self, ip: str, now: datetime) -> State:
        found = self._states.pop(ip, None)
        state = found[1] if found is not None else self._factory()
        self._states[ip] = (now, state)
        while len(self._states) > self._cap:
            self._states.popitem(last=False)        # the address seen longest ago
        return state

    def peek(self, ip: str) -> Optional[State]:
        found = self._states.get(ip)
        return found[1] if found is not None else None

    def prune(self, cutoff: datetime) -> int:
        """Drop the addresses not seen since *cutoff*."""
        dropped = 0
        while self._states:
            ip, (seen, _) = next(iter(self._states.items()))
            if seen >= cutoff:
                break
            del self._states[ip]
            dropped += 1
        return dropped


class BehaviourRule(ABC):
    rule_id: str = ""
    window: timedelta = timedelta(minutes=5)

    @abstractmethod
    def observe(self, entry: AccessLogEntry, request: NormalizedRequest, now: datetime) -> List[Detection]:
        """Take one request into account; return what it completed."""

    @abstractmethod
    def prune(self, now: datetime) -> None:
        """Forget what is older than the window."""

    @property
    @abstractmethod
    def tracked(self) -> int:
        """How many addresses the rule holds state for."""


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

@dataclass
class _LoginState:
    failures: Deque[datetime] = field(default_factory=deque)
    failure_size: int = 0
    failure_method: str = ""
    reported_at: Optional[datetime] = None
    success_reported: bool = False


class BruteForceRule(BehaviourRule):
    """Many failed logins from one address, and what happened after.

    A failure is a 401 or 403, or a 200 on POST with the size the login
    page has when it shows an error (the first such answer sets it). After
    the threshold, a different answer to the same address (a redirect, or
    a 200 of another size) may be the guess that worked.
    """

    rule_id = "LS201"
    success_rule_id = "LS202"
    window = timedelta(minutes=5)
    AFTERWARDS = timedelta(minutes=15)       # how long a success still counts as "after"
    LOGIN = re.compile(
        r"(?:^|/)(?:login|log-in|signin|sign-in|sign_in|logon|auth|authenticate|session|sessions"
        r"|wp-login\.php|xmlrpc\.php|token|j_security_check|user/login|admin/login|accounts/login)(?:/|\.|$)"
    )
    FAILED = frozenset({401, 403})

    def __init__(self, threshold: int = 10, cap: int = MAX_TRACKED) -> None:
        self._threshold = max(2, int(threshold))
        self._states: IpStateTable[Dict[str, _LoginState]] = IpStateTable(dict, cap)

    @property
    def tracked(self) -> int:
        return len(self._states)

    @classmethod
    def is_login(cls, path: str) -> bool:
        return bool(cls.LOGIN.search(path))

    def observe(self, entry: AccessLogEntry, request: NormalizedRequest, now: datetime) -> List[Detection]:
        path = request.path.rstrip("/") or "/"
        if not self.is_login(path):
            return []
        per_path = self._states.get(entry.client_ip, now)
        state = per_path.setdefault(path, _LoginState())
        while state.failures and now - state.failures[0] > self.window:
            state.failures.popleft()

        if self._is_failure(entry, state):
            state.failures.append(now)
            if len(state.failures) > self._threshold * 2:
                state.failures.popleft()            # enough to know; keep it small
            state.failure_method = state.failure_method or entry.method
            if len(state.failures) >= self._threshold and (
                state.reported_at is None or now - state.reported_at > self.window
            ):
                state.reported_at = now
                state.success_reported = False
                return [self._detection(entry, request, self.rule_id, Severity.HIGH, Reason.of(
                    "ls_reason_failed_logins", count=len(state.failures), path=path,
                    minutes=int(self.window.total_seconds() // 60),
                ))]
            return []

        if (state.reported_at is not None and not state.success_reported
                and now - state.reported_at <= self.AFTERWARDS and self._is_success(entry, state)):
            state.success_reported = True
            return [self._detection(entry, request, self.success_rule_id, Severity.CRITICAL, Reason.of(
                "ls_reason_login_success", status=entry.status, path=path,
            ))]
        return []

    def _is_failure(self, entry: AccessLogEntry, state: _LoginState) -> bool:
        if entry.status in self.FAILED:
            return True
        if entry.method != "POST" or entry.status != 200:
            return False
        if not state.failure_size:
            state.failure_size = entry.size     # the first answer to a POST is taken as the error page
            return True
        return self.same_size(entry.size, state.failure_size)

    def _is_success(self, entry: AccessLogEntry, state: _LoginState) -> bool:
        if state.failure_method and entry.method != state.failure_method:
            return False
        if 300 <= entry.status < 400:
            return True
        return 200 <= entry.status < 300 and not self.same_size(entry.size, state.failure_size)

    @staticmethod
    def same_size(size: int, reference: int) -> bool:
        """The error page echoes the user name, so its size varies a little."""
        return abs(size - reference) <= max(64, reference // 50)

    def prune(self, now: datetime) -> None:
        self._states.prune(now - self.AFTERWARDS)

    @staticmethod
    def _detection(entry: AccessLogEntry, request: NormalizedRequest, rule_id: str,
                   severity: Severity, reason: Reason) -> Detection:
        return Detection(rule_id, AttackCategory.BRUTE_FORCE, severity, entry,
                         evidence=f"{entry.method} {request.path}", reasons=(reason,), normalized=request.text)


# ---------------------------------------------------------------------------
# Scanning for paths
# ---------------------------------------------------------------------------

@dataclass
class _ScanState:
    seen: Deque[Tuple[datetime, str]] = field(default_factory=deque)
    paths: Set[str] = field(default_factory=set)
    level: int = 0          # 0 nothing, 1 reported MEDIUM, 2 reported HIGH


class ScanRule(BehaviourRule):
    """Many distinct paths that do not exist, from one address, in two minutes."""

    rule_id = "LS203"
    window = timedelta(minutes=2)

    def __init__(self, medium_after: int = 30, high_after: int = 100, cap: int = MAX_TRACKED) -> None:
        self._medium = medium_after
        self._high = high_after
        self._states: IpStateTable[_ScanState] = IpStateTable(_ScanState, cap)

    @property
    def tracked(self) -> int:
        return len(self._states)

    def observe(self, entry: AccessLogEntry, request: NormalizedRequest, now: datetime) -> List[Detection]:
        if entry.status != 404:
            return []
        state = self._states.get(entry.client_ip, now)
        while state.seen and now - state.seen[0][0] > self.window:
            _, old = state.seen.popleft()
            if all(path != old for _, path in state.seen):
                state.paths.discard(old)
        if not state.seen:
            state.level = 0
        if request.path not in state.paths and len(state.paths) <= self._high:
            state.paths.add(request.path)
            state.seen.append((now, request.path))
        count = len(state.paths)
        level = 2 if count > self._high else 1 if count > self._medium else 0
        if level <= state.level:
            return []
        state.level = level
        severity = Severity.HIGH if level == 2 else Severity.MEDIUM
        return [Detection(self.rule_id, AttackCategory.PATH_SCAN, severity, entry,
                          evidence=f"{count} paths", normalized=request.text,
                          reasons=(Reason.of("ls_reason_scan_paths", count=count, minutes=2),))]

    def prune(self, now: datetime) -> None:
        self._states.prune(now - self.window)


# ---------------------------------------------------------------------------
# Floods
# ---------------------------------------------------------------------------

@dataclass
class _FloodState:
    times: Deque[datetime] = field(default_factory=deque)
    reported_at: Optional[datetime] = None


class FloodRule(BehaviourRule):
    """More requests per minute from one address than the limit."""

    rule_id = "LS204"
    window = timedelta(minutes=1)

    def __init__(self, per_minute: int = 300, cap: int = MAX_TRACKED) -> None:
        self._limit = max(10, int(per_minute))
        self._states: IpStateTable[_FloodState] = IpStateTable(_FloodState, cap)

    @property
    def tracked(self) -> int:
        return len(self._states)

    def observe(self, entry: AccessLogEntry, request: NormalizedRequest, now: datetime) -> List[Detection]:
        state = self._states.get(entry.client_ip, now)
        state.times.append(now)
        while state.times and now - state.times[0] > self.window:
            state.times.popleft()
        if len(state.times) > self._limit + 1:
            state.times.popleft()
        if len(state.times) <= self._limit:
            return []
        if state.reported_at is not None and now - state.reported_at <= self.window:
            return []
        state.reported_at = now
        return [Detection(self.rule_id, AttackCategory.FLOOD, Severity.MEDIUM, entry,
                          evidence=f"> {self._limit}/min", normalized=request.text,
                          reasons=(Reason.of("ls_reason_flood", limit=self._limit),))]

    def prune(self, now: datetime) -> None:
        self._states.prune(now - self.window)


# ---------------------------------------------------------------------------
# Everything for one stream of entries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BehaviourConfig:
    brute_force_threshold: int = 10
    scan_medium_after: int = 30
    scan_high_after: int = 100
    flood_per_minute: int = 300
    flood_enabled: bool = True
    max_tracked: int = MAX_TRACKED


class SentinelEngine:
    """Runs the request rules and the behaviour rules on each entry.

    Addresses on the allowlist are skipped entirely. Entries without a
    time are placed at the clock's time; the windows follow the newest
    time seen, so a log that is read hours later still works.
    """

    PRUNE_EVERY = 1000

    def __init__(
        self,
        allowlist: Iterable[str] = (),
        config: BehaviourConfig = BehaviourConfig(),
        analyzer: Optional[RequestAnalyzer] = None,
        clock: Clock = utc_now,
    ) -> None:
        self._allowlist = NetworkList(allowlist)
        self._analyzer = analyzer or RequestAnalyzer()
        self._clock = clock
        cap = config.max_tracked
        rules: List[BehaviourRule] = [
            BruteForceRule(config.brute_force_threshold, cap),
            ScanRule(config.scan_medium_after, config.scan_high_after, cap),
        ]
        if config.flood_enabled:
            rules.append(FloodRule(config.flood_per_minute, cap))
        self._behaviour: Tuple[BehaviourRule, ...] = tuple(rules)
        self._newest: Optional[datetime] = None
        self._since_prune = 0
        self.skipped = 0

    @property
    def allowlist(self) -> NetworkList:
        return self._allowlist

    @property
    def behaviour_rules(self) -> Sequence[BehaviourRule]:
        return self._behaviour

    def tracked(self) -> int:
        return max((rule.tracked for rule in self._behaviour), default=0)

    def process(self, entry: AccessLogEntry) -> List[Detection]:
        if self._allowlist and self._allowlist.contains(entry.client_ip):
            self.skipped += 1
            return []
        now = entry.time or self._clock()
        if self._newest is None or now > self._newest:
            self._newest = now
        request = self._analyzer.normalize(entry)
        found = self._analyzer.analyze(entry, request)
        for rule in self._behaviour:
            found.extend(rule.observe(entry, request, now))
        self._since_prune += 1
        if self._since_prune >= self.PRUNE_EVERY:
            self.prune()
        return found

    def prune(self) -> None:
        self._since_prune = 0
        if self._newest is not None:
            for rule in self._behaviour:
                rule.prune(self._newest)
