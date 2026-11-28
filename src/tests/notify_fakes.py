"""Stand-ins for the notification tests: report states, a recording SMTP, a Berlin clock.

Every token, password and key is built at runtime, never written out.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone, tzinfo
from typing import Any, Dict, List, Optional, Tuple

from oranovix_guardian.live_defense.base import ChangeType, IntegrityEvent
from oranovix_guardian.log_sentinel.events import EventState, SecurityEvent
from oranovix_guardian.log_sentinel.rules import AttackCategory, Reason
from oranovix_guardian.notify.report import ReportState, ScanSummary, SiteChange
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory
from oranovix_guardian.threat_intel.models import FeedItem, ProjectMatch, Relevance, StoredItem
from oranovix_guardian.threat_intel.projects import Project

UTC = timezone.utc


def telegram_token() -> str:
    return "7" + "123456789" + ":" + "AA" + "h" * 20 + "x" * 13           # digits:35 characters


def smtp_password() -> str:
    return "app-" + "pass" + "-" + "word" * 3


def aws_like_secret() -> str:
    return "AKIA" + "Q" * 16


# ---------------------------------------------------------------------------
# Europe/Berlin without tzdata: CET/CEST, EU rule (last Sunday 01:00 UTC)
# ---------------------------------------------------------------------------

def _last_sunday(year: int, month: int) -> date:
    day = date(year, month + 1, 1) - timedelta(days=1)
    return day - timedelta(days=(day.weekday() + 1) % 7)


class BerlinTime(tzinfo):
    """Summer time from the last Sunday of March to the last Sunday of October, 01:00 UTC."""

    @staticmethod
    def _window(year: int) -> Tuple[datetime, datetime]:
        start = datetime.combine(_last_sunday(year, 3), datetime.min.time()) + timedelta(hours=1)
        end = datetime.combine(_last_sunday(year, 10), datetime.min.time()) + timedelta(hours=1)
        return start, end           # naive UTC

    def dst(self, dt: Optional[datetime]) -> timedelta:
        if dt is None:
            return timedelta(0)
        wall = dt.replace(tzinfo=None)
        start, end = self._window(wall.year)
        summer = start <= wall - timedelta(hours=2) < end
        winter = not (start <= wall - timedelta(hours=1) < end)
        if summer and winter:                       # the repeated hour in October
            return timedelta(hours=1) if not dt.fold else timedelta(0)
        return timedelta(hours=1) if summer else timedelta(0)

    def utcoffset(self, dt: Optional[datetime]) -> timedelta:
        return timedelta(hours=1) + self.dst(dt)

    def tzname(self, dt: Optional[datetime]) -> str:
        return "CEST" if self.dst(dt) else "CET"

    def fromutc(self, dt: datetime) -> datetime:
        utc = dt.replace(tzinfo=None)
        start, end = self._window(utc.year)
        if start <= utc < end:
            return (utc + timedelta(hours=2)).replace(tzinfo=self)
        fold = 1 if end <= utc < end + timedelta(hours=1) else 0
        return (utc + timedelta(hours=1)).replace(tzinfo=self, fold=fold)


BERLIN = BerlinTime()


class Clock:
    """A clock moved by the test. Always returns local (Berlin) time."""

    def __init__(self, utc: datetime) -> None:
        self.utc = utc

    def __call__(self) -> datetime:
        return self.utc.astimezone(BERLIN)

    def advance(self, **delta: float) -> None:
        self.utc = self.utc + timedelta(**delta)

    def set_local(self, year: int, month: int, day: int, hour: int, minute: int = 0) -> None:
        self.utc = datetime(year, month, day, hour, minute, tzinfo=BERLIN).astimezone(UTC)


# ---------------------------------------------------------------------------
# A report state full of things that must never leave the machine
# ---------------------------------------------------------------------------

SNIPPET = "cursor.execute('SELECT * FROM users WHERE id=' + request.GET['id'])"
FULL_IPV4 = "198.51.100.77"
FULL_IPV6 = "2001:db8:85a3:42:1234:5678:9abc:def0"
USER_AGENT = "Mozilla/5.0 (EvilBot; secret-agent/9.9)"
REQUEST_LINE = "GET /login?password=hunter2-" + "x" * 6 + " HTTP/1.1"
ABSOLUTE = "C:\\Users\\alice\\Documents\\private\\shop"
HOSTILE_TITLE = "<script>alert(1)</script> & </b>"


def stored(title: str, relevance: Relevance, projects: Tuple[str, ...] = (), cves: Tuple[str, ...] = (),
           first_seen: Optional[datetime] = None, url: str = "https://example.org/advisory/1",
           summary: str = "") -> StoredItem:
    item = FeedItem(
        id=FeedItem.make_id("test", title), source="test", title=title, url=url,
        published=first_seen, summary=summary, cve_ids=cves,
    )
    matches = tuple(
        ProjectMatch(project=name, project_path=f"{ABSOLUTE}\\{name}", package="django", version="3.2",
                     advisory_id="GHSA-xxxx")
        for name in projects
    )
    return StoredItem(item=item, first_seen=first_seen or datetime(2026, 11, 21, 12, tzinfo=UTC),
                      relevance=relevance, matches=matches)


def sentinel_event(rule: str, severity: Severity, ip: str = FULL_IPV4, hits: int = 1,
                   at: Optional[datetime] = None) -> SecurityEvent:
    return SecurityEvent(
        time=at or datetime(2026, 11, 21, 23, tzinfo=UTC), rule_id=rule, category=AttackCategory.SQL_INJECTION,
        severity=severity, ip=ip, ip_hash="h" + ip, request=REQUEST_LINE, status=200,
        reasons=(Reason.of("ls_reason_pattern", pattern=USER_AGENT),), source=f"{ABSOLUTE}\\logs\\access.log",
        evidence=SNIPPET + " " + USER_AGENT, state=EventState.OPEN, hits=hits,
    )


def integrity_event(path: str, severity: Severity, change: ChangeType = ChangeType.MODIFIED) -> IntegrityEvent:
    secret = Issue(
        rule_id="SEC-AWS1", title="AWS access key", description=f"Found key {aws_like_secret()}",
        severity=Severity.CRITICAL, file_path=f"{ABSOLUTE}\\{path}", line_number=3, code_snippet=SNIPPET,
        category=IssueCategory.SECRET,
    )
    return IntegrityEvent(change=change, severity=severity, root=ABSOLUTE, relative_path=path,
                          reasons=(f"web shell signature: {SNIPPET}",), findings=[secret])


def full_state() -> ReportState:
    projects = [Project("shop", ABSOLUTE), Project("blog", ABSOLUTE + "-blog", "https://blog.example.com/admin?k=v")]
    items = [
        stored("Django SQL injection", Relevance.AFFECTS_YOU, ("shop",), ("CVE-2026-1111",),
               summary=SNIPPET + aws_like_secret()),
        stored(HOSTILE_TITLE, Relevance.AFFECTS_YOU, ("blog",), ("CVE-2026-2222",)),
        stored("Some general news", Relevance.GENERAL),
    ]
    return ReportState(
        feed_items=items, projects=projects, feed_checked=True,
        sites=[SiteChange("blog", "blog.example.com", down_since=datetime(2026, 11, 22, 3, tzinfo=UTC))],
        sentinel_events=[
            sentinel_event("LS101", Severity.HIGH, FULL_IPV4, hits=7),
            sentinel_event("LS101", Severity.HIGH, "198.51.100.12", hits=2),
            sentinel_event("LS109", Severity.MEDIUM, FULL_IPV6, hits=1),
            sentinel_event("LS102", Severity.CRITICAL, "203.0.113.200", hits=1),
        ],
        integrity_events=[
            integrity_event("app/views.py", Severity.CRITICAL),
            integrity_event("static/logo.png", Severity.LOW),
            integrity_event("config/.env", Severity.HIGH, ChangeType.NEW),
        ],
        last_scan=ScanSummary(datetime(2026, 11, 21, 18, tzinfo=UTC), "shop",
                              {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5}),
    )


FORBIDDEN = (
    SNIPPET, "cursor.execute", FULL_IPV4, "198.51.100.12", FULL_IPV6, "203.0.113.200", USER_AGENT, "EvilBot",
    REQUEST_LINE, "hunter2", ABSOLUTE, "alice", "Documents", "access.log", aws_like_secret(), "Found key",
    "web shell signature", "/admin?k=v", "GHSA-xxxx",
)


# ---------------------------------------------------------------------------
# SMTP recorder
# ---------------------------------------------------------------------------

@dataclass
class SmtpLog:
    connections: List[Dict[str, Any]] = field(default_factory=list)
    sent: List[Any] = field(default_factory=list)
    logins: List[Tuple[str, str]] = field(default_factory=list)


class FakeSmtpBase:
    log: SmtpLog = SmtpLog()
    implicit_tls = False
    extensions: Tuple[str, ...] = ("starttls", "auth")
    fail_starttls = False

    def __init__(self, host: str = "", port: int = 0, *args: Any, **kwargs: Any) -> None:
        self.tls = self.implicit_tls
        self.record = {"class": type(self).__name__, "host": host, "port": port,
                       "context": kwargs.get("context"), "tls": self.tls, "starttls_context": None}
        self.log.connections.append(self.record)

    def __enter__(self) -> "FakeSmtpBase":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.quit()

    def ehlo(self, name: str = "") -> Tuple[int, bytes]:
        return 250, b"ok"

    def has_extn(self, name: str) -> bool:
        return name.lower() in self.extensions

    def starttls(self, context: Any = None, **kwargs: Any) -> Tuple[int, bytes]:
        if self.fail_starttls:
            import smtplib
            raise smtplib.SMTPException("STARTTLS failed: handshake error")
        self.tls = True
        self.record["tls"] = True
        self.record["starttls_context"] = context
        return 220, b"ready"

    def login(self, user: str, password: str) -> Tuple[int, bytes]:
        self.log.logins.append((user, password, self.tls))   # type: ignore[arg-type]
        return 235, b"ok"

    def send_message(self, message: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if not self.tls:
            raise AssertionError("message sent without TLS")
        self.log.sent.append(message)
        return {}

    def quit(self) -> None:
        pass

    def close(self) -> None:
        pass


def smtp_classes(**overrides: Any) -> Tuple[type, type, SmtpLog]:
    log = SmtpLog()
    plain = type("FakeSMTP", (FakeSmtpBase,), {"log": log, **overrides})
    ssl = type("FakeSMTP_SSL", (FakeSmtpBase,), {"log": log, "implicit_tls": True, **overrides})
    return plain, ssl, log
