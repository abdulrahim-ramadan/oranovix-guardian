"""
Security events in their own SQLite file.

Events follow the privacy rules of ``privacy.py``: addresses truncated
unless the user chose otherwise, hashed for counting, query secrets
hidden. Old events are removed after the retention period (30 days by
default) when the app starts.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from oranovix_guardian.core.app_paths import AppPaths, DataFile
from oranovix_guardian.scanner_engine.base import Severity

from .events import EventSink, EventState, SecurityEvent
from .privacy import IpAnonymizer
from .rules import AttackCategory, Reason

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EventFilter:
    severities: Tuple[Severity, ...] = ()
    rule_ids: Tuple[str, ...] = ()
    state: Optional[EventState] = None


@dataclass(frozen=True)
class Attacker:
    """One address (by its hash), shown truncated unless full addresses are kept."""

    ip_hash: str
    ip: str
    hits: int
    events: int
    worst: Severity
    last_seen: datetime


class SecurityEventStore(EventSink):
    """Events, acknowledgements, top attackers and counts."""

    DEFAULT_RETENTION_DAYS = 30
    _SEVERITY_RANK = "CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END"
    _COLUMNS = (
        "id, time, last_time, rule_id, category, severity, ip, ip_hash, request, status, "
        "reasons, source, evidence, state, hits"
    )
    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            last_time TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            ip TEXT NOT NULL,
            ip_hash TEXT NOT NULL,
            request TEXT NOT NULL,
            status INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            source TEXT NOT NULL,
            evidence TEXT NOT NULL,
            state TEXT NOT NULL,
            hits INTEGER NOT NULL,
            dedup TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_time ON events (last_time);
        CREATE INDEX IF NOT EXISTS events_open ON events (state, dedup);
        CREATE INDEX IF NOT EXISTS events_ip ON events (ip_hash);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """

    def __init__(self, db_path: Optional[str] = None, clock: Clock = utc_now, window_minutes: int = 10) -> None:
        self._path = Path(db_path) if db_path else self.default_path()
        self._clock = clock
        self._window = window_minutes
        self._lock = threading.RLock()
        with closing(self._connect()) as conn:
            conn.executescript(self._SCHEMA)

    @staticmethod
    def default_path() -> Path:
        return AppPaths.data_file(DataFile.SECURITY_EVENTS)

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def add(self, events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        """Store *events*. An open event of the same rule, address, window and
        severity is counted up instead of stored twice."""
        stored = []
        with self._lock, closing(self._connect()) as conn, conn:
            for event in events:
                key = event.dedup_key(self._window)
                last = event.last_time or event.time
                row = conn.execute(
                    "SELECT id, hits, last_time FROM events WHERE state = 'open' AND dedup = ?", (key,)
                ).fetchone()
                if row is not None:
                    hits = int(row[1]) + event.hits
                    newest = max(_text(last), row[2])
                    conn.execute("UPDATE events SET hits = ?, last_time = ? WHERE id = ?", (hits, newest, row[0]))
                    stored.append(replace(event, id=int(row[0]), hits=hits, last_time=_parse(newest)))
                    continue
                cursor = conn.execute(
                    "INSERT INTO events (time, last_time, rule_id, category, severity, ip, ip_hash, request, "
                    "status, reasons, source, evidence, state, hits, dedup) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        _text(event.time), _text(last), event.rule_id, event.category.value,
                        event.severity.value, event.ip, event.ip_hash, event.request, event.status,
                        json.dumps([[r.key, list(map(list, r.args))] for r in event.reasons]),
                        event.source, event.evidence, event.state.value, event.hits, key,
                    ),
                )
                stored.append(replace(event, id=int(cursor.lastrowid or 0), last_time=last))
        return stored

    def acknowledge(self, event_ids: Iterable[int]) -> int:
        ids = [int(event_id) for event_id in event_ids]
        if not ids:
            return 0
        with self._lock, closing(self._connect()) as conn, conn:
            marks = ",".join("?" * len(ids))
            return conn.execute(
                f"UPDATE events SET state = 'acknowledged' WHERE state = 'open' AND id IN ({marks})", ids
            ).rowcount

    def acknowledge_all(self, event_filter: EventFilter = EventFilter()) -> int:
        where, parameters = self._where(replace(event_filter, state=EventState.OPEN))
        with self._lock, closing(self._connect()) as conn, conn:
            return conn.execute(f"UPDATE events SET state = 'acknowledged' {where}", parameters).rowcount

    def purge(self, retention_days: int = DEFAULT_RETENTION_DAYS) -> int:
        """Remove events last seen before the retention period."""
        cutoff = self._clock() - timedelta(days=max(1, int(retention_days)))
        with self._lock, closing(self._connect()) as conn, conn:
            return conn.execute("DELETE FROM events WHERE last_time < ?", (_text(cutoff),)).rowcount

    def forget_full_addresses(self) -> int:
        """The user switched full addresses off: truncate the ones already stored."""
        changed = 0
        with self._lock, closing(self._connect()) as conn, conn:
            for event_id, ip in conn.execute("SELECT id, ip FROM events").fetchall():
                short = IpAnonymizer.truncate(ip) if ip != "?" else ip
                if short != ip:
                    conn.execute("UPDATE events SET ip = ? WHERE id = ?", (short, event_id))
                    changed += 1
        return changed

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def events(self, event_filter: EventFilter = EventFilter(), limit: int = 500, offset: int = 0) -> List[SecurityEvent]:
        where, parameters = self._where(event_filter)
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {self._COLUMNS} FROM events {where} ORDER BY last_time DESC, id DESC LIMIT ? OFFSET ?",
                (*parameters, limit, max(0, offset)),
            ).fetchall()
        return [self._event(row) for row in rows]

    def count(self, event_filter: EventFilter = EventFilter()) -> int:
        where, parameters = self._where(event_filter)
        with self._lock, closing(self._connect()) as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM events {where}", parameters).fetchone()[0])

    def open_count(self, severities: Sequence[Severity] = (Severity.CRITICAL, Severity.HIGH)) -> int:
        return self.count(EventFilter(severities=tuple(severities), state=EventState.OPEN))

    def top_attackers(self, limit: int = 10) -> List[Attacker]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT ip_hash, MAX(ip), SUM(hits), COUNT(*), MAX({self._SEVERITY_RANK}), MAX(last_time) "
                "FROM events GROUP BY ip_hash ORDER BY MAX(" + self._SEVERITY_RANK + ") DESC, SUM(hits) DESC "
                "LIMIT ?",
                (limit,),
            ).fetchall()
        ranks = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        return [
            Attacker(ip_hash, ip, int(hits), int(count), ranks[int(rank)], _parse(last) or self._clock())
            for ip_hash, ip, hits, count, rank, last in rows
        ]

    def counts_per_rule(self) -> Dict[str, int]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute("SELECT rule_id, SUM(hits) FROM events GROUP BY rule_id ORDER BY rule_id").fetchall()
        return {rule_id: int(hits) for rule_id, hits in rows}

    def counts_per_day(self, days: int = 30) -> Dict[str, int]:
        cutoff = self._clock() - timedelta(days=days)
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT substr(time, 1, 10), SUM(hits) FROM events WHERE time >= ? GROUP BY 1 ORDER BY 1",
                (_text(cutoff),),
            ).fetchall()
        return {day: int(hits) for day, hits in rows}

    def rule_ids(self) -> List[str]:
        with self._lock, closing(self._connect()) as conn:
            return [row[0] for row in conn.execute("SELECT DISTINCT rule_id FROM events ORDER BY rule_id")]

    # ------------------------------------------------------------------
    # Key of the address hash when there is no credential store
    # ------------------------------------------------------------------

    def key(self) -> bytes:
        with self._lock, closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'ip_hash_key'").fetchone()
            if row is not None:
                return bytes.fromhex(row[0])
            value = secrets.token_hex(32)
            conn.execute("INSERT INTO meta (key, value) VALUES ('ip_hash_key', ?)", (value,))
            return bytes.fromhex(value)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _where(event_filter: EventFilter) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if event_filter.severities:
            clauses.append(f"severity IN ({','.join('?' * len(event_filter.severities))})")
            parameters.extend(severity.value for severity in event_filter.severities)
        if event_filter.rule_ids:
            clauses.append(f"rule_id IN ({','.join('?' * len(event_filter.rule_ids))})")
            parameters.extend(event_filter.rule_ids)
        if event_filter.state is not None:
            clauses.append("state = ?")
            parameters.append(event_filter.state.value)
        return ("WHERE " + " AND ".join(clauses) if clauses else ""), parameters

    @staticmethod
    def _event(row: Tuple[Any, ...]) -> SecurityEvent:
        (event_id, time, last_time, rule_id, category, severity, ip, ip_hash, request, status,
         reasons, source, evidence, state, hits) = row
        try:
            parsed_reasons = tuple(
                Reason(str(key), tuple((str(name), str(value)) for name, value in args))
                for key, args in json.loads(reasons)
            )
        except (ValueError, TypeError):
            parsed_reasons = ()
        return SecurityEvent(
            time=_parse(time) or datetime.min.replace(tzinfo=timezone.utc),
            rule_id=rule_id,
            category=_category(category),
            severity=Severity(severity) if severity in Severity.__members__ else Severity.LOW,
            ip=ip, ip_hash=ip_hash, request=request, status=int(status), reasons=parsed_reasons,
            source=source, evidence=evidence,
            state=EventState.ACKNOWLEDGED if state == "acknowledged" else EventState.OPEN,
            id=int(event_id), hits=int(hits), last_time=_parse(last_time),
        )

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self._path, timeout=10)


def _category(value: str) -> AttackCategory:
    try:
        return AttackCategory(value)
    except ValueError:
        return AttackCategory.SCANNER


_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _text(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(_FORMAT)


def _parse(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.strptime(text, _FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
