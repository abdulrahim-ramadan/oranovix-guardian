"""
Local store of feed items (``feed.db``).

The Threat Feed page always reads from here, so it works offline and can
say when the last successful update was. Items are kept once per id; an
item that no feed has listed for 90 days is removed.

Old catalog entries are stored as background items: they are matched
like every other item, but are not counted as new or unread until one
of them affects a project.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Collection, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from oranovix_guardian.core.app_paths import AppPaths, DataFile
from oranovix_guardian.scanner_engine.base import Severity

from .models import (
    AcceptedRisk,
    CacheValidators,
    FeedItem,
    PackageRef,
    ProjectMatch,
    Relevance,
    RiskKey,
    SourceHealth,
    StoredItem,
    project_key,
)

Clock = Callable[[], datetime]
Verdict = Tuple[Relevance, Sequence[ProjectMatch]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Timestamp:
    """Datetimes as fixed-width UTC text, so SQLite can compare them."""

    _FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

    @classmethod
    def text(cls, moment: Optional[datetime]) -> Optional[str]:
        if moment is None:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime(cls._FORMAT)

    @classmethod
    def parse(cls, text: Optional[str]) -> Optional[datetime]:
        if not text:
            return None
        try:
            return datetime.strptime(text, cls._FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            return None


class FeedDatabase:
    """The SQLite file shared by the feed store, the projects and the uptime history."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._path = Path(db_path) if db_path else self.default_path()
        self._lock = threading.RLock()

    @staticmethod
    def default_path() -> Path:
        return AppPaths.data_file(DataFile.FEED)

    @property
    def path(self) -> Path:
        return self._path

    def read(self, sql: str, parameters: Sequence[Any] = ()) -> List[Tuple[Any, ...]]:
        with self._lock, closing(self._connect()) as conn:
            return conn.execute(sql, parameters).fetchall()

    def write(self, sql: str, parameters: Sequence[Any] = ()) -> int:
        with self._lock, closing(self._connect()) as conn, conn:
            return conn.execute(sql, parameters).rowcount

    def write_many(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.executemany(sql, rows)

    def script(self, sql: str) -> None:
        with self._lock, closing(self._connect()) as conn:
            conn.executescript(sql)

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self._path, timeout=10)


class ThreatStore:
    """Feed items with their read flag, relevance and matches."""

    RETENTION_DAYS = 90

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            published TEXT,
            summary TEXT NOT NULL DEFAULT '',
            cve_ids TEXT NOT NULL DEFAULT '[]',
            packages TEXT NOT NULL DEFAULT '[]',
            known_exploited INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            relevance TEXT NOT NULL DEFAULT 'general',
            matches TEXT NOT NULL DEFAULT '[]',
            background INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS items_relevance ON items (relevance, is_read);
        CREATE TABLE IF NOT EXISTS sources (
            name TEXT PRIMARY KEY,
            last_success TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            last_error_at TEXT,
            etag TEXT NOT NULL DEFAULT '',
            last_modified TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alarmed_items (
            item_id TEXT NOT NULL,
            project_path TEXT NOT NULL,
            alarmed_at TEXT NOT NULL,
            PRIMARY KEY (item_id, project_path)
        );
        CREATE TABLE IF NOT EXISTS accepted_risks (
            item_id TEXT NOT NULL,
            project_path TEXT NOT NULL,
            reason TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            PRIMARY KEY (item_id, project_path)
        );
        CREATE TABLE IF NOT EXISTS feed_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """
    _COLUMNS = (
        "id, source, title, url, published, summary, cve_ids, packages, "
        "known_exploited, severity, first_seen, is_read, relevance, matches, background"
    )
    _NEWEST = "COALESCE(published, first_seen) DESC, id"
    _ORDER = (
        "CASE relevance WHEN 'affects_you' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END, " + _NEWEST
    )
    # What counts as new or unread: not the background, unless it affects a project.
    _COUNTED = "(background = 0 OR relevance = 'affects_you')"

    def __init__(self, database: Optional[FeedDatabase] = None, clock: Clock = utc_now) -> None:
        self._db = database or FeedDatabase()
        self._clock = clock
        self._db.script(self._SCHEMA)
        self._upgrade()

    def _upgrade(self) -> None:
        """Add what a feed.db of an earlier version does not have yet."""
        columns = {row[1] for row in self._db.read("PRAGMA table_info(items)")}
        if "background" not in columns:
            self._db.write("ALTER TABLE items ADD COLUMN background INTEGER NOT NULL DEFAULT 0")

    @property
    def database(self) -> FeedDatabase:
        return self._db

    # ------------------------------------------------------------------
    # Items
    # ------------------------------------------------------------------

    def add(self, items: Iterable[FeedItem], background: Collection[str] = ()) -> List[FeedItem]:
        """Store *items* and return the ones that were not known before.

        A known item keeps its read flag and first-seen time; its text is
        refreshed, because feeds correct their headlines. Ids in *background*
        are stored as background items when they are new.
        """
        now = Timestamp.text(self._clock())
        unique = {item.id: item for item in items}
        if not unique:
            return []
        known = self._known_ids(list(unique))
        self._db.write_many(
            "INSERT INTO items (id, source, title, url, published, summary, cve_ids, packages, "
            "known_exploited, severity, first_seen, last_seen, background) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET title = excluded.title, url = excluded.url, "
            "published = excluded.published, summary = excluded.summary, "
            "cve_ids = excluded.cve_ids, packages = excluded.packages, "
            "known_exploited = excluded.known_exploited, severity = excluded.severity, "
            "last_seen = excluded.last_seen",
            [
                (
                    item.id, item.source, item.title, item.url, Timestamp.text(item.published),
                    item.summary, json.dumps(list(item.cve_ids)),
                    json.dumps([[p.ecosystem, p.name] for p in item.packages]),
                    int(item.is_known_exploited),
                    item.severity_hint.value if item.severity_hint else "",
                    now, now, int(item.id in background),
                )
                for item in unique.values()
            ],
        )
        return [item for item in unique.values() if item.id not in known]

    def items(
        self,
        relevances: Optional[Iterable[Relevance]] = None,
        unread_only: bool = False,
        limit: int = 500,
        newest_first: bool = False,
        offset: int = 0,
        keep_affecting: bool = False,
    ) -> List[StoredItem]:
        """Stored items, the ones that affect the user first, then newest first.

        With *newest_first* the date alone decides the order. *offset* skips
        that many items, for the next page of a long list. With
        *keep_affecting*, *unread_only* never hides an item that affects a project.
        """
        where, parameters = self._filter(relevances, unread_only, keep_affecting)
        order = self._NEWEST if newest_first else self._ORDER
        rows = self._db.read(
            f"SELECT {self._COLUMNS} FROM items {where} ORDER BY {order} LIMIT ? OFFSET ?",
            (*parameters, limit, max(0, offset)),
        )
        return [self._stored(row) for row in rows]

    def get(self, item_id: str) -> Optional[StoredItem]:
        rows = self._db.read(f"SELECT {self._COLUMNS} FROM items WHERE id = ?", (item_id,))
        return self._stored(rows[0]) if rows else None

    def new_since(self, since: Optional[datetime]) -> List[StoredItem]:
        """Items first seen after *since*; every item when *since* is ``None``.

        Background items are left out until they affect a project.
        """
        rows = self._db.read(
            f"SELECT {self._COLUMNS} FROM items WHERE first_seen > ? AND {self._COUNTED} "
            f"ORDER BY {self._ORDER}",
            (Timestamp.text(since) or "",),
        )
        return [self._stored(row) for row in rows]

    def count(
        self, relevances: Optional[Iterable[Relevance]] = None,
        unread_only: bool = False, keep_affecting: bool = False,
    ) -> int:
        where, parameters = self._filter(relevances, unread_only, keep_affecting)
        return int(self._db.read(f"SELECT COUNT(*) FROM items {where}", parameters)[0][0])

    def purge(self) -> int:
        """Remove items no feed has listed for ``RETENTION_DAYS``; return how many."""
        limit = Timestamp.text(self._clock() - timedelta(days=self.RETENTION_DAYS))
        removed = self._db.write("DELETE FROM items WHERE last_seen < ?", (limit,))
        self._db.write("DELETE FROM alarmed_items WHERE item_id NOT IN (SELECT id FROM items)")
        self._db.write("DELETE FROM accepted_risks WHERE item_id NOT IN (SELECT id FROM items)")
        return removed

    # ------------------------------------------------------------------
    # Read flag
    # ------------------------------------------------------------------

    def mark_read(self, item_ids: Sequence[str], read: bool = True) -> None:
        self._db.write_many(
            "UPDATE items SET is_read = ? WHERE id = ?", [(int(read), i) for i in item_ids]
        )

    def mark_all_read(self, relevances: Optional[Iterable[Relevance]] = None) -> None:
        where, parameters = self._filter(relevances, unread_only=False)
        self._db.write(f"UPDATE items SET is_read = 1 {where}", parameters)

    def unread_counts(self) -> Dict[Relevance, int]:
        """Unread items per relevance, without the background."""
        counts = {relevance: 0 for relevance in Relevance}
        for value, count in self._db.read(
            f"SELECT relevance, COUNT(*) FROM items WHERE is_read = 0 AND {self._COUNTED} "
            "GROUP BY relevance"
        ):
            try:
                counts[Relevance(value)] = int(count)
            except ValueError:
                continue
        return counts

    def unread_for_you(self) -> int:
        counts = self.unread_counts()
        return counts[Relevance.AFFECTS_YOU] + counts[Relevance.POSSIBLE]

    # ------------------------------------------------------------------
    # Relevance (written by the matcher)
    # ------------------------------------------------------------------

    def set_relevance(self, verdicts: Mapping[str, Verdict]) -> None:
        self._db.write_many(
            "UPDATE items SET relevance = ?, matches = ? WHERE id = ?",
            [
                (relevance.value, json.dumps([self._match_json(m) for m in matches]), item_id)
                for item_id, (relevance, matches) in verdicts.items()
            ],
        )

    # ------------------------------------------------------------------
    # Alarms already raised
    # ------------------------------------------------------------------

    def was_alarmed(self, item_id: str, project_path: str) -> bool:
        return bool(self._db.read(
            "SELECT 1 FROM alarmed_items WHERE item_id = ? AND project_path = ?",
            (item_id, project_path),
        ))

    def mark_alarmed(self, item_id: str, project_path: str) -> None:
        self._db.write(
            "INSERT OR IGNORE INTO alarmed_items (item_id, project_path, alarmed_at) VALUES (?, ?, ?)",
            (item_id, project_path, Timestamp.text(self._clock())),
        )

    # ------------------------------------------------------------------
    # Accepted risks
    # ------------------------------------------------------------------

    def accept_risk(self, item_id: str, project_path: str, reason: str) -> AcceptedRisk:
        """Note that the user lives with *item_id* in the project at *project_path*."""
        now = self._clock()
        key = project_key(project_path)
        self._db.write(
            "INSERT INTO accepted_risks (item_id, project_path, reason, accepted_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(item_id, project_path) DO UPDATE SET reason = excluded.reason, "
            "accepted_at = excluded.accepted_at",
            (item_id, key, reason, Timestamp.text(now)),
        )
        return AcceptedRisk(item_id, key, reason, now)

    def withdraw_risk(self, item_id: str, project_path: Optional[str] = None) -> None:
        """Take the note back, for one project or for every project of the item."""
        if project_path is None:
            self._db.write("DELETE FROM accepted_risks WHERE item_id = ?", (item_id,))
        else:
            self._db.write(
                "DELETE FROM accepted_risks WHERE item_id = ? AND project_path = ?",
                (item_id, project_key(project_path)),
            )

    def forget_risks(self, project_path: str) -> None:
        """The project was removed: its notes go with it."""
        self._db.write("DELETE FROM accepted_risks WHERE project_path = ?", (project_key(project_path),))

    def accepted_risks(self) -> Dict[RiskKey, AcceptedRisk]:
        rows = self._db.read("SELECT item_id, project_path, reason, accepted_at FROM accepted_risks")
        return {
            (item_id, path): AcceptedRisk(item_id, path, reason, Timestamp.parse(accepted_at))
            for item_id, path, reason, accepted_at in rows
        }

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def save_source(self, health: SourceHealth, validators: CacheValidators) -> None:
        self._db.write(
            "INSERT INTO sources (name, last_success, last_error, last_error_at, etag, last_modified) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET last_success = excluded.last_success, "
            "last_error = excluded.last_error, last_error_at = excluded.last_error_at, "
            "etag = excluded.etag, last_modified = excluded.last_modified",
            (
                health.name, Timestamp.text(health.last_success), health.last_error,
                Timestamp.text(health.last_error_at), validators.etag, validators.last_modified,
            ),
        )

    def source_states(self) -> Dict[str, Tuple[SourceHealth, CacheValidators]]:
        rows = self._db.read(
            "SELECT name, last_success, last_error, last_error_at, etag, last_modified FROM sources"
        )
        return {
            name: (
                SourceHealth(name, Timestamp.parse(success), error, Timestamp.parse(error_at)),
                CacheValidators(etag, last_modified),
            )
            for name, success, error, error_at, etag, last_modified in rows
        }

    def last_success(self) -> Optional[datetime]:
        """When any source last answered: "last updated" on the page."""
        row = self._db.read("SELECT MAX(last_success) FROM sources")[0]
        return Timestamp.parse(row[0])

    # ------------------------------------------------------------------
    # Last visit of the page
    # ------------------------------------------------------------------

    def last_visit(self) -> Optional[datetime]:
        rows = self._db.read("SELECT value FROM feed_meta WHERE key = 'last_visit'")
        return Timestamp.parse(rows[0][0]) if rows else None

    def set_last_visit(self, moment: Optional[datetime] = None) -> None:
        self._db.write(
            "INSERT INTO feed_meta (key, value) VALUES ('last_visit', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (Timestamp.text(moment or self._clock()),),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _known_ids(self, item_ids: Sequence[str]) -> set:
        known = set()
        for start in range(0, len(item_ids), 500):
            chunk = item_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            known.update(row[0] for row in self._db.read(
                f"SELECT id FROM items WHERE id IN ({marks})", chunk
            ))
        return known

    @staticmethod
    def _filter(
        relevances: Optional[Iterable[Relevance]], unread_only: bool, keep_affecting: bool = False,
    ) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if relevances is not None:
            values = [relevance.value for relevance in relevances]
            clauses.append(f"relevance IN ({','.join('?' * len(values))})" if values else "0")
            parameters.extend(values)
        if unread_only:
            clauses.append("(is_read = 0 OR relevance = 'affects_you')" if keep_affecting else "is_read = 0")
        return ("WHERE " + " AND ".join(clauses) if clauses else ""), parameters

    @staticmethod
    def _match_json(match: ProjectMatch) -> Dict[str, Any]:
        return {
            "project": match.project, "project_path": match.project_path,
            "package": match.package, "ecosystem": match.ecosystem, "version": match.version,
            "advisory_id": match.advisory_id,
            "severity": match.severity.value if match.severity else "",
            "fixed_version": match.fixed_version, "file_path": match.file_path, "line": match.line,
        }

    @staticmethod
    def _match(data: Mapping[str, Any]) -> ProjectMatch:
        severity = data.get("severity") or ""
        return ProjectMatch(
            project=str(data.get("project", "")), project_path=str(data.get("project_path", "")),
            package=str(data.get("package", "")), ecosystem=str(data.get("ecosystem", "")),
            version=str(data.get("version", "")), advisory_id=str(data.get("advisory_id", "")),
            severity=Severity(severity) if severity in Severity.__members__ else None,
            fixed_version=str(data.get("fixed_version", "")),
            file_path=str(data.get("file_path", "")), line=int(data.get("line", 0) or 0),
        )

    @classmethod
    def _stored(cls, row: Tuple[Any, ...]) -> StoredItem:
        (item_id, source, title, url, published, summary, cve_ids, packages,
         known_exploited, severity, first_seen, is_read, relevance, matches, background) = row
        item = FeedItem(
            id=item_id, source=source, title=title, url=url,
            published=Timestamp.parse(published), summary=summary,
            cve_ids=tuple(json.loads(cve_ids)),
            packages=tuple(PackageRef(ecosystem, name) for ecosystem, name in json.loads(packages)),
            is_known_exploited=bool(known_exploited),
            severity_hint=Severity(severity) if severity in Severity.__members__ else None,
        )
        try:
            level = Relevance(relevance)
        except ValueError:
            level = Relevance.GENERAL
        return StoredItem(
            item=item,
            first_seen=Timestamp.parse(first_seen) or datetime.min.replace(tzinfo=timezone.utc),
            read=bool(is_read),
            relevance=level,
            matches=tuple(cls._match(m) for m in json.loads(matches)),
            background=bool(background),
        )
