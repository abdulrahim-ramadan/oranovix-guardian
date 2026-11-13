"""
Local copy of the OSV vulnerability database (osv.dev).

``OSVDatabase.update`` is the only code that touches the network: it
downloads the PyPI and npm exports and rebuilds a local SQLite file.
Scans only read that file, so they work offline.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import urllib.request
import zipfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from ..base import Severity
from .severity import OSVSeverity
from .versions import Ecosystem, scheme_for

ProgressListener = Callable[[str], None]
Clock = Callable[[], datetime]


class OSVUpdateError(RuntimeError):
    """The database could not be downloaded or rebuilt. The old one is kept."""


@dataclass(frozen=True)
class RangeEvent:
    kind: str       # introduced | fixed | last_affected | limit
    version: str


@dataclass(frozen=True)
class AffectedRange:
    type: str       # ECOSYSTEM | SEMVER
    events: Tuple[RangeEvent, ...]


@dataclass(frozen=True)
class Vulnerability:
    """One advisory, limited to the ranges that affect one package."""

    id: str
    aliases: Tuple[str, ...]
    summary: str
    severity: Severity
    ranges: Tuple[AffectedRange, ...]

    @property
    def all_ids(self) -> Tuple[str, ...]:
        return (self.id, *self.aliases)

    @property
    def cve(self) -> str:
        return next((i for i in self.all_ids if i.upper().startswith("CVE-")), "")


class OSVDatabase:
    """SQLite store of OSV advisories for PyPI and npm."""

    MAX_AGE_DAYS = 14
    SOURCES: Dict[Ecosystem, str] = {
        Ecosystem.PYPI: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
        Ecosystem.NPM: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    }
    # Range types whose versions an ecosystem scheme can compare. GIT ranges
    # hold commit hashes and are skipped.
    _RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
    _EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")

    _SCHEMA = """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE vulns (
            id TEXT PRIMARY KEY,
            aliases TEXT NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE TABLE affected (
            vuln_id TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            severity TEXT NOT NULL,
            ranges TEXT NOT NULL
        );
        CREATE INDEX affected_package ON affected (ecosystem, package);
    """

    def __init__(self, db_path: Optional[str] = None, clock: Clock = datetime.now) -> None:
        self._path = Path(db_path) if db_path else self.default_path()
        self._clock = clock

    @staticmethod
    def default_path() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).parent / "osv.db"
        return Path(__file__).resolve().parents[2] / "osv.db"

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self.updated_at() is not None

    def updated_at(self) -> Optional[datetime]:
        value = self._meta("updated_at")
        try:
            return datetime.fromisoformat(value) if value else None
        except ValueError:
            return None

    def advisory_count(self) -> int:
        try:
            return int(self._meta("advisories") or 0)
        except ValueError:
            return 0

    def age_days(self) -> Optional[int]:
        updated = self.updated_at()
        return None if updated is None else max((self._clock() - updated).days, 0)

    def is_stale(self) -> bool:
        updated = self.updated_at()
        return updated is not None and self._clock() - updated > timedelta(days=self.MAX_AGE_DAYS)

    def status_warning(self) -> str:
        """Text for the scan log, or ``""`` when the database is present and fresh."""
        if not self.exists():
            return (
                "Dependency scan skipped: the vulnerability database is missing. "
                "Open Settings and choose \"Update vulnerability database\"."
            )
        if self.is_stale():
            return (
                f"The vulnerability database is {self.age_days()} days old "
                f"(older than {self.MAX_AGE_DAYS} days). Newer vulnerabilities may be "
                "missing. Update it in Settings."
            )
        return ""

    # ------------------------------------------------------------------
    # Lookup (offline)
    # ------------------------------------------------------------------

    def vulnerabilities_for(self, ecosystem: Ecosystem, package: str) -> List[Vulnerability]:
        """Return every advisory that names *package*; the caller checks the version."""
        if not self._path.is_file():
            return []
        name = scheme_for(ecosystem).normalize_name(package)
        try:
            with closing(sqlite3.connect(self._path)) as conn:
                rows = conn.execute(
                    "SELECT v.id, v.aliases, v.summary, a.severity, a.ranges "
                    "FROM affected a JOIN vulns v ON v.id = a.vuln_id "
                    "WHERE a.ecosystem = ? AND a.package = ? ORDER BY v.id",
                    (ecosystem.value, name),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._vulnerability(*row) for row in rows]

    @staticmethod
    def _vulnerability(
        vuln_id: str, aliases: str, summary: str, severity: str, ranges: str
    ) -> Vulnerability:
        return Vulnerability(
            id=vuln_id,
            aliases=tuple(json.loads(aliases)),
            summary=summary,
            severity=Severity(severity),
            ranges=tuple(
                AffectedRange(
                    type=item["type"],
                    events=tuple(RangeEvent(kind, version) for kind, version in item["events"]),
                )
                for item in json.loads(ranges)
            ),
        )

    # ------------------------------------------------------------------
    # Update (the only network access)
    # ------------------------------------------------------------------

    def update(self, on_progress: Optional[ProgressListener] = None) -> int:
        """Download the OSV exports and rebuild the database.

        Returns the number of advisories stored. Raises ``OSVUpdateError``
        on any failure; the existing database is then left as it was.
        """
        report = on_progress or (lambda message: None)
        with tempfile.TemporaryDirectory(prefix="osv_") as folder:
            archives: Dict[Ecosystem, Path] = {}
            for ecosystem, url in self.SOURCES.items():
                report(f"Downloading {ecosystem.value} advisories...")
                target = Path(folder) / f"{ecosystem.value}.zip"
                try:
                    self._download(url, target)
                except Exception as exc:
                    raise OSVUpdateError(
                        f"Download of the {ecosystem.value} advisories failed "
                        f"({type(exc).__name__})."
                    ) from exc
                archives[ecosystem] = target
            report("Importing advisories...")
            return self.import_archives(archives)

    @staticmethod
    def _download(url: str, target: Path) -> None:
        with urllib.request.urlopen(url, timeout=60) as response, open(target, "wb") as out:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)

    def import_archives(self, archives: Mapping[Ecosystem, Path]) -> int:
        """Rebuild the database from OSV ``all.zip`` files already on disk."""
        try:
            return self._rebuild(
                (ecosystem, self._read_archive(path)) for ecosystem, path in archives.items()
            )
        except (OSError, zipfile.BadZipFile, sqlite3.Error) as exc:
            raise OSVUpdateError(
                f"The vulnerability database could not be built ({type(exc).__name__})."
            ) from exc

    def import_records(self, records: Mapping[Ecosystem, Iterable[Mapping[str, Any]]]) -> int:
        """Rebuild the database from OSV records already in memory."""
        return self._rebuild((ecosystem, iter(items)) for ecosystem, items in records.items())

    @staticmethod
    def _read_archive(path: Path) -> Iterator[Mapping[str, Any]]:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(name))
                except ValueError:
                    continue
                if isinstance(record, dict):
                    yield record

    def _rebuild(
        self, sources: Iterable[Tuple[Ecosystem, Iterator[Mapping[str, Any]]]]
    ) -> int:
        """Write a new database beside the old one and swap it in when complete."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._path.with_name(self._path.name + ".new")
        if temp.exists():
            temp.unlink()
        try:
            with closing(sqlite3.connect(temp)) as conn:
                conn.executescript(self._SCHEMA)
                for ecosystem, records in sources:
                    for record in records:
                        self._store(conn, ecosystem, record)
                count = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
                conn.executemany(
                    "INSERT INTO meta (key, value) VALUES (?, ?)",
                    [("updated_at", self._clock().isoformat()), ("advisories", str(count))],
                )
                conn.commit()
            os.replace(temp, self._path)
        finally:
            if temp.exists():
                temp.unlink()
        return count

    def _store(
        self, conn: sqlite3.Connection, ecosystem: Ecosystem, record: Mapping[str, Any]
    ) -> None:
        vuln_id = str(record.get("id", "")).strip()
        if not vuln_id or record.get("withdrawn"):
            return
        scheme = scheme_for(ecosystem)
        rows = []
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            if package.get("ecosystem") != ecosystem.value or not package.get("name"):
                continue
            ranges = self._ranges(affected.get("ranges") or [])
            if not ranges:
                continue
            rows.append((
                vuln_id, ecosystem.value, scheme.normalize_name(str(package["name"])),
                OSVSeverity.of(record, affected).value, json.dumps(ranges),
            ))
        if not rows:
            return
        conn.execute(
            "INSERT OR REPLACE INTO vulns (id, aliases, summary) VALUES (?, ?, ?)",
            (vuln_id, json.dumps(self._aliases(record)), self._summary(record)),
        )
        conn.executemany(
            "INSERT INTO affected (vuln_id, ecosystem, package, severity, ranges) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )

    @classmethod
    def _ranges(cls, raw_ranges: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        ranges = []
        for raw in raw_ranges:
            if raw.get("type") not in cls._RANGE_TYPES:
                continue
            events = [
                [kind, str(event[kind])]
                for event in raw.get("events") or []
                for kind in cls._EVENT_KINDS
                if kind in event
            ]
            if events:
                ranges.append({"type": raw["type"], "events": events})
        return ranges

    @staticmethod
    def _aliases(record: Mapping[str, Any]) -> List[str]:
        return [str(alias) for alias in record.get("aliases") or [] if alias]

    @staticmethod
    def _summary(record: Mapping[str, Any]) -> str:
        summary = str(record.get("summary") or "").strip()
        if not summary:
            details = str(record.get("details") or "").strip()
            summary = details.splitlines()[0] if details else ""
        return summary[:300]

    def _meta(self, key: str) -> str:
        if not self._path.is_file():
            return ""
        try:
            with closing(sqlite3.connect(self._path)) as conn:
                row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        except sqlite3.Error:
            return ""
        return str(row[0]) if row else ""
