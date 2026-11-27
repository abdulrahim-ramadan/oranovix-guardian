"""
Reading a growing log file.

The position in each file is kept with the identity of the file (inode
on Linux, file index on Windows) in a small SQLite file, so a restart
continues where it stopped, a rotated file is read from its start and a
truncated file is read again from the top.

When a log is rotated by renaming it to ``<name>.1`` (logrotate and the
nginx default), the rest of the old file is read first.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from oranovix_guardian.core.app_paths import AppPaths, DataFile


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int

    @classmethod
    def of(cls, stat: os.stat_result) -> "FileIdentity":
        return cls(int(stat.st_dev), int(stat.st_ino))

    @property
    def text(self) -> str:
        return f"{self.device}:{self.inode}"


@dataclass(frozen=True)
class TailPosition:
    identity: str
    offset: int


@dataclass(frozen=True)
class ReadResult:
    lines: Tuple[str, ...] = ()
    bytes_read: int = 0
    pending: int = 0                # bytes still waiting after this read
    rotated: bool = False
    truncated: bool = False
    first_run: bool = False
    missing: bool = False


class TailStateStore:
    """Offsets of the watched files, in their own SQLite file."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._path = Path(db_path) if db_path else self.default_path()
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS positions (path TEXT PRIMARY KEY, identity TEXT NOT NULL, "
                "offset INTEGER NOT NULL)"
            )

    @staticmethod
    def default_path() -> Path:
        return AppPaths.data_file(DataFile.SENTINEL_STATE)

    def get(self, path: str) -> Optional[TailPosition]:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT identity, offset FROM positions WHERE path = ?", (self._key(path),)).fetchone()
        return TailPosition(row[0], int(row[1])) if row else None

    def save(self, path: str, position: TailPosition) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO positions (path, identity, offset) VALUES (?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET identity = excluded.identity, offset = excluded.offset",
                (self._key(path), position.identity, position.offset),
            )

    def forget(self, path: str) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM positions WHERE path = ?", (self._key(path),))

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self._path, timeout=10)


class LogTailer:
    """Reads the new complete lines of one file."""

    def __init__(self, path: str, store: TailStateStore, backfill_bytes: int = 0) -> None:
        self._path = os.path.abspath(path)
        self._store = store
        self._backfill = max(0, int(backfill_bytes))

    @property
    def path(self) -> str:
        return self._path

    ROTATED_SUFFIXES = (".1",)

    def read(self, max_bytes: int) -> ReadResult:
        """At most *max_bytes*; a line that is still being written waits for the next read."""
        saved = self._store.get(self._path)
        try:
            stat = os.stat(self._path)
        except OSError:
            return ReadResult(missing=True)
        if saved is not None and saved.identity != FileIdentity.of(stat).text:
            rest = self._finish_rotated(saved, max_bytes)
            if rest is not None:
                return rest
        identity = FileIdentity.of(stat).text
        size = int(stat.st_size)
        first_run = rotated = truncated = False
        if saved is None:
            # A new file to watch: start at its end, or a little before when asked.
            first_run = True
            offset = max(0, size - self._backfill) if self._backfill else size
        elif saved.identity != identity:
            rotated, offset = True, 0
        elif size < saved.offset:
            truncated, offset = True, 0
        else:
            offset = saved.offset

        lines, consumed = self._read_from(self._path, offset, size, max_bytes, skip_partial=first_run and offset > 0)
        new_offset = offset + consumed
        self._store.save(self._path, TailPosition(identity, new_offset))
        return ReadResult(
            lines=tuple(lines), bytes_read=consumed, pending=max(0, size - new_offset),
            rotated=rotated, truncated=truncated, first_run=first_run,
        )

    def _finish_rotated(self, saved: TailPosition, max_bytes: int) -> Optional[ReadResult]:
        """Read what is left of the file we were reading, now under its rotated name."""
        for suffix in self.ROTATED_SUFFIXES:
            old = self._path + suffix
            try:
                stat = os.stat(old)
            except OSError:
                continue
            if FileIdentity.of(stat).text != saved.identity or stat.st_size <= saved.offset:
                continue
            lines, consumed = self._read_from(old, saved.offset, int(stat.st_size), max_bytes)
            if consumed == 0:
                return None             # only a line that never ended is left
            self._store.save(self._path, TailPosition(saved.identity, saved.offset + consumed))
            # "+ 1": the new file is still waiting after the old one.
            return ReadResult(lines=tuple(lines), bytes_read=consumed,
                              pending=int(stat.st_size) - saved.offset - consumed + 1, rotated=True)
        return None

    @staticmethod
    def _read_from(path: str, offset: int, size: int, max_bytes: int,
                   skip_partial: bool = False) -> Tuple[List[str], int]:
        if size <= offset or max_bytes <= 0:
            return [], 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            chunk = handle.read(min(max_bytes, size - offset))
        consumed = 0
        if skip_partial:
            # Backfill starts in the middle of a line: skip to the next one.
            start = chunk.find(b"\n") + 1
            chunk, consumed = chunk[start:], start
        end = chunk.rfind(b"\n") + 1
        if end == 0 and len(chunk) >= max_bytes:
            end = len(chunk)            # one giant line: take it, the parser caps it
        lines = chunk[:end].decode("utf-8", errors="replace").splitlines()
        return lines, consumed + end
