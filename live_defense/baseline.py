"""
Baseline: the known-good state of every file under a monitored root.

One SQLite table per root holds relative path, sha256, size and mtime.
The rows and the ignore patterns are signed with HMAC-SHA256; the key
lives in the OS credential store, so editing the database file by hand
is detected on the next check.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import sys
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

from core.secret_store import SecretStore
from .paths import public_part

HMAC_KEY_NAME = "file_integrity_hmac_key"
UNREADABLE = "unreadable"
TAMPER_REASON = "Baseline was modified outside the app"


class BaselineError(RuntimeError):
    """The baseline cannot be created or changed."""


class KeyStore(Protocol):
    def get(self) -> str: ...
    def set(self, value: str) -> None: ...
    def is_available(self) -> bool: ...


@dataclass(frozen=True)
class FileState:
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class StatInfo:
    """Size and mtime from ``lstat``: symlinks are never followed."""

    size: int
    mtime_ns: int
    is_link: bool


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    detail: str = ""


class IgnoreRules:
    """Decides which files the baseline leaves out.

    Deliberately not the scanner's ``EXCLUDED_DIRS``: build output, dist,
    migrations and ``.git/hooks`` are where planted files hide, so only
    pure third-party or cache folders are skipped, and not even those
    when they sit inside a public folder.
    """

    DEFAULT_FILE_PATTERNS: Tuple[str, ...] = ("*.pyc", "*.log", "db.sqlite3")
    SKIPPED_DIRS: Tuple[str, ...] = ("__pycache__", "node_modules", "venv", ".venv", "site-packages")
    SKIPPED_PATHS: Tuple[str, ...] = (".git/objects",)

    def __init__(
        self,
        user_patterns: Iterable[str] = (),
        extra_files: Iterable[str] = (),
        root_name: str = "",
    ) -> None:
        self.user_patterns: Tuple[str, ...] = self.clean(user_patterns)
        self._extra = {os.path.normcase(os.path.abspath(p)) for p in extra_files}
        self._root_name = root_name

    @staticmethod
    def clean(patterns: Iterable[str]) -> Tuple[str, ...]:
        """Strip blanks and ``#`` comments; keep order, drop repeats."""
        seen: Dict[str, None] = {}
        for raw in patterns:
            pattern = raw.strip().replace("\\", "/")
            if pattern and not pattern.startswith("#"):
                seen.setdefault(pattern, None)
        return tuple(seen)

    def ignores_dir(self, name: str, relative: str) -> bool:
        if self._skipped_by_default(relative):
            return True
        return any(
            self._match(name, relative, pattern.rstrip("/"))
            for pattern in self.user_patterns
            if pattern.endswith("/") or "*" not in pattern or "/" in pattern
        )

    def ignores_file(self, name: str, relative: str, absolute: str) -> bool:
        if os.path.normcase(absolute) in self._extra:
            return True
        patterns = (*self.DEFAULT_FILE_PATTERNS, *(p for p in self.user_patterns if not p.endswith("/")))
        return any(self._match(name, relative, pattern) for pattern in patterns)

    def _skipped_by_default(self, relative: str) -> bool:
        parts = PurePosixPath(relative).parts
        if not parts:
            return False
        lowered = [p.lower() for p in parts]
        if lowered[-1] not in self.SKIPPED_DIRS and "/".join(lowered[-2:]) not in self.SKIPPED_PATHS:
            return False
        return not public_part((self._root_name, *parts[:-1]))

    @staticmethod
    def _match(name: str, relative: str, pattern: str) -> bool:
        pattern = pattern.lower()
        return fnmatch.fnmatch(name.lower(), pattern) or fnmatch.fnmatch(relative.lower(), pattern)


class FileTree:
    """Walks a root without following links and hashes files by streaming."""

    CHUNK = 1 << 20

    def __init__(self, root: str, rules: IgnoreRules) -> None:
        self._root = os.path.abspath(root)
        self._rules = rules

    def walk(self) -> Dict[str, StatInfo]:
        found: Dict[str, StatInfo] = {}
        pending: List[Tuple[str, str]] = [(self._root, "")]
        while pending:
            folder, prefix = pending.pop()
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                relative = f"{prefix}{entry.name}"
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if self._is_link(entry.path, info):
                    if not self._rules.ignores_file(entry.name, relative, entry.path):
                        found[relative] = StatInfo(0, info.st_mtime_ns, True)
                elif stat.S_ISDIR(info.st_mode):
                    if not self._rules.ignores_dir(entry.name, relative):
                        pending.append((entry.path, relative + "/"))
                elif stat.S_ISREG(info.st_mode):
                    if not self._rules.ignores_file(entry.name, relative, entry.path):
                        found[relative] = StatInfo(info.st_size, info.st_mtime_ns, False)
        return found

    def absolute(self, relative: str) -> str:
        """Full path; on Windows a name ending in a dot or space needs the extended-length prefix."""
        parts = PurePosixPath(relative).parts
        path = os.path.join(self._root, *parts)
        if os.name == "nt" and any(p != p.rstrip(". ") for p in parts) and not path.startswith("\\\\"):
            return "\\\\?\\" + path
        return path

    def hash(self, relative: str, is_link: bool = False) -> str:
        """sha256 of the content; for a link, of its target text. ``UNREADABLE`` on error."""
        path = self.absolute(relative)
        digest = hashlib.sha256()
        try:
            if is_link:
                digest.update(b"link:" + os.readlink(path).encode("utf-8", "surrogateescape"))
                return digest.hexdigest()
            with open(path, "rb") as handle:
                while chunk := handle.read(self.CHUNK):
                    digest.update(chunk)
        except OSError:
            return UNREADABLE
        return digest.hexdigest()

    def state(self, relative: str, info: StatInfo) -> FileState:
        return FileState(info.size, info.mtime_ns, self.hash(relative, info.is_link))

    @staticmethod
    def _is_link(path: str, info: os.stat_result) -> bool:
        if stat.S_ISLNK(info.st_mode):
            return True
        isjunction = getattr(os.path, "isjunction", None)
        return bool(isjunction and isjunction(path))


class Baseline:
    """Signed record of the files under one root."""

    def __init__(
        self,
        root: str,
        db_path: Optional[str] = None,
        key_store: Optional[KeyStore] = None,
    ) -> None:
        self._root = os.path.abspath(root)
        self._db_path = Path(db_path) if db_path else self.default_path()
        self._keys: KeyStore = key_store or SecretStore(name=HMAC_KEY_NAME)
        self._root_key = os.path.normcase(self._root)
        self._table = "files_" + hashlib.sha1(self._root_key.encode("utf-8")).hexdigest()[:16]
        self._lock = threading.Lock()

    @staticmethod
    def default_path() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).parent / "integrity.db"
        return Path(__file__).resolve().parents[1] / "integrity.db"

    @property
    def root(self) -> str:
        return self._root

    @property
    def db_path(self) -> Path:
        return self._db_path

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self._root_row() is not None

    def created_at(self) -> Optional[datetime]:
        row = self._root_row()
        try:
            return datetime.fromisoformat(row[1]) if row else None
        except ValueError:
            return None

    def ignore_patterns(self) -> Tuple[str, ...]:
        row = self._root_row()
        if not row:
            return ()
        try:
            return IgnoreRules.clean(json.loads(row[0]))
        except (ValueError, TypeError):
            return ()

    def rules(self, patterns: Optional[Iterable[str]] = None) -> IgnoreRules:
        """Ignore rules of this baseline; the database file itself is always left out."""
        own = str(self._db_path)
        return IgnoreRules(
            self.ignore_patterns() if patterns is None else patterns,
            extra_files=(own, own + "-journal", own + "-wal", own + "-shm"),
            root_name=os.path.basename(self._root),
        )

    def tree(self) -> FileTree:
        return FileTree(self._root, self.rules())

    def entries(self) -> Dict[str, FileState]:
        try:
            with closing(sqlite3.connect(self._db_path)) as conn:
                rows = conn.execute(
                    f"SELECT path, size, mtime_ns, sha256 FROM {self._table}"
                ).fetchall()
        except sqlite3.Error:
            return {}
        return {path: FileState(int(size), int(mtime), str(sha)) for path, size, mtime, sha in rows}

    def verify(self) -> VerifyResult:
        """Check the signature before the baseline is trusted."""
        row = self._root_row()
        if row is None:
            return VerifyResult(False, "The baseline record is missing.")
        key = self._key()
        if key is None:
            return VerifyResult(False, "The baseline key is missing from the credential store.")
        try:
            with closing(sqlite3.connect(self._db_path)) as conn:
                rows = self._rows(conn)
        except sqlite3.Error:
            return VerifyResult(False, "The baseline table cannot be read.")
        expected = self._sign(key, row[0], rows)
        if not hmac.compare_digest(expected, str(row[2] or "")):
            return VerifyResult(False, "The stored signature does not match the baseline rows.")
        return VerifyResult(True)

    def signature(self) -> str:
        row = self._root_row()
        return str(row[2] or "") if row else ""

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def create(self, ignore_patterns: Optional[Iterable[str]] = None) -> int:
        """Record every file under the root as known-good. Returns the file count."""
        if not os.path.isdir(self._root):
            raise BaselineError(f"Folder not found: {self._root}")
        key = self._key_or_create()
        patterns = IgnoreRules.clean(
            ignore_patterns if ignore_patterns is not None else self.ignore_patterns()
        )
        tree = FileTree(self._root, self.rules(patterns))
        states = {relative: tree.state(relative, info) for relative, info in tree.walk().items()}
        with self._lock, closing(self._connect()) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {self._table}")
            conn.execute(
                f"CREATE TABLE {self._table} (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, "
                "size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL)"
            )
            conn.executemany(
                f"INSERT INTO {self._table} (path, sha256, size, mtime_ns) VALUES (?, ?, ?, ?)",
                [(p, s.sha256, s.size, s.mtime_ns) for p, s in states.items()],
            )
            patterns_json = json.dumps(list(patterns))
            now = datetime.now().isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO roots (root_key, root, table_name, created_at, "
                "ignore_patterns, signature) VALUES (?, ?, ?, ?, ?, ?)",
                (self._root_key, self._root, self._table, now, patterns_json,
                 self._sign(key, patterns_json, self._rows(conn))),
            )
            conn.commit()
        return len(states)

    def apply(self, changes: Mapping[str, Optional[FileState]]) -> None:
        """Accept changes: store each new state (``None`` removes the file) and re-sign."""
        self._require_trusted()
        key = self._key()
        if key is None:
            raise BaselineError("The baseline key is missing from the credential store.")
        with self._lock, closing(self._connect()) as conn:
            for relative, state in changes.items():
                if state is None:
                    conn.execute(f"DELETE FROM {self._table} WHERE path = ?", (relative,))
                else:
                    conn.execute(
                        f"INSERT OR REPLACE INTO {self._table} (path, sha256, size, mtime_ns) "
                        "VALUES (?, ?, ?, ?)",
                        (relative, state.sha256, state.size, state.mtime_ns),
                    )
            self._resign(conn, key)
            conn.commit()

    def set_ignore_patterns(self, patterns: Iterable[str]) -> Tuple[str, ...]:
        """Change the user patterns, drop rows they now exclude, and re-sign."""
        self._require_trusted()
        key = self._key()
        if key is None:
            raise BaselineError("The baseline key is missing from the credential store.")
        cleaned = IgnoreRules.clean(patterns)
        rules = self.rules(cleaned)
        with self._lock, closing(self._connect()) as conn:
            for (relative,) in conn.execute(f"SELECT path FROM {self._table}").fetchall():
                name = PurePosixPath(relative).name
                parents = PurePosixPath(relative).parents
                hidden_by_dir = any(
                    rules.ignores_dir(parent.name, parent.as_posix())
                    for parent in parents if parent.as_posix() != "."
                )
                absolute = os.path.join(self._root, *PurePosixPath(relative).parts)
                if hidden_by_dir or rules.ignores_file(name, relative, absolute):
                    conn.execute(f"DELETE FROM {self._table} WHERE path = ?", (relative,))
            conn.execute(
                "UPDATE roots SET ignore_patterns = ? WHERE root_key = ?",
                (json.dumps(list(cleaned)), self._root_key),
            )
            self._resign(conn, key)
            conn.commit()
        return cleaned

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require_trusted(self) -> None:
        result = self.verify()
        if not result.ok:
            raise BaselineError(f"{TAMPER_REASON}. {result.detail} Create a new baseline.")

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS roots (root_key TEXT PRIMARY KEY, root TEXT NOT NULL, "
            "table_name TEXT NOT NULL, created_at TEXT NOT NULL, ignore_patterns TEXT NOT NULL, "
            "signature TEXT NOT NULL)"
        )
        return conn

    def _root_row(self) -> Optional[Tuple[str, str, str]]:
        if not self._db_path.is_file():
            return None
        try:
            with closing(sqlite3.connect(self._db_path)) as conn:
                row = conn.execute(
                    "SELECT ignore_patterns, created_at, signature FROM roots WHERE root_key = ?",
                    (self._root_key,),
                ).fetchone()
        except sqlite3.Error:
            return None
        return (str(row[0]), str(row[1]), str(row[2])) if row else None

    def _rows(self, conn: sqlite3.Connection) -> List[Tuple[str, str, int, int]]:
        return conn.execute(
            f"SELECT path, sha256, size, mtime_ns FROM {self._table} ORDER BY path"
        ).fetchall()

    def _resign(self, conn: sqlite3.Connection, key: bytes) -> None:
        row = conn.execute(
            "SELECT ignore_patterns FROM roots WHERE root_key = ?", (self._root_key,)
        ).fetchone()
        conn.execute(
            "UPDATE roots SET signature = ? WHERE root_key = ?",
            (self._sign(key, str(row[0]), self._rows(conn)), self._root_key),
        )

    def _sign(self, key: bytes, patterns_json: str, rows: Sequence[Tuple[str, str, int, int]]) -> str:
        mac = hmac.new(key, digestmod=hashlib.sha256)
        mac.update(f"oranovix-baseline-v1\n{self._root_key}\n{patterns_json}\n".encode("utf-8"))
        for path, sha, size, mtime in sorted(rows):
            mac.update(f"{path}\0{sha}\0{size}\0{mtime}\n".encode("utf-8", "surrogateescape"))
        return mac.hexdigest()

    def _key(self) -> Optional[bytes]:
        value = self._keys.get()
        try:
            return bytes.fromhex(value) if value else None
        except ValueError:
            return None

    def _key_or_create(self) -> bytes:
        if self._keys.get():
            key = self._key()
            if key is None:
                raise BaselineError("The baseline key in the credential store is damaged.")
            return key
        if not self._keys.is_available():
            raise BaselineError(
                "Secure storage is not available on this system, so the baseline cannot be signed."
            )
        value = secrets.token_hex(32)
        try:
            self._keys.set(value)
        except Exception as exc:
            raise BaselineError(f"The baseline key could not be stored ({type(exc).__name__}).") from exc
        return bytes.fromhex(value)
