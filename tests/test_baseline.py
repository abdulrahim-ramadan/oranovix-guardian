"""Baseline: what it records, what it ignores, and that tampering is detected."""
from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterator

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.backends.fail import Keyring as FailKeyring

from core.secret_store import SecretStore
from live_defense.baseline import (
    HMAC_KEY_NAME,
    UNREADABLE,
    Baseline,
    BaselineError,
    FileState,
    FileTree,
    IgnoreRules,
)


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


def write(path: Path, data: str | bytes = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "site"
    write(root / "manage.py", "print('manage')\n")
    write(root / "app" / "settings.py", "DEBUG = False\n")
    write(root / "static" / "logo.png", b"\x89PNG\r\n")
    write(root / "README.md", "# Site\n")
    return root


@pytest.fixture
def keys() -> MemoryKeyStore:
    return MemoryKeyStore()


@pytest.fixture
def baseline(project: Path, tmp_path: Path, keys: MemoryKeyStore) -> Baseline:
    created = Baseline(str(project), str(tmp_path / "integrity.db"), keys)
    created.create()
    return created


def raw_update(baseline: Baseline, sql: str, *params: object) -> None:
    """Change the database the way an attacker would: directly."""
    with closing(sqlite3.connect(baseline.db_path)) as conn:
        conn.execute(sql.replace("{table}", baseline._table), params)
        conn.commit()


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

def test_every_file_is_recorded_with_hash_size_and_mtime(baseline: Baseline, project: Path) -> None:
    entries = baseline.entries()

    assert sorted(entries) == ["README.md", "app/settings.py", "manage.py", "static/logo.png"]
    settings = entries["app/settings.py"]
    content = (project / "app" / "settings.py").read_bytes()
    assert settings.sha256 == hashlib.sha256(content).hexdigest()
    assert settings.size == len(content)
    assert settings.mtime_ns == os.stat(project / "app" / "settings.py").st_mtime_ns


def test_all_file_types_are_covered(project: Path, tmp_path: Path, keys: MemoryKeyStore) -> None:
    for name in ("photo.jpg", "data.bin", "Makefile", ".htaccess", "notes"):
        write(project / name)
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"), keys)

    baseline.create()

    assert {"photo.jpg", "data.bin", "Makefile", ".htaccess", "notes"} <= set(baseline.entries())


def test_excluded_folders_and_default_patterns_are_ignored(
    project: Path, tmp_path: Path, keys: MemoryKeyStore
) -> None:
    write(project / "venv" / "lib" / "site.py")
    write(project / "node_modules" / "lodash" / "index.js")
    write(project / "app" / "__pycache__" / "x.cpython-313.pyc")
    write(project / "app" / "views.pyc")
    write(project / "debug.log")
    write(project / "db.sqlite3")
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"), keys)

    baseline.create()

    assert sorted(baseline.entries()) == [
        "README.md", "app/settings.py", "manage.py", "static/logo.png",
    ]


def test_user_patterns(project: Path, tmp_path: Path, keys: MemoryKeyStore) -> None:
    write(project / "cache" / "a.bin")
    write(project / "app" / "local.ini")
    write(project / "exports" / "2026" / "report.csv")
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"), keys)

    baseline.create(["cache/", "*.ini", "exports/*", "  ", "# a comment"])

    assert baseline.ignore_patterns() == ("cache/", "*.ini", "exports/*")
    assert not any(p.startswith(("cache/", "exports/")) or p.endswith(".ini") for p in baseline.entries())


def test_database_inside_the_root_is_not_recorded(project: Path, keys: MemoryKeyStore) -> None:
    baseline = Baseline(str(project), str(project / "integrity.db"), keys)

    baseline.create()
    baseline.create()       # the file now exists inside the root

    assert "integrity.db" not in baseline.entries()


def test_hash_is_streamed(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    big = write(project / "big.bin", os.urandom(3 * FileTree.CHUNK + 17))
    monkeypatch.setattr(FileTree, "CHUNK", 1024)

    digest = FileTree(str(project), IgnoreRules()).hash("big.bin")

    assert digest == hashlib.sha256(big.read_bytes()).hexdigest()


def test_unreadable_file(project: Path) -> None:
    assert FileTree(str(project), IgnoreRules()).hash("missing.txt") == UNREADABLE


def test_symlinks_are_recorded_but_not_followed(
    project: Path, tmp_path: Path, keys: MemoryKeyStore
) -> None:
    outside = write(tmp_path / "outside" / "secret.txt", "outside the root")
    try:
        os.symlink(outside, project / "link.txt")
        os.symlink(outside.parent, project / "linkdir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra rights on this system")
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"), keys)

    baseline.create()

    entries = baseline.entries()
    assert entries["link.txt"].sha256 != hashlib.sha256(outside.read_bytes()).hexdigest()
    assert entries["link.txt"].size == 0
    assert "linkdir" in entries
    assert not any(p.startswith("linkdir/") for p in entries)


@pytest.mark.skipif(os.name != "nt", reason="directory junctions exist on Windows only")
def test_junctions_are_recorded_but_not_followed(
    project: Path, tmp_path: Path, keys: MemoryKeyStore
) -> None:
    import _winapi

    outside = write(tmp_path / "outside" / "secret.txt", "outside the root")
    _winapi.CreateJunction(str(outside.parent), str(project / "junction"))  # type: ignore[attr-defined]
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"), keys)

    baseline.create()

    entries = baseline.entries()
    assert "junction" in entries
    assert entries["junction"].size == 0
    assert not any(p.startswith("junction/") for p in entries)


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

def test_fresh_baseline_verifies(baseline: Baseline) -> None:
    assert baseline.exists()
    assert baseline.verify().ok


def test_editing_a_row_is_detected(baseline: Baseline) -> None:
    raw_update(baseline, "UPDATE {table} SET sha256 = ? WHERE path = 'app/settings.py'", "0" * 64)

    result = baseline.verify()

    assert not result.ok
    assert "signature" in result.detail


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM {table} WHERE path = 'manage.py'",
        "INSERT INTO {table} VALUES ('uploads/shell.php', 'aa', 1, 1)",
        "UPDATE {table} SET mtime_ns = mtime_ns + 1",
        "UPDATE roots SET ignore_patterns = '[\"*.php\"]'",
        "UPDATE roots SET signature = 'forged'",
    ],
    ids=["delete-row", "insert-row", "touch-mtime", "widen-ignore", "forge-signature"],
)
def test_any_direct_change_is_detected(baseline: Baseline, sql: str) -> None:
    raw_update(baseline, sql)

    assert not baseline.verify().ok


def test_deleting_the_record_is_detected(baseline: Baseline) -> None:
    raw_update(baseline, "DELETE FROM roots")

    assert baseline.verify().detail == "The baseline record is missing."


def test_missing_key_is_detected(baseline: Baseline, keys: MemoryKeyStore) -> None:
    keys.value = ""

    assert baseline.verify().detail == "The baseline key is missing from the credential store."


def test_tables_of_two_roots_are_separate(tmp_path: Path, keys: MemoryKeyStore) -> None:
    db = str(tmp_path / "integrity.db")
    first = Baseline(str(write(tmp_path / "a" / "x.txt").parent), db, keys)
    second = Baseline(str(write(tmp_path / "b" / "y.txt").parent), db, keys)

    first.create()
    second.create()

    assert list(first.entries()) == ["x.txt"]
    assert list(second.entries()) == ["y.txt"]
    assert first.verify().ok and second.verify().ok


# ---------------------------------------------------------------------------
# Changes through the app
# ---------------------------------------------------------------------------

def test_apply_updates_rows_and_resigns(baseline: Baseline) -> None:
    before = baseline.signature()

    baseline.apply({"app/settings.py": FileState(5, 7, "e" * 64), "README.md": None})

    entries = baseline.entries()
    assert entries["app/settings.py"] == FileState(5, 7, "e" * 64)
    assert "README.md" not in entries
    assert baseline.signature() != before
    assert baseline.verify().ok


def test_apply_refuses_a_tampered_baseline(baseline: Baseline) -> None:
    raw_update(baseline, "UPDATE {table} SET size = 0")

    with pytest.raises(BaselineError, match="modified outside the app"):
        baseline.apply({"manage.py": None})


def test_changing_patterns_drops_rows_and_resigns(baseline: Baseline) -> None:
    patterns = baseline.set_ignore_patterns(["static/", "*.md"])

    assert patterns == ("static/", "*.md")
    assert sorted(baseline.entries()) == ["app/settings.py", "manage.py"]
    assert baseline.verify().ok


def test_create_needs_an_existing_folder(tmp_path: Path, keys: MemoryKeyStore) -> None:
    with pytest.raises(BaselineError, match="Folder not found"):
        Baseline(str(tmp_path / "nope"), str(tmp_path / "integrity.db"), keys).create()


# ---------------------------------------------------------------------------
# Key in the credential store
# ---------------------------------------------------------------------------

class FakeKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.passwords: Dict[tuple, str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.passwords.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.passwords[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.passwords.pop((service, username), None)


@pytest.fixture
def fake_keyring() -> Iterator[FakeKeyring]:
    previous = keyring.get_keyring()
    backend = FakeKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


def test_key_is_created_in_the_credential_store(
    project: Path, tmp_path: Path, fake_keyring: FakeKeyring
) -> None:
    baseline = Baseline(str(project), str(tmp_path / "integrity.db"))

    baseline.create()

    stored = fake_keyring.passwords[("OranovixGuardian", HMAC_KEY_NAME)]
    assert len(bytes.fromhex(stored)) == 32
    assert baseline.verify().ok
    # A second baseline reuses the key.
    Baseline(str(project), str(tmp_path / "other.db")).create()
    assert fake_keyring.passwords[("OranovixGuardian", HMAC_KEY_NAME)] == stored
    # The key is not written to the database.
    assert stored.encode() not in (tmp_path / "integrity.db").read_bytes()


def test_no_credential_store_means_no_baseline(project: Path, tmp_path: Path) -> None:
    previous = keyring.get_keyring()
    keyring.set_keyring(FailKeyring())
    try:
        with pytest.raises(BaselineError, match="Secure storage is not available"):
            Baseline(str(project), str(tmp_path / "integrity.db"), SecretStore(name=HMAC_KEY_NAME)).create()
    finally:
        keyring.set_keyring(previous)
