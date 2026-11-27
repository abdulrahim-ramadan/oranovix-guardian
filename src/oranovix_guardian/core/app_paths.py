"""
Where Oranovix Guardian keeps its files.

There are two kinds of files:

* Resources that ship with the app (assets, translations,
  ``default_rules.json``). They are read-only and come from the
  PyInstaller bundle (``sys._MEIPASS``) or, from source, from the
  checkout and application package.
* Data the app writes (settings, databases, custom rules, reports). It
  all lives in one data folder, and this class is the only place that
  knows where that is:

  - ``ORANOVIX_DATA_DIR`` when set (tests, portable use);
  - the installed exe on Windows: ``%LOCALAPPDATA%\\Oranovix Guardian``,
    falling back to ``%APPDATA%`` and then the home folder. The exe
    itself lives in Program Files, which a normal user cannot write to;
  - the installed exe elsewhere: ``$XDG_DATA_HOME/Oranovix Guardian``
    (default ``~/.local/share``);
  - from source: the project root, as before.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Sequence

APP_NAME = "Oranovix Guardian"
DATA_DIR_ENV = "ORANOVIX_DATA_DIR"

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _PACKAGE_ROOT.parents[1]


class DataFile:
    """Names of the files in the data folder (relative paths)."""

    SETTINGS = "settings.json"
    SCAN_HISTORY = "scan_history.db"      # also holds the alarm memory
    INTEGRITY = "integrity.db"
    FEED = "feed.db"
    SECURITY_EVENTS = "security_events.db"
    SENTINEL_STATE = "log_sentinel_state.db"
    OSV = "osv.db"
    CUSTOM_RULES = "rules/custom_rules.json"
    REPORTS = "reports/output"

    #: Files an older version wrote next to the exe; copied once on start.
    MIGRATED: Sequence[str] = (
        SETTINGS, SCAN_HISTORY, INTEGRITY, FEED, SECURITY_EVENTS, SENTINEL_STATE, OSV, CUSTOM_RULES,
    )


class AppPaths:
    """Resolves resource and data paths for source runs and the frozen exe."""

    MIGRATION_MARKER = ".migrated-from-install-folder"

    # ------------------------------------------------------------------
    # Mode
    # ------------------------------------------------------------------

    @staticmethod
    def is_frozen() -> bool:
        return bool(getattr(sys, "frozen", False))

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    @classmethod
    def data_dir(cls) -> Path:
        """The folder for everything the app writes; created on first use."""
        for candidate in cls._data_dir_candidates():
            try:
                candidate.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue
            return candidate
        return cls._data_dir_candidates()[0]

    @classmethod
    def _data_dir_candidates(cls) -> List[Path]:
        override = os.environ.get(DATA_DIR_ENV, "").strip()
        if override:
            return [Path(override).expanduser()]
        if not cls.is_frozen():
            return [_PROJECT_ROOT]
        bases: List[Path] = []
        if sys.platform == "win32":
            for variable in ("LOCALAPPDATA", "APPDATA"):
                value = os.environ.get(variable, "").strip()
                if value:
                    bases.append(Path(value))
        else:
            xdg = os.environ.get("XDG_DATA_HOME", "").strip()
            bases.append(Path(xdg) if xdg else Path.home() / ".local" / "share")
        bases.append(Path.home())
        return [base / APP_NAME for base in bases]

    @classmethod
    def data_file(cls, name: str) -> Path:
        """Path of *name* (e.g. ``DataFile.FEED``) inside the data folder.

        The parent folder is created, the file is not.
        """
        path = cls.data_dir() / name
        if path.parent != path:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass                    # the caller's write reports the problem
        return path

    @classmethod
    def settings_path(cls) -> Path:
        return cls.data_file(DataFile.SETTINGS)

    @classmethod
    def reports_dir(cls) -> Path:
        path = cls.data_dir() / DataFile.REPORTS
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        return path

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    @classmethod
    def resource_dir(cls) -> Path:
        """Read-only files shipped with the app."""
        bundle = getattr(sys, "_MEIPASS", None)
        if cls.is_frozen() and bundle:
            return Path(bundle)
        return _PROJECT_ROOT

    @classmethod
    def resource(cls, *parts: str) -> Path:
        if not cls.is_frozen() and parts and parts[0] in {"rules", "translations"}:
            return _PACKAGE_ROOT.joinpath(*parts)
        return cls.resource_dir().joinpath(*parts)

    # ------------------------------------------------------------------
    # Migration from the install folder
    # ------------------------------------------------------------------

    @classmethod
    def legacy_dir(cls) -> Optional[Path]:
        """Where versions up to 1.1.0 wrote their data: next to the exe."""
        if not cls.is_frozen():
            return None
        return Path(sys.executable).resolve().parent

    @classmethod
    def migrate_legacy(cls) -> List[str]:
        """Copy data files from the install folder into the data folder.

        Runs once: a marker in the data folder stops later copies. A file
        that already exists in the data folder is never overwritten, and
        the old files are never deleted. Returns the names copied.
        """
        legacy = cls.legacy_dir()
        if legacy is None:
            return []
        target = cls.data_dir()
        marker = target / cls.MIGRATION_MARKER
        if marker.exists() or os.path.normcase(str(legacy)) == os.path.normcase(str(target.resolve())):
            return []
        copied: List[str] = []
        for name in DataFile.MIGRATED:
            source = legacy / name
            destination = target / name
            if not source.is_file() or destination.exists():
                continue
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                for suffix in ("-wal", "-shm", "-journal"):
                    companion = source.with_name(source.name + suffix)
                    if companion.is_file():
                        shutil.copy2(companion, destination.with_name(destination.name + suffix))
            except OSError:
                continue
            copied.append(name)
        try:
            marker.write_text("\n".join(copied) + "\n", encoding="utf-8")
        except OSError:
            pass
        return copied
