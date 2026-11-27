"""
The one owner of ``settings.json``.

Theme, sound, AI consent, Live Defense, Threat Feed and Log Sentinel all
keep their settings in the same file. Every read-modify-write goes
through this class so that:

* writers in different threads never lose each other's keys (one lock
  per file for the whole process);
* a crash in the middle of a write never leaves half a file (the new
  content goes to a temp file that replaces the old one);
* a file that cannot be parsed is renamed to
  ``settings.json.corrupt-<timestamp>`` instead of being overwritten
  with a single section, so nothing the user set is silently lost;
* a write that fails is reported to the user (``StorageProblems``).
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.storage_problems import StorageProblems

PathLike = Union[str, "os.PathLike[str]"]


class SettingsFile:
    """Reads and writes one settings file safely."""

    _registry_lock = threading.Lock()
    _locks: Dict[str, threading.RLock] = {}

    def __init__(self, path: Optional[PathLike] = None) -> None:
        self._explicit = Path(path) if path else None

    @property
    def path(self) -> Path:
        # Resolved on every use, so a changed data folder (tests) is honoured.
        return self._explicit if self._explicit is not None else AppPaths.settings_path()

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def read(self) -> Dict[str, Any]:
        path = self.path
        with self._lock_for(path):
            data = self._load(path)
        return data if data is not None else {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.read().get(key, default)

    def section(self, key: str) -> Dict[str, Any]:
        entry = self.read().get(key)
        return dict(entry) if isinstance(entry, dict) else {}

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def update(self, change: Callable[[Dict[str, Any]], None]) -> bool:
        """Read, apply *change* to the dict, write back. ``False`` when not saved."""
        path = self.path
        with self._lock_for(path):
            data = self._load(path)
            if data is None:
                return False                # unreadable for another reason: do not clobber
            change(data)
            return self._write(path, data)

    def set(self, key: str, value: Any) -> bool:
        return self.update(lambda data: data.__setitem__(key, value))

    def set_many(self, **values: Any) -> bool:
        return self.update(lambda data: data.update(values))

    def remove(self, key: str) -> bool:
        return self.update(lambda data: data.pop(key, None))

    def update_section(self, key: str, **values: Any) -> bool:
        def change(data: Dict[str, Any]) -> None:
            entry = data.get(key)
            entry = dict(entry) if isinstance(entry, dict) else {}
            entry.update(values)
            data[key] = entry
        return self.update(change)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @classmethod
    def _lock_for(cls, path: Path) -> threading.RLock:
        key = os.path.normcase(os.path.abspath(path))
        with cls._registry_lock:
            lock = cls._locks.get(key)
            if lock is None:
                lock = cls._locks[key] = threading.RLock()
            return lock

    def _load(self, path: Path) -> Optional[Dict[str, Any]]:
        """The file's content; ``{}`` when missing or corrupt, ``None`` when unreadable."""
        try:
            text = path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            StorageProblems.report("settings", path, exc)
            return None
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            return data
        self._quarantine(path)
        return {}

    @staticmethod
    def _quarantine(path: Path) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = path.with_name(f"{path.name}.corrupt-{stamp}")
        counter = 1
        while target.exists():
            target = path.with_name(f"{path.name}.corrupt-{stamp}-{counter}")
            counter += 1
        try:
            os.replace(path, target)
        except OSError as exc:
            StorageProblems.report("settings", path, exc)

    @staticmethod
    def _write(path: Path, data: Dict[str, Any]) -> bool:
        temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            _replace(temp, path)
        except OSError as exc:
            try:
                temp.unlink()
            except OSError:
                pass
            StorageProblems.report("settings", path, exc)
            return False
        return True


def _replace(source: Path, target: Path) -> None:
    """``os.replace``; retried briefly because a virus scanner or a reader can
    hold the target open on Windows for a moment."""
    for attempt in range(5):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))
