"""
Only one running copy per data folder.

Two copies would run their monitors on the same databases and settings
file. On Windows a named mutex marks the running copy (it disappears
with the process, even after a crash); elsewhere an exclusive lock on a
file in the data folder does the same.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import IO, Any, Optional

from oranovix_guardian.core.app_paths import APP_NAME, AppPaths

_ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    """``acquire()`` is ``False`` when another copy holds the same name."""

    def __init__(self, name: str, lock_dir: Optional[Path] = None) -> None:
        self.name = name
        self._lock_dir = lock_dir
        self._handle: Any = None
        self._lock_file: Optional[IO[str]] = None

    @classmethod
    def for_data_dir(cls) -> "SingleInstance":
        """The instance guard for the current data folder."""
        folder = AppPaths.data_dir()
        key = hashlib.sha256(os.path.normcase(str(folder.resolve())).encode("utf-8")).hexdigest()[:16]
        return cls(f"OranovixGuardian-{key}", lock_dir=folder)

    def acquire(self) -> bool:
        if sys.platform == "win32":
            return self._acquire_mutex()
        return self._acquire_lock_file()

    def release(self) -> None:
        if self._handle is not None:
            import ctypes
            ctypes.WinDLL("kernel32").CloseHandle(self._handle)
            self._handle = None
        if self._lock_file is not None:
            try:
                self._lock_file.close()
            except OSError:
                pass
            self._lock_file = None

    # ------------------------------------------------------------------
    # Windows: named mutex
    # ------------------------------------------------------------------

    def _acquire_mutex(self) -> bool:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        handle = kernel32.CreateMutexW(None, False, f"Local\\{self.name}")
        error = ctypes.get_last_error()
        if not handle:
            return True                     # cannot tell: never block the user
        if error == _ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return False
        self._handle = handle
        return True

    # ------------------------------------------------------------------
    # Elsewhere: lock file
    # ------------------------------------------------------------------

    def _acquire_lock_file(self) -> bool:
        import fcntl  # type: ignore[import-not-found]  # POSIX only
        folder = self._lock_dir or AppPaths.data_dir()
        try:
            handle = open(folder / f".{self.name}.lock", "w", encoding="utf-8")
        except OSError:
            return True
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
        except OSError:
            handle.close()
            return False
        self._lock_file = handle
        return True


def tell_already_running() -> None:
    """Bring the running copy to the front and say why nothing else opens."""
    from oranovix_guardian.core.language_manager import LanguageManager
    lm = LanguageManager()
    text = lm.t("already_running")
    if sys.platform == "win32":
        import ctypes
        user32 = ctypes.WinDLL("user32")
        window = user32.FindWindowW("TkTopLevel", APP_NAME)      # not an Explorer window of that name
        user32.MessageBoxW(None, text, APP_NAME, 0x40 | 0x10000)     # information, foreground
        if window:
            user32.ShowWindow(window, 9)                                # SW_RESTORE
            user32.SetForegroundWindow(window)
        return
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showinfo(APP_NAME, text, parent=root)
        root.destroy()
    except Exception:
        print(text, file=sys.stderr)
