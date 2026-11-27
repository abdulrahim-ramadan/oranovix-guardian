"""
Entry point for the Oranovix Guardian desktop application.

This module bootstraps the application by ensuring the source directory is
present on ``sys.path`` (so all package imports resolve regardless of the
working directory), instantiating the :class:`~oranovix_guardian.gui.app.CodeGuardianApp`
root window, and handing control to Tkinter's event loop.

Running this file directly (``python main.py``) and importing it as a
module are both supported; the ``if __name__ == "__main__"`` guard
prevents unintended execution when the module is imported by tests or
other tooling.

Version: 1.2.0
"""
from __future__ import annotations

import sys
from pathlib import Path

if sys.platform == "win32":
    # Own taskbar identity: our icon, not Python's, when run from source.
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Oranovix.Guardian")
    except Exception:
        pass

# The source launcher and PyInstaller use the same qualified package imports.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core import single_instance
from oranovix_guardian.core.single_instance import AppLocks, tell_already_running
from oranovix_guardian.gui.app import CodeGuardianApp


def main() -> None:
    """Create the application window and start the Tkinter event loop.

    This is the single entry point for the entire application.  A second
    copy on the same data folder only brings the running one to the front:
    two copies would run their monitors on the same databases.  While the
    window is open a fixed mutex tells Setup and the uninstaller that the
    app is running (``installer.iss``, ``AppMutex``).  Data an
    older version wrote next to the exe is copied into the data folder
    once, before anything reads it.  Then :class:`~oranovix_guardian.gui.app.CodeGuardianApp`
    opens the scanner and creates other pages on demand, and ``mainloop()``
    blocks until the window is closed.
    """
    instance = AppLocks(single_instance.SingleInstance.for_data_dir(), single_instance.RunningMarker())
    if not instance.acquire():
        tell_already_running()
        return
    try:
        AppPaths.migrate_legacy()
        app = CodeGuardianApp(instance=instance)
        app.mainloop()
    finally:
        instance.release()


if __name__ == "__main__":
    main()
