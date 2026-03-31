"""
Entry point for the Oranovix Guardian desktop application.

This module bootstraps the application by ensuring the project root is
present on ``sys.path`` (so all package imports resolve regardless of the
working directory), instantiating the :class:`~gui.app.CodeGuardianApp`
root window, and handing control to Tkinter's event loop.

Running this file directly (``python main.py``) and importing it as a
module are both supported; the ``if __name__ == "__main__"`` guard
prevents unintended execution when the module is imported by tests or
other tooling.

Version: 1.1.0
"""
from __future__ import annotations

import sys
import os

# Ensure the project root directory is first on sys.path so that all
# internal packages (gui, core, scanner_engine, …) can be imported with
# simple top-level names regardless of the current working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import CodeGuardianApp


def main() -> None:
    """Create the application window and start the Tkinter event loop.

    This is the single entry point for the entire application.  It
    instantiates :class:`~gui.app.CodeGuardianApp`, which internally
    shows the splash screen and builds the full UI, then delegates
    execution to ``mainloop()`` which blocks until the window is closed.
    """
    app = CodeGuardianApp()
    app.mainloop()


if __name__ == "__main__":
    main()
