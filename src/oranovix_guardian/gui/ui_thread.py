"""
Hand a worker thread's result to the Tk thread.

Tk widgets may only be created and changed on the thread that runs the
main loop. A background job (the AI fix, a scan) calls the function
returned by ``on_ui_thread`` with its result; the real work then runs
through ``widget.after(0, ...)``. If the window is gone by then, the
result is dropped quietly.
"""
from __future__ import annotations

import tkinter
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def on_ui_thread(widget: Any, fn: Callable[[T], object]) -> Callable[[T], None]:
    """A callback, safe to call from any thread, that runs ``fn(value)`` on Tk's thread."""
    def deliver(value: T) -> None:
        try:
            widget.after(0, fn, value)
        except (tkinter.TclError, RuntimeError):
            pass                    # the window was closed while the worker ran
    return deliver
