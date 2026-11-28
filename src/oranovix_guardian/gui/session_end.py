"""
Closing politely when Windows or Restart Manager asks.

Setup (Restart Manager) and a logoff ask the app to close with
``WM_QUERYENDSESSION`` and ``WM_ENDSESSION``; Task Manager and
``taskkill`` without ``/F`` send ``WM_CLOSE``. Every one of them must
run the same clean ``_on_close`` path: stop the monitors, flush the
stores, release the locks.

* ``WM_CLOSE`` reaches Tk, which runs the ``WM_DELETE_WINDOW`` protocol.
* Tk turns ``WM_QUERYENDSESSION`` into the ``WM_SAVE_YOURSELF`` protocol.
* ``WM_ENDSESSION`` has no Tk protocol. :class:`WindowsCloseHook` sees it
  in the window procedure. At a real logoff Windows may end the process
  as soon as the message returns, so the hook waits (bounded) for the
  shutdown. For Restart Manager (``ENDSESSION_CLOSEAPP``) it must not
  wait: Tk has to keep running the close, and Restart Manager waits for
  the process to exit.

:class:`CloseMessages` holds the decisions and runs everywhere, so it is
tested off Windows. The hook only forwards messages to it.
"""
from __future__ import annotations

import logging
import sys
from typing import Any, Callable, Optional

_log = logging.getLogger(__name__)

WM_CLOSE = 0x0010
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
ENDSESSION_CLOSEAPP = 0x00000001


class CloseRequest:
    """Calls *on_close* once, however often and from wherever the close is asked."""

    def __init__(self, on_close: Callable[[], None]) -> None:
        self._on_close = on_close
        self.asked = False

    def __call__(self) -> None:
        if self.asked:
            return
        self.asked = True
        try:
            self._on_close()
        except Exception:
            _log.exception("closing after a request from Windows failed")


class CloseMessages:
    """What to do with each close message. ``None`` means: pass it on to Tk."""

    ENDSESSION_WAIT_SECONDS = 5.0

    def __init__(self, request: CloseRequest, wait: Callable[[float], None]) -> None:
        self._request = request
        self._wait = wait

    def handle(self, message: int, wparam: int, lparam: int) -> Optional[int]:
        if message == WM_QUERYENDSESSION:
            self._request()
            return 1                    # yes, the session may end; never block an update
        if message == WM_ENDSESSION:
            if not wparam:
                return None             # someone refused: the session goes on
            self._request()
            if not lparam & ENDSESSION_CLOSEAPP:
                self._wait(self.ENDSESSION_WAIT_SECONDS)
            return 0
        if message == WM_CLOSE:
            self._request()
            return None                 # Tk still runs WM_DELETE_WINDOW (same request)
        return None


class WindowsCloseHook:
    """Subclasses the Tk wrapper window to see ``WM_ENDSESSION`` (Windows only).

    Every message goes on to Tk's own window procedure unless
    :class:`CloseMessages` answers it. Installing never raises: without
    the hook the Tk protocols still cover ``WM_CLOSE`` and
    ``WM_QUERYENDSESSION``.
    """

    _GWLP_WNDPROC = -4

    def __init__(self, messages: CloseMessages) -> None:
        self._messages = messages
        self._hwnd = 0
        self._old: Any = None
        self._proc: Any = None          # keeps the ctypes callback alive

    def install(self, window: Any) -> bool:
        if sys.platform != "win32" or self._proc is not None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32")
            lresult = ctypes.c_ssize_t
            wndproc = ctypes.WINFUNCTYPE(lresult, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
            user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
                                               wintypes.WPARAM, wintypes.LPARAM]
            user32.CallWindowProcW.restype = lresult
            user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            user32.SetWindowLongPtrW.restype = ctypes.c_void_p

            hwnd = int(window.wm_frame(), 16)

            def proc(handle: Any, message: int, wparam: int, lparam: int) -> int:
                try:
                    answer = self._messages.handle(message, wparam, lparam)
                except Exception:
                    answer = None
                if answer is not None and message != WM_CLOSE:
                    return answer
                return user32.CallWindowProcW(self._old, handle, message, wparam, lparam)

            self._proc = wndproc(proc)
            pointer = ctypes.cast(self._proc, ctypes.c_void_p).value
            old = user32.SetWindowLongPtrW(hwnd, self._GWLP_WNDPROC, pointer)
            if not old:
                self._proc = None
                return False
            self._old, self._hwnd = old, hwnd
            return True
        except Exception:
            _log.warning("the close hook could not be installed", exc_info=True)
            self._proc = None
            return False

    def remove(self) -> None:
        """Gives Tk its own window procedure back before the window is destroyed."""
        if self._proc is None or not self._old:
            return
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.WinDLL("user32")
            user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            user32.SetWindowLongPtrW.restype = ctypes.c_void_p
            user32.SetWindowLongPtrW(self._hwnd, self._GWLP_WNDPROC, self._old)
        except Exception:
            pass
        self._old = None
