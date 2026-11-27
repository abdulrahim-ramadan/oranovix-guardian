"""
Match the native Windows frame to the app theme.

Windows 10 1809+ and 11: dark or light title bar
(``DWMWA_USE_IMMERSIVE_DARK_MODE``). Windows 11 also takes the exact
caption and caption-text colors. Everywhere else, and on any error, this
does nothing: the frame color is cosmetic.
"""
from __future__ import annotations

import sys
from typing import Any

DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19      # Windows 10 before 20H1
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36
WINDOWS_11_BUILD = 22000


def _dwm_set(hwnd: int, attribute: int, value: int) -> int:
    """``DwmSetWindowAttribute`` with a 4-byte value; returns the HRESULT."""
    import ctypes
    from ctypes import wintypes
    data = wintypes.DWORD(value)
    return ctypes.windll.dwmapi.DwmSetWindowAttribute(
        wintypes.HWND(hwnd), wintypes.DWORD(attribute),
        ctypes.byref(data), ctypes.sizeof(data),
    )


def _windows_build() -> int:
    return sys.getwindowsversion().build  # type: ignore[attr-defined]


def _colorref(hex_color: str) -> int:
    """``#RRGGBB`` as a Win32 COLORREF (0x00BBGGRR)."""
    value = hex_color.lstrip("#")
    if len(value) != 6:
        raise ValueError(hex_color)
    r, g, b = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
    return (b << 16) | (g << 8) | r


def apply_frame_theme(window: Any, dark: bool, caption: str, text: str) -> None:
    """Color the native frame of ``window``. Never raises."""
    if sys.platform != "win32":
        return
    try:
        # wm_frame is the real top-level HWND; winfo_id is Tk's inner client window.
        hwnd = int(window.wm_frame(), 16)
        if not hwnd:
            return
        flag = 1 if dark else 0
        if _dwm_set(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, flag) != 0:
            _dwm_set(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, flag)
        if _windows_build() >= WINDOWS_11_BUILD:
            _dwm_set(hwnd, DWMWA_CAPTION_COLOR, _colorref(caption))
            _dwm_set(hwnd, DWMWA_TEXT_COLOR, _colorref(text))
    except Exception:
        pass
