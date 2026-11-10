"""
GUI alarm channels: red toast and taskbar flash.

Both marshal onto the Tk main thread, so ``AlarmCenter.notify`` can be
called from a scan thread or a background monitor.
"""
from __future__ import annotations

import ctypes
import sys

from core.alarm_center import (
    Alarm,
    AlarmCenter,
    AlarmChannel,
    AlarmLevel,
    SoundAlarmChannel,
)
from gui.animation_manager import AnimationManager
from gui.theme_manager import ThemeManager


class ToastAlarmChannel(AlarmChannel):
    """Shows the alarm as a toast: red for CRITICAL, orange for HIGH."""

    _DURATION_MS = 7000

    def __init__(self, root) -> None:
        self._root = root

    def deliver(self, alarm: Alarm) -> None:
        self._root.after(0, self._show, alarm)

    def _show(self, alarm: Alarm) -> None:
        tm = ThemeManager()
        color = tm.c("critical") if alarm.level is AlarmLevel.CRITICAL else tm.c("warning")
        AnimationManager.show_toast(
            self._root, alarm.message, color=color, duration_ms=self._DURATION_MS
        )


class _FlashInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("hwnd", ctypes.c_void_p),
        ("dwFlags", ctypes.c_uint),
        ("uCount", ctypes.c_uint),
        ("dwTimeout", ctypes.c_uint),
    ]


class TaskbarFlashChannel(AlarmChannel):
    """Flashes the window's taskbar button (Windows only)."""

    levels = frozenset({AlarmLevel.CRITICAL})

    _FLASHW_ALL = 0x3
    _FLASH_COUNT = 6

    def __init__(self, root) -> None:
        self._root = root

    def deliver(self, alarm: Alarm) -> None:
        self._root.after(0, self._flash)

    def _flash(self) -> None:
        if sys.platform != "win32":
            return
        try:
            info = _FlashInfo(
                ctypes.sizeof(_FlashInfo),
                self._root.winfo_id(),
                self._FLASHW_ALL,
                self._FLASH_COUNT,
                0,
            )
            ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
        except Exception:
            pass


def build_alarm_center(root) -> AlarmCenter:
    """Create the application's alarm center with sound, toast and flash."""
    return AlarmCenter(
        channels=[
            SoundAlarmChannel(),
            ToastAlarmChannel(root),
            TaskbarFlashChannel(root),
        ]
    )
