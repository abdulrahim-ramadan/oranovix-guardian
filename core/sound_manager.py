"""
SoundManager — Windows sound alerts using winsound (built-in, no install needed).
P4 implementation: critical / complete / error tones with settings persistence.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import List, Tuple


class SoundManager:
    """
    Singleton.  Plays alert tones via winsound on Windows.
    Gracefully silenced on non-Windows or when disabled by user.
    """

    _instance:    "SoundManager | None" = None
    _initialized: bool = False

    # Named tone sequences: list of (frequency_hz, duration_ms) tuples
    _TONES: dict[str, List[Tuple[int, int]]] = {
        "complete": [(880, 80), (1100, 80), (1320, 120)],   # ascending chime
        "critical": [(400, 150), (300, 150), (200, 200)],   # descending alarm
        "error":    [(300, 200), (250, 150)],                # low error beep
        "info":     [(800, 80)],                             # single short beep
        "warning":  [(600, 120), (400, 120)],                # two-tone warning
    }

    def __new__(cls) -> "SoundManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._enabled: bool  = True
        self._volume:  float = 1.0   # 0.0–1.0 (stored for UI; winsound has no vol)
        self._load_settings()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def play(self, tone: str) -> None:
        """Play a named tone asynchronously.  Safe to call from any thread."""
        if not self._enabled or sys.platform != "win32":
            return
        notes = self._TONES.get(tone)
        if not notes:
            return
        threading.Thread(
            target=self._play_notes, args=(notes,), daemon=True
        ).start()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value
        self._save_settings()

    @property
    def volume(self) -> float:
        return self._volume

    @volume.setter
    def volume(self, value: float) -> None:
        self._volume = max(0.0, min(1.0, float(value)))
        self._save_settings()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _play_notes(self, notes: List[Tuple[int, int]]) -> None:
        try:
            import winsound
            for freq, dur in notes:
                winsound.Beep(max(37, freq), max(1, dur))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Settings persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _settings_path() -> str:
        if getattr(sys, "frozen", False):
            return os.path.join(os.path.dirname(sys.executable), "settings.json")
        return str(Path(__file__).parent.parent / "settings.json")

    def _save_settings(self) -> None:
        try:
            path = self._settings_path()
            data: dict = {}
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            data["sound_enabled"] = self._enabled
            data["sound_volume"]  = self._volume
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_settings(self) -> None:
        try:
            path = self._settings_path()
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._enabled = bool(data.get("sound_enabled", True))
                self._volume  = float(data.get("sound_volume", 1.0))
        except Exception:
            pass
