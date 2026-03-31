"""
ThemeManager — Singleton that owns both the Dark (Red/Black) and Light palettes.
Every UI color goes through TM.c('key').  Observers are notified on toggle.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional


class ThemeManager:
    """
    Singleton.  Two complete color palettes: DARK (Red/Black) and LIGHT.
    """

    _instance:     Optional["ThemeManager"] = None
    _initialized:  bool = False

    # ── Palettes ───────────────────────────────────────────────────────────
    DARK: Dict[str, str] = {
        "bg":           "#0a0a0a",
        "bg2":          "#111111",
        "bg3":          "#1a0000",
        "sidebar":      "#1a0000",
        "titlebar":     "#0f0f0f",
        "card":         "#150000",
        "input_bg":     "#1a0000",
        "hover":        "#2a0000",
        "active":       "#330000",
        "active_text":  "#ffffff",
        "accent":       "#cc0000",
        "accent_h":     "#ff0000",
        "accent_glow":  "#4d0000",
        "text":         "#ffffff",
        "text2":        "#888888",
        "text3":        "#555555",
        "border":       "#330000",
        "success":      "#00ff41",
        "warning":      "#ff8800",
        "error":        "#ff0000",
        "critical":     "#ff0000",
        "high":         "#cc0000",
        "medium":       "#ff8800",
        "low":          "#00ff41",
        "btn_close":    "#ff0000",
        "btn_min":      "#ff8800",
        "btn_max":      "#00ff41",
        "log_bg":       "#050505",
        "log_text":     "#cccccc",
        "log_info":     "#888888",
        "log_scan":     "#007acc",
        "log_warn":     "#ff8800",
        "log_err":      "#ff0000",
        "log_ok":       "#00ff41",
        "progress_bg":  "#1a0000",
        "splash_bg":    "#050505",
    }

    LIGHT: Dict[str, str] = {
        "bg":           "#ffffff",
        "bg2":          "#f3f3f3",
        "bg3":          "#ebebeb",
        "sidebar":      "#e8e8e8",
        "titlebar":     "#f0f0f0",
        "card":         "#f8f8f8",
        "input_bg":     "#ffffff",
        "hover":        "#e0e0e0",
        "active":       "#ffd6d6",
        "active_text":  "#cc0000",
        "accent":       "#cc0000",
        "accent_h":     "#ff0000",
        "accent_glow":  "#ffb3b3",
        "text":         "#1e1e1e",
        "text2":        "#6e6e6e",
        "text3":        "#9a9a9a",
        "border":       "#d4d4d4",
        "success":      "#16825d",
        "warning":      "#b5531f",
        "error":        "#cd3131",
        "critical":     "#cd3131",
        "high":         "#cc0000",
        "medium":       "#b5531f",
        "low":          "#16825d",
        "btn_close":    "#e81123",
        "btn_min":      "#c8a800",
        "btn_max":      "#00a343",
        "log_bg":       "#f5f5f5",
        "log_text":     "#1e1e1e",
        "log_info":     "#6e6e6e",
        "log_scan":     "#0070c1",
        "log_warn":     "#b5531f",
        "log_err":      "#cd3131",
        "log_ok":       "#16825d",
        "progress_bg":  "#d4d4d4",
        "splash_bg":    "#0d0d0d",   # splash is always dark
    }

    # ── Singleton ──────────────────────────────────────────────────────────

    def __new__(cls) -> "ThemeManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._mode: str = "dark"
        self._observers: List[Callable[[], None]] = []
        self._load_settings()

    @classmethod
    def instance(cls) -> "ThemeManager":
        return cls()

    # ── Color access ───────────────────────────────────────────────────────

    def c(self, key: str, fallback: str = "#ffffff") -> str:
        """Return hex color for *key* in the active palette."""
        palette = self.DARK if self._mode == "dark" else self.LIGHT
        return palette.get(key, fallback)

    @staticmethod
    def blend(c1: str, c2: str, t: float) -> str:
        """
        Linear interpolation between hex colors c1 (t=0) and c2 (t=1).
        Used for hover transition animations.
        """
        t = max(0.0, min(1.0, t))
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def is_dark(self) -> bool:
        return self._mode == "dark"

    @property
    def toggle_icon(self) -> str:
        return "🌙" if self._mode == "dark" else "☀️"

    # ── Switching ──────────────────────────────────────────────────────────

    def set_mode(self, mode: str) -> None:
        if mode not in ("dark", "light") or mode == self._mode:
            return
        self._mode = mode
        self._save_settings()
        self._notify()

    def toggle(self) -> None:
        self.set_mode("light" if self._mode == "dark" else "dark")

    # ── Observers ──────────────────────────────────────────────────────────

    def add_observer(self, cb: Callable[[], None]) -> None:
        if cb not in self._observers:
            self._observers.append(cb)

    def remove_observer(self, cb: Callable[[], None]) -> None:
        self._observers = [o for o in self._observers if o is not cb]

    def clear_observers(self) -> None:
        self._observers.clear()

    # ── Persistence ────────────────────────────────────────────────────────

    def _settings_path(self) -> str:
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
            data["theme"] = self._mode
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
                m = data.get("theme", "dark")
                if m in ("dark", "light"):
                    self._mode = m
        except Exception:
            pass

    def _notify(self) -> None:
        import customtkinter as ctk
        ctk.set_appearance_mode("dark" if self._mode == "dark" else "light")
        for cb in list(self._observers):
            try:
                cb()
            except Exception:
                pass
