"""
StatusBar — Bottom strip: status dot + message, scan time, language badge.
"""
from __future__ import annotations

import customtkinter as ctk

from gui.theme_manager    import ThemeManager
from core.language_manager import LanguageManager


class StatusBar(ctk.CTkFrame):
    """Single-row status bar at the bottom of the main window."""

    HEIGHT = 26

    def __init__(self, master, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            height=self.HEIGHT,
            fg_color=tm.c("bg2"),
            corner_radius=0,
            **kwargs,
        )
        self.pack_propagate(False)
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        # Left: status
        self._dot = ctk.CTkLabel(
            self,
            text="●",
            font=ctk.CTkFont(size=9),
            text_color=tm.c("success"),
            fg_color="transparent",
            width=14,
        )
        self._dot.pack(side="left", padx=(10, 2))

        self._status_lbl = ctk.CTkLabel(
            self,
            text=lm.t("ready"),
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=tm.c("text2"),
            fg_color="transparent",
        )
        self._status_lbl.pack(side="left")

        # Right: language + version
        ctk.CTkLabel(
            self,
            text=lm.current_display_name,
            font=ctk.CTkFont(size=10),
            text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="right", padx=(0, 12))

        ctk.CTkFrame(
            self, width=1, height=14, fg_color=tm.c("border")
        ).pack(side="right", padx=4)

        ctk.CTkLabel(
            self,
            text="Oranovix Guardian v1.0",
            font=ctk.CTkFont(size=10),
            text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="right", padx=(0, 4))

        # Accent line at very top of status bar
        ctk.CTkFrame(
            self, height=1, fg_color=tm.c("border"), corner_radius=0
        ).place(relx=0, rely=0, relwidth=1)

    def set_status(self, text: str, level: str = "info") -> None:
        """Update the status text. level: 'info' | 'ok' | 'warn' | 'error'"""
        tm = ThemeManager()
        color_map = {
            "info":  tm.c("text2"),
            "ok":    tm.c("success"),
            "warn":  tm.c("warning"),
            "error": tm.c("error"),
        }
        dot_map = {
            "info":  tm.c("text3"),
            "ok":    tm.c("success"),
            "warn":  tm.c("warning"),
            "error": tm.c("error"),
        }
        self._status_lbl.configure(text=text, text_color=color_map.get(level, tm.c("text2")))
        self._dot.configure(text_color=dot_map.get(level, tm.c("text3")))

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg2"))
