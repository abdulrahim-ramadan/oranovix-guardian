"""
CustomTitleBar — the in-window header: logo, app name, language menu and
theme toggle.

The window itself keeps the native Windows frame, so minimize, maximize,
close, moving, snapping and resizing are the system's own.
"""
from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.asset_helper import load_logo


def _load_icon_image(size: int = 16) -> Optional[ctk.CTkImage]:
    """The app logo at ``size`` px (longer side, aspect ratio kept), or None."""
    img = load_logo(size)
    if img is None:
        return None
    return ctk.CTkImage(img, size=img.size)


class CustomTitleBar(ctk.CTkFrame):
    """Header strip under the native title bar."""

    HEIGHT = 38

    def __init__(
        self,
        master,
        window,
        on_theme_toggle: Callable,
        on_lang_change:  Callable[[str], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(
            master, height=self.HEIGHT,
            fg_color=tm.c("titlebar"), corner_radius=0, **kwargs,
        )
        self._window    = window
        self._on_theme  = on_theme_toggle
        self._on_lang   = on_lang_change

        self.pack_propagate(False)
        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        # ── Left: icon + name ─────────────────────────────────────────
        left = ctk.CTkFrame(self, fg_color="transparent")
        left.pack(side="left", padx=(10, 0))

        icon_img = _load_icon_image(16)
        if icon_img:
            ctk.CTkLabel(
                left, image=icon_img, text="",
                fg_color="transparent", width=20,
            ).pack(side="left", padx=(0, 4))
        else:
            ctk.CTkLabel(
                left, text="🛡",
                font=ctk.CTkFont(size=16),
                text_color=tm.c("accent"), fg_color="transparent",
            ).pack(side="left", padx=(0, 4))

        self._title_lbl = ctk.CTkLabel(
            left,
            text="Oranovix Guardian",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        )
        self._title_lbl.pack(side="left")

        # ── Right: controls ───────────────────────────────────────────
        right = ctk.CTkFrame(self, fg_color="transparent")
        right.pack(side="right", padx=(0, 6))

        # Language menu
        lm_var = ctk.StringVar(value=lm.current_display_name)
        self._lang_menu = ctk.CTkOptionMenu(
            right,
            values=lm.display_names,
            variable=lm_var,
            command=self._on_lang,
            width=110, height=26,
            font=ctk.CTkFont(size=11),
            fg_color=tm.c("bg3"),
            button_color=tm.c("accent"),
            button_hover_color=tm.c("accent_h"),
            text_color=tm.c("text"),
        )
        self._lang_menu.pack(side="left", padx=(0, 6), pady=6)

        # Theme toggle
        self._theme_btn = ctk.CTkButton(
            right, text=tm.toggle_icon,
            width=32, height=26, corner_radius=6,
            font=ctk.CTkFont(size=14),
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text"), command=self._on_theme,
        )
        self._theme_btn.pack(side="left", padx=(0, 4), pady=6)

    # ------------------------------------------------------------------
    # Theme refresh
    # ------------------------------------------------------------------

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("titlebar"))
        self._theme_btn.configure(
            text=tm.toggle_icon,
            fg_color=tm.c("bg3"),
            text_color=tm.c("text"),
        )
        self._title_lbl.configure(text_color=tm.c("text"))
        self._lang_menu.configure(
            fg_color=tm.c("bg3"),
            text_color=tm.c("text"),
        )
