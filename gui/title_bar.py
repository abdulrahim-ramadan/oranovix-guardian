"""
CustomTitleBar — Replaces the OS title bar when overrideredirect=True.
Bug fixes:
  - Minimize uses ctypes SW_MINIMIZE (works with overrideredirect)
  - Maximize checks actual window state
  - App icon loaded from assets/icon.png (16x16)
"""
from __future__ import annotations

import os
import sys
from typing import Callable, Optional

import customtkinter as ctk

from gui.theme_manager import ThemeManager
from core.language_manager import LanguageManager
from gui.asset_helper import get_asset_path


def _load_icon_image(size: int = 16) -> Optional[ctk.CTkImage]:
    """Load assets/icon.png and return a CTkImage, or None on failure."""
    try:
        from PIL import Image
        ico = get_asset_path("icon.png")
        if os.path.exists(ico):
            img = Image.open(ico).convert("RGBA").resize((size, size))
            return ctk.CTkImage(img, size=(size, size))
    except Exception:
        pass
    return None


class CustomTitleBar(ctk.CTkFrame):
    """Red/Black custom title bar with drag-to-move."""

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
        self._drag_x    = 0
        self._drag_y    = 0

        self.pack_propagate(False)
        self._build()
        self._bind_drag()

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
        right.pack(side="right")

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

        # Divider
        ctk.CTkFrame(
            right, width=1, height=22, fg_color=tm.c("border")
        ).pack(side="left", padx=4, pady=8)

        # Window buttons
        self._btn_min = self._wbtn(right, "─", tm.c("text2"), tm.c("accent"),  self._minimize)
        self._btn_max = self._wbtn(right, "□", tm.c("text2"), tm.c("accent"),  self._maximize)
        self._btn_cls = self._wbtn(right, "✕", "#ffffff",     tm.c("error"),   self._close)

    @staticmethod
    def _wbtn(parent, text, text_color, hover_color, command) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            parent, text=text,
            width=38, height=38, corner_radius=0,
            font=ctk.CTkFont(size=11),
            fg_color="transparent",
            hover_color=hover_color,
            text_color=text_color,
            command=command,
        )
        btn.pack(side="left")
        return btn

    # ------------------------------------------------------------------
    # Window actions (Bug 3 fix: ctypes minimize)
    # ------------------------------------------------------------------

    def _minimize(self) -> None:
        """Minimize window — uses ctypes on Windows so overrideredirect works."""
        if sys.platform == "win32":
            try:
                import ctypes
                hwnd = ctypes.windll.user32.GetParent(self._window.winfo_id())
                ctypes.windll.user32.ShowWindow(hwnd, 6)   # SW_MINIMIZE = 6
                return
            except Exception:
                pass
        self._window.iconify()

    def _maximize(self) -> None:
        if self._window.state() == "zoomed":
            self._window.state("normal")
            self._btn_max.configure(text="□")
        else:
            self._window.state("zoomed")
            self._btn_max.configure(text="❐")

    def _close(self) -> None:
        self._window.destroy()

    # ------------------------------------------------------------------
    # Drag to move
    # ------------------------------------------------------------------

    def _bind_drag(self) -> None:
        self.bind("<ButtonPress-1>",  self._on_press)
        self.bind("<B1-Motion>",      self._on_drag)
        self._title_lbl.bind("<ButtonPress-1>", self._on_press)
        self._title_lbl.bind("<B1-Motion>",     self._on_drag)

    def _on_press(self, event) -> None:
        self._drag_x = event.x_root - self._window.winfo_x()
        self._drag_y = event.y_root - self._window.winfo_y()

    def _on_drag(self, event) -> None:
        if self._window.state() == "zoomed":
            return
        self._window.geometry(
            f"+{event.x_root - self._drag_x}+{event.y_root - self._drag_y}"
        )

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
