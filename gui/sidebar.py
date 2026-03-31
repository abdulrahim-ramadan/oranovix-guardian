"""
Sidebar — Navigation panel with hover animations.
P2: red left-border line slides in on hover.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable, List, Optional, Tuple

import customtkinter as ctk

from gui.theme_manager    import ThemeManager
from gui.animation_manager import AnimationManager
from core.language_manager import LanguageManager


# ── NavItem ───────────────────────────────────────────────────────────────

class NavItem(ctk.CTkFrame):
    """
    A single sidebar navigation row.
    Shows icon + label; highlights on hover with colour transition.
    """

    def __init__(
        self,
        master,
        icon:    str,
        label:   str,
        page_id: str,
        on_click: Callable[[str], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            height=44,
            fg_color=tm.c("sidebar"),
            corner_radius=8,
            cursor="hand2",
            **kwargs,
        )
        self._page_id  = page_id
        self._on_click = on_click
        self._active   = False
        self.pack_propagate(False)

        # Red left-accent bar (slides in width on hover)
        self._accent_bar = tk.Frame(self, width=0, bg=tm.c("accent"))
        self._accent_bar.place(x=0, y=0, relheight=1, width=0)

        self._icon_lbl = ctk.CTkLabel(
            self,
            text=icon,
            font=ctk.CTkFont(size=16),
            text_color=tm.c("text2"),
            fg_color="transparent",
            width=36,
        )
        self._icon_lbl.pack(side="left", padx=(10, 4))

        self._text_lbl = ctk.CTkLabel(
            self,
            text=label,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=tm.c("text2"),
            fg_color="transparent",
            anchor="w",
        )
        self._text_lbl.pack(side="left", fill="x", expand=True)

        self._bind_all()

    def _bind_all(self) -> None:
        for w in (self, self._icon_lbl, self._text_lbl):
            w.bind("<ButtonRelease-1>", self._click)
            w.bind("<Enter>",           self._hover_enter)
            w.bind("<Leave>",           self._hover_leave)

    def _click(self, _event=None) -> None:
        self._on_click(self._page_id)

    def _hover_enter(self, _event=None) -> None:
        if self._active:
            return
        tm = ThemeManager()
        AnimationManager.hover_transition(
            self, self, tm.c("sidebar"), tm.c("hover"),
        )
        self._icon_lbl.configure(text_color=tm.c("text"))
        self._text_lbl.configure(text_color=tm.c("text"))
        self._slide_bar(0, 3)

    def _hover_leave(self, _event=None) -> None:
        if self._active:
            return
        tm = ThemeManager()
        AnimationManager.hover_transition(
            self, self, tm.c("hover"), tm.c("sidebar"),
        )
        self._icon_lbl.configure(text_color=tm.c("text2"))
        self._text_lbl.configure(text_color=tm.c("text2"))
        self._slide_bar(3, 0)

    def _slide_bar(self, frm: int, to: int) -> None:
        """Animate accent bar width from *frm* to *to* pixels."""
        step = 1 if to > frm else -1

        def _go(w: int) -> None:
            if w == to:
                return
            nw = w + step
            try:
                self._accent_bar.place_configure(width=nw)
            except Exception:
                return
            self.after(18, _go, nw)

        self.after(0, _go, frm)

    def set_active(self, active: bool) -> None:
        self._active = active
        tm = ThemeManager()
        if active:
            self.configure(fg_color=tm.c("active"))
            self._icon_lbl.configure(text_color=tm.c("accent"))
            self._text_lbl.configure(
                text_color=tm.c("active_text"),
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            )
            try:
                self._accent_bar.configure(bg=tm.c("accent"))
                self._accent_bar.place_configure(width=3)
            except Exception:
                pass
        else:
            self.configure(fg_color=tm.c("sidebar"))
            self._icon_lbl.configure(text_color=tm.c("text2"))
            self._text_lbl.configure(
                text_color=tm.c("text2"),
                font=ctk.CTkFont(family="Segoe UI", size=13),
            )
            try:
                self._accent_bar.place_configure(width=0)
            except Exception:
                pass

    def update_text(self, label: str) -> None:
        self._text_lbl.configure(text=label)

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        try:
            self._accent_bar.configure(bg=tm.c("accent"))
        except Exception:
            pass
        self.set_active(self._active)


# ── Sidebar ───────────────────────────────────────────────────────────────

class Sidebar(ctk.CTkFrame):
    """
    Left navigation panel.
    Width: 200 px.  Navigation items + version footer.
    """

    WIDTH = 200

    _NAV_ITEMS: List[Tuple[str, str, str]] = [
        # (icon, i18n_key, page_id)
        ("🏠", "nav_dashboard", "dashboard"),
        ("🔍", "nav_scanner",   "scanner"),
        ("📊", "nav_reports",   "reports"),
        ("⚙️",  "nav_settings",  "settings"),
    ]

    def __init__(
        self,
        master,
        on_navigate: Callable[[str], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            width=self.WIDTH,
            fg_color=tm.c("sidebar"),
            corner_radius=0,
            **kwargs,
        )
        self._on_navigate = on_navigate
        self._items:       dict[str, NavItem] = {}
        self._active_page: Optional[str]      = None
        self.pack_propagate(False)
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        # Top accent bar
        ctk.CTkFrame(
            self, height=3, fg_color=tm.c("accent"), corner_radius=0
        ).pack(fill="x")

        # App mini-logo
        logo_frame = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=56)
        logo_frame.pack(fill="x")
        logo_frame.pack_propagate(False)
        ctk.CTkLabel(
            logo_frame,
            text="🛡  Oranovix Guardian",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=tm.c("accent"),
            fg_color="transparent",
        ).pack(expand=True)

        # Divider
        ctk.CTkFrame(self, height=1, fg_color=tm.c("border"), corner_radius=0).pack(fill="x")

        # Section label
        self._section_lbl = ctk.CTkLabel(
            self,
            text=lm.t("sidebar_scanner"),
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=tm.c("text3"),
            fg_color="transparent",
            anchor="w",
        )
        self._section_lbl.pack(anchor="w", padx=16, pady=(12, 4))

        # Nav items
        nav_frame = ctk.CTkFrame(self, fg_color="transparent")
        nav_frame.pack(fill="x", padx=8)

        # Ensure translations have nav keys (fallback to reasonable defaults)
        _nav_fallbacks = {
            "nav_dashboard": "Dashboard",
            "nav_scanner":   "Scanner",
            "nav_reports":   "Reports",
            "nav_settings":  "Settings",
        }
        for icon, key, page_id in self._NAV_ITEMS:
            label = lm.t(key) if lm.t(key) != key else _nav_fallbacks[key]
            item  = NavItem(
                nav_frame,
                icon=icon,
                label=label,
                page_id=page_id,
                on_click=self._navigate,
            )
            item.pack(fill="x", pady=2)
            self._items[page_id] = item

        # Spacer
        ctk.CTkFrame(self, fg_color="transparent").pack(fill="both", expand=True)

        # Version
        ctk.CTkLabel(
            self,
            text=lm.t("version_label"),
            font=ctk.CTkFont(size=9),
            text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="bottom", pady=10)

        # Bottom border
        ctk.CTkFrame(
            self, height=1, fg_color=tm.c("border"), corner_radius=0
        ).pack(side="bottom", fill="x")

    def _navigate(self, page_id: str) -> None:
        """Called by NavItem clicks — updates highlight AND fires the app callback."""
        self._highlight(page_id)
        self._on_navigate(page_id)

    def _highlight(self, page_id: str) -> None:
        """Update visual highlight only, without firing the navigation callback."""
        if self._active_page:
            old = self._items.get(self._active_page)
            if old:
                old.set_active(False)
        item = self._items.get(page_id)
        if item:
            item.set_active(True)
        self._active_page = page_id

    def set_active(self, page_id: str) -> None:
        """Public API for app to update highlight without triggering callback."""
        self._highlight(page_id)

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("sidebar"))
        for item in self._items.values():
            item.refresh_theme()
