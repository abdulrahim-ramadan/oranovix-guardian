"""
Small themed yes/no dialog.
"""
from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from core.language_manager import LanguageManager
from gui.theme_manager import ThemeManager


class ConfirmDialog(ctk.CTkToplevel):
    """Modal question; ``choice`` is ``True``, ``False``, or ``None`` when closed."""

    def __init__(self, master, title: str, text: str, yes: str, no: str) -> None:
        super().__init__(master)
        tm = ThemeManager()
        lm = LanguageManager()
        self.choice: Optional[bool] = None

        self.title(title)
        self.geometry("460x190")
        self.resizable(False, False)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())

        ctk.CTkLabel(
            self, text=title, font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(18, 6))
        ctk.CTkLabel(
            self, text=text, font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
            fg_color="transparent", wraplength=420, anchor=lm.text_anchor,
            justify="right" if lm.is_rtl else "left",
        ).pack(fill="x", padx=20, pady=(0, 14))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(0, 16), side="bottom")
        yes_btn = ctk.CTkButton(
            buttons, text=yes, width=120, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", command=lambda: self._answer(True),
        )
        yes_btn.pack(side="right")
        ctk.CTkButton(
            buttons, text=no, width=120, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), command=lambda: self._answer(False),
        ).pack(side="right", padx=(0, 8))

        self.bind("<Escape>", lambda _e: self._answer(False))
        self.after(100, self._take_focus, yes_btn)

    def _take_focus(self, button: ctk.CTkButton) -> None:
        try:
            self.lift()
            self.grab_set()
            button.focus_set()
        except Exception:
            pass

    def _answer(self, choice: bool) -> None:
        self.choice = choice
        self.destroy()

    @classmethod
    def ask(cls, master, title: str, text: str, yes: str, no: str) -> Optional[bool]:
        dialog = cls(master, title, text, yes, no)
        master.wait_window(dialog)
        return dialog.choice
