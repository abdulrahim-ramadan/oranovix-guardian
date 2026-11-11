"""
Consent dialog shown before the first online AI fix request.
"""
from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from core.language_manager import LanguageManager
from gui.theme_manager import ThemeManager


class AIConsentDialog(ctk.CTkToplevel):
    """Modal question: may the vulnerable line be sent to Google Gemini?

    ``choice`` is ``True`` (Allow), ``False`` (Use offline only) or
    ``None`` when the window was closed without an answer.
    """

    def __init__(self, master) -> None:
        super().__init__(master)
        tm = ThemeManager()
        lm = LanguageManager()
        self.choice: Optional[bool] = None

        self.title(lm.t("ai_consent_title"))
        self.geometry("460x200")
        self.resizable(False, False)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())

        ctk.CTkLabel(
            self, text=lm.t("ai_consent_title"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
            anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(18, 6))

        ctk.CTkLabel(
            self, text=lm.t("ai_consent_text"),
            font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
            fg_color="transparent", wraplength=420,
            anchor=lm.text_anchor, justify="right" if lm.is_rtl else "left",
        ).pack(fill="x", padx=20, pady=(0, 14))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(0, 16), side="bottom")

        # Offline is the default: it has the focus and answers the Enter key.
        offline_btn = ctk.CTkButton(
            buttons, text=lm.t("ai_consent_offline"),
            width=160, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", font=ctk.CTkFont(size=11),
            command=lambda: self._answer(False),
        )
        offline_btn.pack(side="right")
        ctk.CTkButton(
            buttons, text=lm.t("ai_consent_allow"),
            width=110, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), font=ctk.CTkFont(size=11),
            command=lambda: self._answer(True),
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _e: self._answer(False))
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(100, self._take_focus, offline_btn)

    def _take_focus(self, button: ctk.CTkButton) -> None:
        try:
            self.lift()
            self.grab_set()
            button.focus_set()
        except Exception:
            pass  # window already closed

    def _answer(self, allowed: bool) -> None:
        self.choice = allowed
        self.destroy()

    @classmethod
    def ask(cls, master) -> Optional[bool]:
        """Show the dialog and wait for the answer."""
        dialog = cls(master)
        master.wait_window(dialog)
        return dialog.choice
