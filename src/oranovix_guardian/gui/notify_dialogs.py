"""
Dialogs of the Notifications settings: consent, preview, chat picker.

The consent follows the Threat Feed consent: it names the exact host
that will be contacted, says what is sent and what never is, and
keeping it off is the default answer.
"""
from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.notify.models import OutboundMessage


class _Dialog(ctk.CTkToplevel):
    def __init__(self, master, title: str) -> None:
        super().__init__(master)
        tm = ThemeManager()
        self.title(title)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())
        self.bind("<Escape>", lambda _e: self.destroy())

    def _heading(self, text: str) -> None:
        tm, lm = ThemeManager(), LanguageManager()
        ctk.CTkLabel(
            self, text=text, font=ctk.CTkFont(size=14, weight="bold"), text_color=tm.c("text"),
            fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(18, 6))

    def _button(self, parent, text: str, command, primary: bool = False) -> ctk.CTkButton:
        tm = ThemeManager()
        if primary:
            return ctk.CTkButton(parent, text=text, width=140, height=30, corner_radius=6, fg_color=tm.c("accent"),
                                 hover_color=tm.c("accent_h"), text_color="#ffffff", font=ctk.CTkFont(size=11),
                                 command=command)
        return ctk.CTkButton(parent, text=text, width=140, height=30, corner_radius=6, fg_color=tm.c("bg3"),
                             hover_color=tm.c("hover"), text_color=tm.c("text"), border_width=1,
                             border_color=tm.c("accent"), font=ctk.CTkFont(size=11), command=command)

    def _take_focus(self, widget) -> None:
        try:
            self.lift()
            self.grab_set()
            widget.focus_set()
        except Exception:
            pass        # already closed


class NotifyConsentDialog(_Dialog):
    """``choice`` is ``True`` only when the user switched the channel on."""

    def __init__(self, master, host: str) -> None:
        lm, tm = LanguageManager(), ThemeManager()
        super().__init__(master, lm.t("nt_consent_title"))
        self.choice: Optional[bool] = None
        self.resizable(False, False)
        self._heading(lm.t("nt_consent_title"))
        ctk.CTkLabel(
            self, text=self.consent_text(host), font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
            fg_color="transparent", wraplength=480, anchor=lm.text_anchor, justify=lm.text_justify,
        ).pack(fill="x", padx=20, pady=(0, 14))
        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(0, 16))
        off = self._button(buttons, lm.t("nt_consent_no"), lambda: self._answer(False), primary=True)
        off.pack(side="right")
        self._button(buttons, lm.t("nt_consent_yes"), lambda: self._answer(True)).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda _e: self._answer(False))
        self.after(100, self._take_focus, off)

    @staticmethod
    def consent_text(host: str) -> str:
        lm = LanguageManager()
        return "\n\n".join((lm.t("nt_consent_text", host=f"  • {host}"), lm.t("nt_consent_sent"),
                            lm.t("nt_consent_never")))

    def _answer(self, enable: bool) -> None:
        self.choice = enable
        self.destroy()

    @classmethod
    def ask(cls, master, host: str) -> bool:
        dialog = cls(master, host)
        master.wait_window(dialog)
        return dialog.choice is True


class PreviewDialog(_Dialog):
    """Shows the message that would be sent now: subject and text."""

    def __init__(self, master, message: OutboundMessage) -> None:
        lm, tm = LanguageManager(), ThemeManager()
        super().__init__(master, lm.t("nt_ui_preview_title"))
        self.geometry("640x560")
        self._heading(message.subject)
        box = ctk.CTkTextbox(self, fg_color=tm.c("input_bg"), text_color=tm.c("text"),
                             font=ctk.CTkFont(family="Consolas", size=11), wrap="word")
        box.insert("1.0", message.text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        close = self._button(self, lm.t("nt_ui_close"), self.destroy, primary=True)
        close.pack(pady=(0, 14))
        self.after(100, self._take_focus, close)


class ChatPickerDialog(_Dialog):
    """Choose one of the chats found by "Find my chat". ``choice`` is ``(id, name)`` or ``None``."""

    def __init__(self, master, chats: Sequence[Tuple[str, str]]) -> None:
        lm, tm = LanguageManager(), ThemeManager()
        super().__init__(master, lm.t("nt_ui_find_chat"))
        self.choice: Optional[Tuple[str, str]] = None
        self.resizable(False, False)
        self._heading(lm.t("nt_ui_pick_chat"))
        self._chats: List[Tuple[str, str]] = list(chats)
        self._selected = ctk.StringVar(value=self._chats[0][0] if self._chats else "")
        for chat_id, name in self._chats:
            ctk.CTkRadioButton(
                self, text=f"{name}  ({chat_id})", variable=self._selected, value=chat_id,
                text_color=tm.c("text"), font=ctk.CTkFont(size=11),
            ).pack(anchor=lm.text_anchor, padx=24, pady=3)
        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(12, 16))
        ok = self._button(buttons, lm.t("nt_ui_use_chat"), self._accept, primary=True)
        ok.pack(side="right")
        self._button(buttons, lm.t("nt_ui_cancel"), self.destroy).pack(side="right", padx=(0, 8))
        self.after(100, self._take_focus, ok)

    def _accept(self) -> None:
        chosen = self._selected.get()
        self.choice = next((chat for chat in self._chats if chat[0] == chosen), None)
        self.destroy()

    @classmethod
    def ask(cls, master, chats: Sequence[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
        dialog = cls(master, chats)
        master.wait_window(dialog)
        return dialog.choice
