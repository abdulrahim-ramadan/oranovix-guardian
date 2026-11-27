"""
Dialogs of the Threat Feed and My Projects pages.
"""
from __future__ import annotations

import os
import webbrowser
from tkinter import filedialog
from typing import Callable, Optional, Sequence, Tuple

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.confirm_dialog import ConfirmDialog
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.threat_intel.sanitize import SafeUrl


class FeedConsentDialog(ctk.CTkToplevel):
    """First-run question: may the feed be downloaded, and from which hosts?

    ``choice`` is ``True`` (switch on), ``False`` (keep off) or ``None``
    when the window was closed. Off is the default answer.
    """

    def __init__(self, master, hosts: Sequence[str]) -> None:
        super().__init__(master)
        tm = ThemeManager()
        lm = LanguageManager()
        self.choice: Optional[bool] = None

        self.title(lm.t("tf_consent_title"))
        # No fixed size: the window is as high as its text and buttons.
        self.resizable(False, False)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())

        ctk.CTkLabel(
            self, text=lm.t("tf_consent_title"), font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(18, 6))
        ctk.CTkLabel(
            self, text=self.consent_text(hosts), font=ctk.CTkFont(size=11),
            text_color=tm.c("text2"), fg_color="transparent", wraplength=460,
            anchor=lm.text_anchor, justify=lm.text_justify,
        ).pack(fill="x", padx=20, pady=(0, 14))

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(0, 16))
        # Keeping it off is the default: it has the focus and answers Enter.
        off_btn = ctk.CTkButton(
            buttons, text=lm.t("tf_consent_no"), width=140, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"), text_color="#ffffff",
            font=ctk.CTkFont(size=11), command=lambda: self._answer(False),
        )
        off_btn.pack(side="right")
        ctk.CTkButton(
            buttons, text=lm.t("tf_consent_yes"), width=140, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"), text_color=tm.c("text"),
            border_width=1, border_color=tm.c("accent"),
            font=ctk.CTkFont(size=11), command=lambda: self._answer(True),
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _e: self._answer(False))
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(100, self._take_focus, off_btn)

    @staticmethod
    def consent_text(hosts: Sequence[str]) -> str:
        """The question with every host that will be contacted, one per line."""
        listed = "\n".join(f"  • {host}" for host in hosts)
        return LanguageManager().t("tf_consent_text", hosts=listed)

    def _take_focus(self, button: ctk.CTkButton) -> None:
        try:
            self.lift()
            self.grab_set()
            button.focus_set()
        except Exception:
            pass    # window already closed

    def _answer(self, enable: bool) -> None:
        self.choice = enable
        self.destroy()

    @classmethod
    def ask(cls, master, hosts: Sequence[str]) -> Optional[bool]:
        dialog = cls(master, hosts)
        master.wait_window(dialog)
        return dialog.choice


class LinkOpener:
    """Opens a feed link in the browser after showing where it leads."""

    @staticmethod
    def question(url: str) -> Tuple[str, str]:
        """Title and text of the confirmation; the text names the domain."""
        lm = LanguageManager()
        return lm.t("tf_open_title"), lm.t("tf_open_text", host=SafeUrl.host(url))

    @classmethod
    def open(cls, master, url: str, browser: Callable[[str], object] = webbrowser.open) -> bool:
        if not SafeUrl.clean(url):
            return False
        lm = LanguageManager()
        title, text = cls.question(url)
        if not ConfirmDialog.ask(master, title, text, lm.t("tf_open_yes"), lm.t("tf_open_no")):
            return False
        browser(url)
        return True


class ProjectDialog(ctk.CTkToplevel):
    """Name, folder and optional site address of a new project.

    ``result`` is ``(name, folder, site_url)`` or ``None`` when cancelled.
    *validate* is called with the three values and returns an error text,
    or ``""`` when the project was added.
    """

    def __init__(self, master, validate: Callable[[str, str, str], str]) -> None:
        super().__init__(master)
        tm = ThemeManager()
        lm = LanguageManager()
        self._validate = validate
        self.result: Optional[Tuple[str, str, str]] = None

        self.title(lm.t("proj_dialog_title"))
        self.geometry("520x390")
        self.resizable(False, False)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())

        ctk.CTkLabel(
            self, text=lm.t("proj_dialog_title"), font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(16, 8))

        self._name = self._field(lm.t("proj_name"))
        self._folder = self._field(lm.t("proj_folder"), browse=True)
        self._site = self._field(lm.t("proj_site_url"), placeholder="https://")
        ctk.CTkLabel(
            self, text=f"⚠  {lm.t('proj_site_notice')}", font=ctk.CTkFont(size=10, weight="bold"),
            text_color=tm.c("warning"), fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(0, 4))

        self._error = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=10), text_color=tm.c("error"),
            fg_color="transparent", anchor=lm.text_anchor, wraplength=480, justify=lm.text_justify,
        )
        self._error.pack(fill="x", padx=20)

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(0, 16), side="bottom")
        save = ctk.CTkButton(
            buttons, text=lm.t("proj_save"), width=120, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"), text_color="#ffffff",
            command=self._save,
        )
        save.pack(side="right")
        ctk.CTkButton(
            buttons, text=lm.t("proj_cancel"), width=120, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"), text_color=tm.c("text2"),
            command=self.destroy,
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _e: self._save())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(100, self._take_focus)

    def _field(self, label: str, browse: bool = False, placeholder: str = "") -> ctk.CTkEntry:
        tm = ThemeManager()
        lm = LanguageManager()
        ctk.CTkLabel(
            self, text=label, font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
            fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 8))
        entry = ctk.CTkEntry(
            row, height=28, fg_color=tm.c("input_bg"), border_color=tm.c("border"),
            text_color=tm.c("text"), placeholder_text=placeholder,
        )
        if browse:
            ctk.CTkButton(
                row, text=lm.t("proj_choose"), width=90, height=28, corner_radius=6,
                fg_color=tm.c("bg3"), hover_color=tm.c("hover"), text_color=tm.c("text2"),
                font=ctk.CTkFont(size=10), command=self._browse,
            ).pack(side="right", padx=(8, 0))
        entry.pack(side="left", fill="x", expand=True)
        return entry

    def _browse(self) -> None:
        folder = filedialog.askdirectory(parent=self, title=LanguageManager().t("proj_folder"))
        if not folder:
            return
        self._folder.delete(0, "end")
        self._folder.insert(0, os.path.normpath(folder))
        if not self._name.get().strip():
            self._name.insert(0, os.path.basename(os.path.normpath(folder)))

    def _save(self) -> None:
        values = (self._name.get().strip(), self._folder.get().strip(), self._site.get().strip())
        error = self._validate(*values)
        if error:
            self._error.configure(text=error)
            return
        self.result = values
        self.destroy()

    def _take_focus(self) -> None:
        try:
            self.lift()
            self.grab_set()
            self._name.focus_set()
        except Exception:
            pass

    @classmethod
    def ask(cls, master, validate: Callable[[str, str, str], str]) -> Optional[Tuple[str, str, str]]:
        dialog = cls(master, validate)
        master.wait_window(dialog)
        return dialog.result


class RiskDialog(ctk.CTkToplevel):
    """Asks for the reason why the risk of an item is accepted.

    ``reason`` is the text, or ``None`` when cancelled. An empty reason
    is not taken: the note is what the next person will read.
    """

    MAX_REASON = 200

    def __init__(self, master, item_title: str, projects: Sequence[str]) -> None:
        super().__init__(master)
        tm = ThemeManager()
        lm = LanguageManager()
        self.reason: Optional[str] = None

        self.title(lm.t("tf_risk_title"))
        self.resizable(False, False)
        self.configure(fg_color=tm.c("bg"))
        self.transient(master.winfo_toplevel())

        ctk.CTkLabel(
            self, text=lm.t("tf_risk_title"), font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20, pady=(16, 6))
        ctk.CTkLabel(
            self, text=self.question(item_title, projects), font=ctk.CTkFont(size=11),
            text_color=tm.c("text2"), fg_color="transparent", wraplength=460,
            anchor=lm.text_anchor, justify=lm.text_justify,
        ).pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkLabel(
            self, text=lm.t("tf_risk_reason"), font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
            fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=20)
        self._entry = ctk.CTkEntry(
            self, height=28, width=460, fg_color=tm.c("input_bg"), border_color=tm.c("border"),
            text_color=tm.c("text"),
        )
        self._entry.pack(fill="x", padx=20, pady=(0, 4))
        self._error = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=10), text_color=tm.c("error"),
            fg_color="transparent", anchor=lm.text_anchor,
        )
        self._error.pack(fill="x", padx=20)

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(4, 16))
        ctk.CTkButton(
            buttons, text=lm.t("tf_risk_cancel"), width=120, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"), text_color="#ffffff",
            font=ctk.CTkFont(size=11), command=self.destroy,
        ).pack(side="right")
        ctk.CTkButton(
            buttons, text=lm.t("tf_accept_risk"), width=120, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"), text_color=tm.c("text"),
            border_width=1, border_color=tm.c("accent"),
            font=ctk.CTkFont(size=11), command=self._save,
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda _e: self._save())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.after(100, self._take_focus)

    @staticmethod
    def question(item_title: str, projects: Sequence[str]) -> str:
        """What is accepted and for which projects."""
        return LanguageManager().t("tf_risk_text", item=item_title, projects=", ".join(projects))

    @classmethod
    def valid_reason(cls, text: str) -> str:
        """The reason as it will be stored; ``""`` when there is none."""
        return " ".join(text.split())[: cls.MAX_REASON]

    def _save(self) -> None:
        reason = self.valid_reason(self._entry.get())
        if not reason:
            self._error.configure(text=LanguageManager().t("tf_risk_reason_missing"))
            return
        self.reason = reason
        self.destroy()

    def _take_focus(self) -> None:
        try:
            self.lift()
            self.grab_set()
            self._entry.focus_set()
        except Exception:
            pass    # window already closed

    @classmethod
    def ask(cls, master, item_title: str, projects: Sequence[str]) -> Optional[str]:
        dialog = cls(master, item_title, projects)
        master.wait_window(dialog)
        return dialog.reason
