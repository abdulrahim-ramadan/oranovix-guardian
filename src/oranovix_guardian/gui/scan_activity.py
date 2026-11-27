"""Shared scan status, progress and action controls."""
from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.theme_manager import ThemeManager


class ScanActivity(ctk.CTkFrame):
    def __init__(self, master, before) -> None:
        lm = LanguageManager()
        super().__init__(master, fg_color=ThemeManager().c("bg2"), corner_radius=0)
        self._before = before
        self._action_side = lm.opposite_side
        self._stage = ""
        self._fraction = -1.0
        self._action = ctk.CTkButton(self, width=130, height=28, text="")
        self._action.pack(side=self._action_side, padx=12, pady=5)
        self._meter = ctk.CTkProgressBar(self, width=115, height=5)
        self._label = ctk.CTkLabel(self, text="", anchor=lm.text_anchor)
        self._label.pack(side=lm.pack_side, padx=12, fill="x", expand=True)

    def show_progress(self, cancel: Callable[[], None]) -> None:
        self._stage = ""
        self._fraction = -1.0
        self.update_progress("discovery", 0)
        self._action.configure(text=LanguageManager().t("scan_cancel"), state="normal", command=cancel)
        self._meter.pack(side=self._action_side, padx=6)
        self._show()

    def update_progress(self, stage: str, fraction: float) -> None:
        if stage != self._stage:
            self._stage = stage
            self._label.configure(text=LanguageManager().t(f"scan_stage_{stage}"))
        if fraction != self._fraction:
            self._fraction = fraction
            self._meter.set(fraction)

    def show_cancelling(self) -> None:
        self._action.configure(state="disabled")
        self._label.configure(text=LanguageManager().t("scan_cancelling"))

    def show_ready(self, warning_count: int, view: Callable[[], None]) -> None:
        lm = LanguageManager()
        self._meter.pack_forget()
        text = lm.t("scan_partial_details", count=warning_count) if warning_count else lm.t("scan_ready")
        self._label.configure(text=text)
        self._action.configure(text=lm.t("scan_view_results"), state="normal", command=view)
        self._show()

    def _show(self) -> None:
        self.pack(side="bottom", fill="x", before=self._before)
