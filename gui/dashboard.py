"""
Scan history dashboard — secondary window, RTL-aware.
"""
from __future__ import annotations

from typing import List

import customtkinter as ctk

from core.language_manager import LanguageManager
from scanner_engine.base import ScanResult
from .app import Theme, StatCard


class DashboardWindow(ctk.CTkToplevel):
    """Aggregate statistics across multiple scan runs."""

    def __init__(self, master, history: List[ScanResult]) -> None:
        super().__init__(master)
        lm = LanguageManager()
        self.title(f"{lm.t('app_title')} — {lm.t('scan_history')}")
        self.geometry("800x500")
        self.configure(fg_color=Theme.BG_DARK.value)
        self._history = history
        self._build_ui()

    def _build_ui(self) -> None:
        lm     = LanguageManager()
        anchor = lm.text_anchor

        ctk.CTkLabel(
            self,
            text=lm.t("scan_history"),
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=Theme.TEXT.value,
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            self,
            text=f"{len(self._history)} scan(s)",
            font=ctk.CTkFont(size=11),
            text_color=Theme.TEXT_MID.value,
        ).pack(pady=(0, 12))

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=16)

        total_issues = sum(r.total_issues for r in self._history)
        total_files  = sum(r.files_scanned for r in self._history)

        StatCard(cards, lm.t("scan_history"),   str(len(self._history))).pack(side="left", fill="both", expand=True, padx=4)
        StatCard(cards, lm.t("total_issues"),   str(total_issues), Theme.DANGER.value).pack(side="left", fill="both", expand=True, padx=4)
        StatCard(cards, lm.t("files_scanned"),  str(total_files)).pack(side="left", fill="both", expand=True, padx=4)

        scroll = ctk.CTkScrollableFrame(self, fg_color=Theme.BG_MID.value, corner_radius=12)
        scroll.pack(fill="both", expand=True, padx=16, pady=12)

        for r in self._history:
            row = ctk.CTkFrame(scroll, fg_color=Theme.BG_CARD.value, corner_radius=8)
            row.pack(fill="x", padx=4, pady=3)

            ctk.CTkLabel(
                row,
                text=r.target_path,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=Theme.TEXT.value,
                anchor=anchor,
            ).pack(side=lm.pack_side, padx=10, pady=6)

            ctk.CTkLabel(
                row,
                text=f"{r.total_issues} issues  •  {r.risk_label}  •  {r.duration_seconds:.1f}s",
                font=ctk.CTkFont(size=10),
                text_color=Theme.TEXT_MID.value,
            ).pack(side=lm.opposite_side, padx=10)
