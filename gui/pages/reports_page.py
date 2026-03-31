"""
ReportsPage — lists previously generated PDF reports and allows re-generation.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Callable, List

import customtkinter as ctk

from gui.theme_manager    import ThemeManager
from core.language_manager import LanguageManager


class ReportsPage(ctk.CTkFrame):
    """Shows previously generated PDFs in reports/output/."""

    def __init__(self, master, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr,
            text="  📊  Reports",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"),
            fg_color="transparent",
            anchor="w",
        ).pack(side="left", padx=16, fill="y")

        refresh_btn = ctk.CTkButton(
            hdr,
            text="⟳  Refresh",
            width=100,
            height=28,
            corner_radius=6,
            fg_color=tm.c("card"),
            hover_color=tm.c("hover"),
            text_color=tm.c("text2"),
            font=ctk.CTkFont(size=11),
            command=self._load_reports,
        )
        refresh_btn.pack(side="right", padx=16, pady=11)

        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color=tm.c("bg"), corner_radius=0
        )
        self._scroll.pack(fill="both", expand=True, padx=16, pady=12)

        self._load_reports()

    def _load_reports(self) -> None:
        for w in self._scroll.winfo_children():
            w.destroy()

        output_dir = self._reports_dir()
        if not os.path.isdir(output_dir):
            self._empty_state("No reports generated yet.")
            return

        pdfs = sorted(
            [f for f in os.listdir(output_dir) if f.endswith(".pdf")],
            reverse=True,
        )
        if not pdfs:
            self._empty_state("No PDF reports found.")
            return

        for pdf in pdfs:
            self._report_row(os.path.join(output_dir, pdf), pdf)

    def _report_row(self, full_path: str, filename: str) -> None:
        tm = ThemeManager()
        row = ctk.CTkFrame(
            self._scroll,
            fg_color=tm.c("card"),
            corner_radius=8,
            border_width=1,
            border_color=tm.c("border"),
        )
        row.pack(fill="x", pady=4)

        ctk.CTkLabel(
            row,
            text="📄",
            font=ctk.CTkFont(size=18),
            text_color=tm.c("accent"),
            fg_color="transparent",
        ).pack(side="left", padx=(12, 8), pady=8)

        ctk.CTkLabel(
            row,
            text=filename,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=tm.c("text"),
            fg_color="transparent",
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        size_kb = os.path.getsize(full_path) // 1024
        ctk.CTkLabel(
            row,
            text=f"{size_kb} KB",
            font=ctk.CTkFont(size=10),
            text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            row,
            text="Open",
            width=64,
            height=26,
            corner_radius=4,
            fg_color=tm.c("accent"),
            hover_color=tm.c("accent_h"),
            text_color="#ffffff",
            font=ctk.CTkFont(size=10),
            command=lambda p=full_path: self._open_pdf(p),
        ).pack(side="left", padx=(0, 8), pady=8)

    def _empty_state(self, msg: str) -> None:
        tm = ThemeManager()
        ctk.CTkLabel(
            self._scroll,
            text=msg,
            font=ctk.CTkFont(size=14),
            text_color=ThemeManager().c("text3"),
            fg_color="transparent",
        ).pack(pady=60)

    @staticmethod
    def _open_pdf(path: str) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path)
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    @staticmethod
    def _reports_dir() -> str:
        if getattr(sys, "frozen", False):
            return os.path.join(os.path.dirname(sys.executable), "reports", "output")
        from pathlib import Path
        return str(Path(__file__).parent.parent.parent / "reports" / "output")

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg"))
        self._load_reports()
