"""
Results and dashboard page for the Oranovix Guardian graphical interface.

This module implements the P3 dashboard redesign of the results view.  It is
a self-contained CustomTkinter page that combines a persistent scan-history
dashboard (upper half) with a per-scan detail view (lower half).

Layout (top to bottom):
  - Header bar: page title, Quick Scan shortcut, Export PDF button.
  - Stat Cards row (4 cards): Total Scans / Average Score / Total Issues /
    Files Scanned — aggregated from ``ScanHistory``.
  - Charts row: ``_TrendChart`` (line chart of last ≤10 risk scores) and
    ``_PieChart`` (donut chart of current-scan severity breakdown).
  - Recent Scans table: last 5 scan records from history.
  - Horizontal divider.
  - Score circle + four ``SeverityCard`` widgets (current scan counts).
  - Filter row + expandable ``IssueAccordion`` list (current scan issues).

Key classes:
  - ``_ScrollCanvas``   — custom Canvas/Scrollbar container that avoids
                          Python 3.13 compatibility issues in CTkScrollableFrame.
  - ``ScoreCircle``     — animated arc widget displaying the numeric risk score.
  - ``SeverityCard``    — compact card showing an animated severity count.
  - ``_StatCard``       — larger dashboard stat card with icon and animated value.
  - ``_TrendChart``     — Canvas line chart of historical risk scores.
  - ``_PieChart``       — Canvas donut chart for the severity breakdown.
  - ``_RecentTable``    — table widget showing the last 5 scan records.
  - ``IssueAccordion``  — expandable row with full vulnerability education panel.
  - ``ResultsPage``     — the top-level page frame that orchestrates all widgets.

P1 fix note: ``_refresh_stats`` count_up calls now use
``lambda v, l=lbl: l.configure(text=v)`` to capture the label reference
correctly inside the loop closure.

Version: 1.1.0
"""
from __future__ import annotations

import math
import os
import tkinter as tk
from tkinter import filedialog
from typing import Callable, List, Optional

import customtkinter as ctk

from gui.theme_manager     import ThemeManager
from gui.animation_manager import AnimationManager
from core.language_manager import LanguageManager
from core.scan_history     import ScanHistory
from core.alarm_center     import AlarmCenter
from scanner_engine.base   import ScanResult, Severity, Issue


# ── Canvas-based scrollable container ────────────────────────────────────

class _ScrollCanvas(ctk.CTkFrame):
    """Vertically scrollable container implemented with a raw Tk Canvas.

    This is a drop-in replacement for ``CTkScrollableFrame`` that avoids a
    compatibility bug present in Python 3.13 where the scrollable frame raises
    an error during widget destruction.  The inner content frame (``self.inner``)
    should be used as the parent for all child widgets.

    The mousewheel is bound only while the cursor is inside the canvas area,
    preventing accidental scroll-jacking of other widgets.

    Args:
        master:    Parent widget.
        bg_color:  Background colour hex string applied to both the canvas and
                   the inner frame so they blend with the surrounding layout.
    """

    def __init__(self, master, bg_color: str, **kwargs) -> None:
        super().__init__(master, fg_color=bg_color, corner_radius=0, **kwargs)
        tm = ThemeManager()
        self._canvas = tk.Canvas(self, bg=bg_color, highlightthickness=0)
        self._sb = ctk.CTkScrollbar(
            self, command=self._canvas.yview,
            fg_color=bg_color,
            button_color=tm.c("border"),
            button_hover_color=tm.c("accent"),
        )
        # The inner frame is placed inside the canvas as a window item.
        self.inner = ctk.CTkFrame(self._canvas, fg_color=bg_color, corner_radius=0)
        self._win_id = self._canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self._canvas.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        # Update the scroll region whenever the inner frame resizes.
        self.inner.bind("<Configure>", self._on_inner_configure)
        # Resize the inner window item width to match the canvas when it resizes.
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        # Bind and unbind mousewheel scrolling based on cursor position.
        self._canvas.bind("<Enter>",  self._bind_mousewheel)
        self._canvas.bind("<Leave>",  self._unbind_mousewheel)

    def _on_inner_configure(self, _=None) -> None:
        """Recalculate the canvas scroll region when the inner frame changes size."""
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        """Stretch the inner window item to fill the full canvas width on resize."""
        self._canvas.itemconfig(self._win_id, width=event.width)

    def _on_mousewheel(self, event) -> None:
        """Scroll the canvas vertically in response to a mouse-wheel event.

        The ``event.delta`` value is divided by 120 because on Windows each
        notch of the wheel generates a delta of ±120.
        """
        try:
            self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass

    def _bind_mousewheel(self, _=None) -> None:
        """Bind the ``<MouseWheel>`` event on the top-level window while hovering."""
        self._canvas.winfo_toplevel().bind("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, _=None) -> None:
        """Unbind the ``<MouseWheel>`` event when the cursor leaves the canvas."""
        try:
            self._canvas.winfo_toplevel().unbind("<MouseWheel>")
        except Exception:
            pass


# ── Score Circle ──────────────────────────────────────────────────────────

class ScoreCircle(ctk.CTkFrame):
    """Animated circular arc widget that displays a numeric risk score.

    Renders a fixed-size canvas with two concentric arcs: a static background
    ring and a foreground arc that animates from 0° to the score-proportional
    extent (clockwise from 12 o'clock).  The arc and score text are colour-coded
    by risk level.

    Class attributes:
        SIZE: Diameter in pixels of both the frame and the canvas.
    """

    SIZE = 180

    def __init__(self, master, **kwargs) -> None:
        """Create the score circle frame and draw its initial (empty) state.

        Args:
            master: Parent widget.
        """
        super().__init__(master, fg_color="transparent",
                         width=self.SIZE, height=self.SIZE, **kwargs)
        self.pack_propagate(False)
        self._build()

    def _build(self) -> None:
        """Create the canvas and draw the background ring, foreground arc, and labels."""
        tm = ThemeManager()
        self._cv = tk.Canvas(self, width=self.SIZE, height=self.SIZE,
                              bg=tm.c("bg2"), highlightthickness=0)
        self._cv.pack()
        r, pad = self.SIZE, 18
        # Static grey background ring drawn beneath the coloured arc.
        self._bg_ring = self._cv.create_oval(
            pad, pad, r - pad, r - pad, outline=tm.c("border"), width=14)
        # Foreground arc starts with zero extent; animated by animate_to().
        self._arc = self._cv.create_arc(
            pad, pad, r - pad, r - pad,
            start=90, extent=0, outline=tm.c("success"), width=14, style="arc")
        # Numeric score text centred inside the ring.
        self._score_id = self._cv.create_text(
            r // 2, r // 2 - 10, text="—",
            font=("Segoe UI", 32, "bold"), fill=tm.c("text"))
        # "Risk Score" sub-label beneath the number.
        self._label_id = self._cv.create_text(
            r // 2, r // 2 + 22, text="Risk Score",
            font=("Segoe UI", 10), fill=tm.c("text2"))

    def animate_to(self, score: int) -> None:
        """Animate the arc and score text to the given risk score over 900 ms.

        The arc colour follows the same threshold logic as the overall risk label:
        error (red) for score ≥ 80, warning (orange) for score ≥ 50, and
        success (green) for a score of 0.

        Args:
            score: Integer risk score in the range 0–100.
        """
        tm = ThemeManager()
        # Select arc colour based on risk thresholds.
        color = (tm.c("error")   if score >= 80 else
                 tm.c("warning") if score >= 50 else
                 tm.c("warning") if score >   0 else tm.c("success"))
        self._cv.itemconfig(self._arc,      outline=color)
        self._cv.itemconfig(self._score_id, fill=color)
        # Animate the arc sweep and numeric count simultaneously.
        AnimationManager.animate_arc(self._cv, self._cv, self._arc, score, 900)
        AnimationManager.count_up(
            self._cv,
            lambda v: self._cv.itemconfig(self._score_id, text=v),
            score, duration_ms=900,
        )

    def reset(self) -> None:
        """Reset the arc to zero extent and restore the placeholder dash text."""
        tm = ThemeManager()
        self._cv.itemconfig(self._arc, extent=0, outline=tm.c("success"))
        self._cv.itemconfig(self._score_id, text="—", fill=tm.c("text"))

    def refresh_theme(self) -> None:
        """Reapply the current theme colours to all canvas items.

        Called by the parent page when the user switches between light and dark
        themes at runtime.
        """
        tm = ThemeManager()
        self._cv.configure(bg=tm.c("bg2"))
        self._cv.itemconfig(self._bg_ring, outline=tm.c("border"))
        self._cv.itemconfig(self._score_id, fill=tm.c("text"))
        self._cv.itemconfig(self._label_id, fill=tm.c("text2"))


# ── Severity Card ─────────────────────────────────────────────────────────

class SeverityCard(ctk.CTkFrame):
    _SEV_COLORS = {"CRITICAL": "critical", "HIGH": "high",
                   "MEDIUM": "medium", "LOW": "low"}

    def __init__(self, master, severity_key: str, count: int = 0, **kwargs) -> None:
        tm = ThemeManager()
        color = tm.c(self._SEV_COLORS.get(severity_key, "text2"))
        super().__init__(master, fg_color=tm.c("card"), corner_radius=10,
                         border_width=1, border_color=color, **kwargs)
        self._sev_key   = severity_key
        self._count_var = tk.StringVar(value="0")
        ctk.CTkFrame(self, height=4, fg_color=color, corner_radius=0).pack(fill="x")
        ctk.CTkLabel(self, textvariable=self._count_var,
                     font=ctk.CTkFont(family="Segoe UI", size=30, weight="bold"),
                     text_color=color, fg_color="transparent").pack(pady=(10, 2))
        ctk.CTkLabel(self, text=severity_key,
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=ThemeManager().c("text2"),
                     fg_color="transparent").pack(pady=(0, 10))
        self._animate_count(count)

    def _animate_count(self, target: int) -> None:
        AnimationManager.count_up(self, self._count_var.set, target, 700)

    def update_count(self, count: int) -> None:
        self._animate_count(count)


# ── Stat Card (P3) ────────────────────────────────────────────────────────

class _StatCard(ctk.CTkFrame):
    """Large stat card: icon + animated number + label."""

    def __init__(self, master, icon: str, label: str,
                 value=0, suffix: str = "", **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("card"), corner_radius=12,
                         border_width=1, border_color=tm.c("border"),
                         width=140, height=100, **kwargs)
        self.pack_propagate(False)
        self._suffix    = suffix
        self._value_var = tk.StringVar(value="—")

        ctk.CTkLabel(self, text=icon,
                     font=ctk.CTkFont(size=22), fg_color="transparent",
                     text_color=tm.c("accent")).pack(pady=(10, 0))

        ctk.CTkLabel(self, textvariable=self._value_var,
                     font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
                     fg_color="transparent",
                     text_color=tm.c("text")).pack(pady=(0, 1))

        ctk.CTkLabel(self, text=label,
                     font=ctk.CTkFont(size=9),
                     fg_color="transparent",
                     text_color=tm.c("text3")).pack(pady=(0, 10))

        self.set_value(value)

    def set_value(self, value, animate: bool = True) -> None:
        if isinstance(value, int) and value > 0 and animate:
            AnimationManager.count_up(
                self,
                lambda v, s=self._suffix: self._value_var.set(f"{v}{s}"),
                value, duration_ms=700,
            )
        elif value == 0 or value == "—":
            self._value_var.set("—")
        else:
            self._value_var.set(f"{value}{self._suffix}")


# ── Score Trend Chart (P3) ────────────────────────────────────────────────

class _TrendChart(ctk.CTkFrame):
    """Canvas line chart — risk scores for the last ≤10 scans."""

    def __init__(self, master, scores: list, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("card"), corner_radius=10,
                         border_width=1, border_color=tm.c("border"), **kwargs)
        self._scores = scores
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        ctk.CTkLabel(self, text="📈  Score Trend",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=tm.c("text2"), fg_color="transparent",
                     anchor="w").pack(anchor="w", padx=12, pady=(8, 4))
        self._cv = tk.Canvas(self, height=130, bg=tm.c("card"),
                              highlightthickness=0)
        self._cv.pack(fill="x", padx=8, pady=(0, 8))
        self._cv.bind("<Configure>", lambda _: self._render())
        self.after(50, self._render)

    def _render(self) -> None:
        self._cv.delete("all")
        tm = ThemeManager()
        try:
            w = self._cv.winfo_width() or 300
            h = self._cv.winfo_height() or 130
        except Exception:
            return

        if not self._scores:
            self._cv.create_text(w // 2, h // 2, text="No scan history yet",
                                  fill=tm.c("text3"), font=("Segoe UI", 10))
            return

        pad_l, pad_r, pad_t, pad_b = 32, 10, 10, 24
        cw = w - pad_l - pad_r
        ch = h - pad_t - pad_b

        # Grid lines & Y-axis labels
        for score in (0, 25, 50, 75, 100):
            y = pad_t + ch - (score / 100) * ch
            self._cv.create_line(pad_l, y, w - pad_r, y,
                                  fill=tm.c("border"), width=1, dash=(3, 4))
            self._cv.create_text(pad_l - 4, y, text=str(score), anchor="e",
                                  fill=tm.c("text3"), font=("Segoe UI", 7))

        # Data points
        n = len(self._scores)
        pts = []
        for i, s in enumerate(self._scores):
            x = pad_l + (i / max(n - 1, 1)) * cw if n > 1 else pad_l + cw // 2
            y = pad_t + ch - (s / 100) * ch
            pts.append((x, y))

        # Connecting lines
        for i in range(len(pts) - 1):
            self._cv.create_line(pts[i][0], pts[i][1],
                                  pts[i + 1][0], pts[i + 1][1],
                                  fill=tm.c("accent"), width=2, smooth=True)

        # Dots
        for i, (x, y) in enumerate(pts):
            s     = self._scores[i]
            color = (tm.c("error")   if s >= 80 else
                     tm.c("warning") if s >= 50 else tm.c("success"))
            self._cv.create_oval(x - 4, y - 4, x + 4, y + 4,
                                  fill=color, outline="")
            # X label
            self._cv.create_text(x, h - pad_b + 8, text=str(i + 1),
                                  fill=tm.c("text3"), font=("Segoe UI", 7))

    def update_scores(self, scores: list) -> None:
        self._scores = scores
        self._render()


# ── Issue Pie Chart (P3) ──────────────────────────────────────────────────

class _PieChart(ctk.CTkFrame):
    """Canvas donut chart — CRITICAL / HIGH / MEDIUM / LOW breakdown."""

    _LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    _KEYS   = ["critical", "high", "medium", "low"]

    def __init__(self, master, critical=0, high=0, medium=0, low=0, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("card"), corner_radius=10,
                         border_width=1, border_color=tm.c("border"), **kwargs)
        self._counts = [critical, high, medium, low]
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        ctk.CTkLabel(self, text="🥧  Issue Breakdown",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=tm.c("text2"), fg_color="transparent",
                     anchor="w").pack(anchor="w", padx=12, pady=(8, 4))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(0, 8))

        self._cv = tk.Canvas(row, height=110, width=120, bg=tm.c("card"),
                              highlightthickness=0)
        self._cv.pack(side="left")

        # Legend
        leg = ctk.CTkFrame(row, fg_color="transparent")
        leg.pack(side="left", padx=(8, 0), anchor="center")
        self._leg_lbls = []
        for label, key in zip(self._LABELS, self._KEYS):
            fr = ctk.CTkFrame(leg, fg_color="transparent")
            fr.pack(anchor="w", pady=2)
            ctk.CTkFrame(fr, width=10, height=10, fg_color=tm.c(key),
                         corner_radius=2).pack(side="left", padx=(0, 4))
            lbl = ctk.CTkLabel(fr, text=f"{label}: 0",
                                font=ctk.CTkFont(size=9), fg_color="transparent",
                                text_color=tm.c("text3"))
            lbl.pack(side="left")
            self._leg_lbls.append(lbl)

        self._cv.bind("<Configure>", lambda _: self._render())
        self.after(50, self._render)

    def _render(self) -> None:
        self._cv.delete("all")
        tm = ThemeManager()
        try:
            w = self._cv.winfo_width() or 120
            h = self._cv.winfo_height() or 110
        except Exception:
            return

        total = sum(self._counts)
        cx, cy = w // 2, h // 2 - 4
        r      = min(w, h) // 2 - 8

        if total == 0:
            self._cv.create_oval(cx - r, cy - r, cx + r, cy + r,
                                  fill=tm.c("border"), outline="")
            self._cv.create_text(cx, cy, text="No data",
                                  fill=tm.c("text3"), font=("Segoe UI", 8))
            return

        start = 90
        for count, key in zip(self._counts, self._KEYS):
            if count == 0:
                continue
            extent = 360 * (count / total)
            self._cv.create_arc(cx - r, cy - r, cx + r, cy + r,
                                  start=start, extent=-extent,
                                  fill=tm.c(key), outline=tm.c("card"))
            start -= extent

        # Donut hole
        inner = int(r * 0.52)
        self._cv.create_oval(cx - inner, cy - inner, cx + inner, cy + inner,
                              fill=tm.c("card"), outline="")
        self._cv.create_text(cx, cy, text=str(total),
                              fill=tm.c("text"), font=("Segoe UI", 10, "bold"))

    def update_counts(self, critical=0, high=0, medium=0, low=0) -> None:
        self._counts = [critical, high, medium, low]
        tm = ThemeManager()
        for i, (label, key, count) in enumerate(
                zip(self._LABELS, self._KEYS, self._counts)):
            self._leg_lbls[i].configure(
                text=f"{label}: {count}",
                text_color=tm.c("text2") if count > 0 else tm.c("text3"),
            )
        self._render()


# ── Recent Scans Table (P3) ───────────────────────────────────────────────

class _RecentTable(ctk.CTkFrame):
    """Shows the last 5 scans in a simple table."""

    _COLS = [("Date", 100), ("Target", 180), ("Files", 55),
             ("Issues", 60), ("Score", 75)]

    def __init__(self, master, records: list, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("card"), corner_radius=10,
                         border_width=1, border_color=tm.c("border"), **kwargs)
        self._records = records
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        ctk.CTkLabel(self, text="🕐  Recent Scans",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=tm.c("text2"), fg_color="transparent",
                     anchor="w").pack(anchor="w", padx=12, pady=(8, 4))
        ctk.CTkFrame(self, height=1, fg_color=tm.c("border"),
                     corner_radius=0).pack(fill="x")

        # Header row
        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg3"), corner_radius=0)
        hdr.pack(fill="x")
        for col, w in self._COLS:
            ctk.CTkLabel(hdr, text=col, width=w,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("text3"), fg_color="transparent",
                         anchor="w").pack(side="left", padx=(8, 0), pady=4)

        if not self._records:
            ctk.CTkLabel(self, text="No scans yet",
                         font=ctk.CTkFont(size=11),
                         text_color=tm.c("text3"),
                         fg_color="transparent").pack(pady=14)
            return

        for i, rec in enumerate(self._records):
            row = ctk.CTkFrame(
                self,
                fg_color=tm.c("card") if i % 2 == 0 else tm.c("bg2"),
                corner_radius=0,
            )
            row.pack(fill="x")
            score = rec.get("score", 0)
            sc = (tm.c("error")   if score >= 80 else
                  tm.c("warning") if score >= 50 else tm.c("success"))
            cells = [
                (rec.get("date",   "—")[:10],  100, tm.c("text2")),
                (rec.get("target", "—")[:22],  180, tm.c("text")),
                (str(rec.get("files",  0)),      55, tm.c("text2")),
                (str(rec.get("issues", 0)),      60,
                 tm.c("warning") if rec.get("issues", 0) else tm.c("success")),
                (f"{score}/100",                75, sc),
            ]
            for val, w, color in cells:
                ctk.CTkLabel(row, text=val, width=w,
                             font=ctk.CTkFont(size=9),
                             text_color=color, fg_color="transparent",
                             anchor="w").pack(side="left", padx=(8, 0), pady=3)


# ── Expandable Issue Row ──────────────────────────────────────────────────

class IssueAccordion(ctk.CTkFrame):
    """Expandable row with full vulnerability education panel."""

    def __init__(self, master, issue: Issue, idx: int, **kwargs) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        bg = tm.c("card") if idx % 2 == 0 else tm.c("bg2")
        super().__init__(master, fg_color=bg, corner_radius=6, **kwargs)

        sev_colors = {"CRITICAL": tm.c("critical"), "HIGH": tm.c("high"),
                      "MEDIUM": tm.c("medium"), "LOW": tm.c("low")}
        color = sev_colors.get(issue.severity.value, tm.c("text2"))
        self._expanded = False

        # Header row
        hdr = ctk.CTkFrame(self, fg_color="transparent", cursor="hand2")
        hdr.pack(fill="x", padx=8, pady=6)

        ctk.CTkLabel(hdr,
                     text=f" {lm.t(issue.severity.value.lower())} ",
                     fg_color=color, corner_radius=4,
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color="#ffffff").pack(side="left", padx=(0, 8))

        if issue.needs_review:
            ctk.CTkLabel(hdr,
                         text=f" {lm.t('needs_review')} ",
                         fg_color=tm.c("warning"), corner_radius=4,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color="#ffffff").pack(side="left", padx=(0, 8))

        title = lm.rule_title((issue.rule_id, *issue.also_detected_by), issue.title)
        ctk.CTkLabel(hdr, text=title,
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=tm.c("text"), fg_color="transparent",
                     anchor="w").pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(hdr,
                     text=f"{issue.filename}:{issue.line_number}",
                     font=ctk.CTkFont(size=10),
                     text_color=tm.c("text2"),
                     fg_color="transparent").pack(side="left", padx=(0, 6))

        self._chevron = ctk.CTkLabel(hdr, text="\u203a",
                                      font=ctk.CTkFont(size=14),
                                      text_color=tm.c("accent"),
                                      fg_color="transparent", width=20)
        self._chevron.pack(side="right")

        # Detail panel
        self._detail = ctk.CTkFrame(self, fg_color=tm.c("bg3"), corner_radius=0)
        self._build_detail(self._detail, issue, tm, lm, color)

        hdr.bind("<ButtonRelease-1>", self._toggle)
        for child in hdr.winfo_children():
            child.bind("<ButtonRelease-1>", self._toggle)

    def _build_detail(self, parent, issue: Issue, tm, lm, color: str) -> None:
        def _row(icon: str, label: str, text: str, text_color: str = "") -> None:
            if not text:
                return
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(fill="x", padx=16, pady=(4, 0))
            ctk.CTkLabel(f, text=f"{icon} {label}:",
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("accent"), fg_color="transparent",
                         anchor="w", width=140).pack(side="left", anchor="n")
            ctk.CTkLabel(f, text=text, font=ctk.CTkFont(size=10),
                         text_color=text_color or tm.c("text2"),
                         fg_color="transparent",
                         wraplength=480, anchor="w",
                         justify="left").pack(side="left", fill="x", expand=True)

        def _code_block(text: str) -> None:
            if not text:
                return
            ctk.CTkLabel(parent, text=text,
                         font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=tm.c("log_ok"), fg_color=tm.c("log_bg"),
                         corner_radius=4, anchor="w", justify="left",
                         wraplength=560).pack(fill="x", padx=16, pady=(2, 4))

        if issue.needs_review:
            _row("\U0001f50d", lm.t("needs_review"), lm.t("needs_review_hint"),
                 tm.c("warning"))
        if issue.description:
            _row("\U0001f4cb", lm.t("vulnerability"), issue.description)
        if issue.what_is_it:
            _row("\u2753", lm.t("what_is_it"), issue.what_is_it)
        if issue.why_dangerous:
            _row("\u26a0\ufe0f", lm.t("why_dangerous"),
                 issue.why_dangerous, tm.c("warning"))
        if issue.how_exploited:
            _row("\U0001f480", lm.t("how_exploited"),
                 issue.how_exploited, tm.c("error"))

        fix = issue.fix_suggestion or issue.recommendation
        if fix:
            ctk.CTkLabel(parent,
                         text=f"\u2705 {lm.t('fix_suggestion')}:",
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("success"), fg_color="transparent",
                         anchor="w").pack(anchor="w", padx=16, pady=(6, 1))
            _code_block(fix)

        meta = ctk.CTkFrame(parent, fg_color="transparent")
        meta.pack(fill="x", padx=16, pady=(4, 4))
        if issue.owasp_category:
            ctk.CTkLabel(meta,
                         text=f"\U0001f3f7\ufe0f {lm.t('owasp_category')}: "
                              f"{issue.owasp_category}",
                         font=ctk.CTkFont(size=9),
                         text_color=tm.c("text3"),
                         fg_color="transparent").pack(side="left", padx=(0, 12))
        if issue.cwe:
            ctk.CTkLabel(meta, text=f"{lm.t('cwe_label')}: {issue.cwe}",
                         font=ctk.CTkFont(size=9),
                         text_color=tm.c("text3"),
                         fg_color="transparent").pack(side="left", padx=(0, 12))
        ctk.CTkLabel(meta,
                     text=f"\U0001f4cd {lm.t('line_number')} {issue.line_number}",
                     font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
                     fg_color="transparent").pack(side="left")

        # AI Fix button row
        ai_row = ctk.CTkFrame(parent, fg_color="transparent")
        ai_row.pack(fill="x", padx=16, pady=(4, 10))
        ai_fix_btn = ctk.CTkButton(
            ai_row,
            text=f"\U0001f916  {lm.t('ai_fix')}",
            width=110, height=26, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", font=ctk.CTkFont(size=10),
            command=lambda i=issue, p=parent: self._show_ai_fix(i, p, ai_row),
        )
        ai_fix_btn.pack(side="left")
        ctk.CTkLabel(
            ai_row,
            text=lm.t("ai_fix_hint"),
            font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="left", padx=(8, 0))

    def _show_ai_fix(self, issue, parent_frame, ai_row) -> None:
        """Generate and display an AI fix suggestion inline below the button row.

        Replaces the AI Fix button with a loading indicator, then renders
        the fix suggestion (fixed code + explanation + prevention + copy button)
        once the generator completes.
        """
        from scanner_engine.ai_fix_generator import AIFixGenerator
        tm = ThemeManager()
        lm = LanguageManager()

        # Hide button row while loading
        for widget in ai_row.winfo_children():
            widget.pack_forget()

        loading_lbl = ctk.CTkLabel(
            ai_row,
            text=f"\u23f3  {lm.t('ai_fix_loading')}",
            font=ctk.CTkFont(size=10),
            text_color=tm.c("text2"),
            fg_color="transparent",
        )
        loading_lbl.pack(side="left")

        # Container for the fix panel (created now, populated in callback)
        fix_frame = ctk.CTkFrame(parent_frame, fg_color=tm.c("log_bg"),
                                  corner_radius=6)

        def _on_fix(suggestion) -> None:
            # Must update UI on the main thread
            try:
                loading_lbl.pack_forget()
                fix_frame.pack(fill="x", padx=0, pady=(0, 8))

                source_tag = (
                    "\U0001f916 Gemini AI" if suggestion.source == "gemini"
                    else "\U0001f4be Offline"
                )
                conf_pct = int(suggestion.confidence * 100)

                if getattr(suggestion, "notice", ""):
                    ctk.CTkLabel(
                        fix_frame, text=f"\u26a0  {suggestion.notice}",
                        font=ctk.CTkFont(size=10), text_color=tm.c("warning"),
                        fg_color="transparent", anchor="w", justify="left",
                        wraplength=640,
                    ).pack(fill="x", padx=10, pady=(6, 0))

                # Header row: source badge + confidence
                hdr = ctk.CTkFrame(fix_frame, fg_color="transparent")
                hdr.pack(fill="x", padx=10, pady=(6, 2))
                ctk.CTkLabel(
                    hdr, text=source_tag,
                    font=ctk.CTkFont(size=9, weight="bold"),
                    text_color=tm.c("accent"), fg_color="transparent",
                ).pack(side="left")
                ctk.CTkLabel(
                    hdr, text=f"{lm.t('ai_fix_confidence')}: {conf_pct}%",
                    font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
                    fg_color="transparent",
                ).pack(side="right")

                # Fixed code block
                if suggestion.fixed_code:
                    ctk.CTkLabel(
                        fix_frame,
                        text=f"\u2705 {lm.t('ai_fix_fixed_code')}:",
                        font=ctk.CTkFont(size=9, weight="bold"),
                        text_color=tm.c("success"), fg_color="transparent",
                        anchor="w",
                    ).pack(anchor="w", padx=10, pady=(4, 1))
                    ctk.CTkLabel(
                        fix_frame, text=suggestion.fixed_code,
                        font=ctk.CTkFont(family="Consolas", size=9),
                        text_color=tm.c("log_ok"), fg_color=tm.c("bg"),
                        corner_radius=4, anchor="w", justify="left",
                        wraplength=520,
                    ).pack(fill="x", padx=10, pady=(0, 4))

                # Explanation
                if suggestion.explanation:
                    ctk.CTkLabel(
                        fix_frame,
                        text=f"\U0001f4a1 {lm.t('ai_fix_explanation')}: "
                             f"{suggestion.explanation}",
                        font=ctk.CTkFont(size=9), text_color=tm.c("text2"),
                        fg_color="transparent", wraplength=520,
                        anchor="w", justify="left",
                    ).pack(anchor="w", padx=10, pady=(0, 2))

                # Prevention
                if suggestion.prevention:
                    ctk.CTkLabel(
                        fix_frame,
                        text=f"\U0001f6e1 {lm.t('ai_fix_prevention')}: "
                             f"{suggestion.prevention}",
                        font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
                        fg_color="transparent", wraplength=520,
                        anchor="w", justify="left",
                    ).pack(anchor="w", padx=10, pady=(0, 4))

                # Copy fix button
                def _copy_fix() -> None:
                    try:
                        parent_frame.winfo_toplevel().clipboard_clear()
                        parent_frame.winfo_toplevel().clipboard_append(
                            suggestion.fixed_code
                        )
                    except Exception:
                        pass

                ctk.CTkButton(
                    fix_frame,
                    text=f"\U0001f4cb  {lm.t('ai_fix_copy')}",
                    width=100, height=24, corner_radius=5,
                    fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
                    text_color=tm.c("text2"), font=ctk.CTkFont(size=9),
                    command=_copy_fix,
                ).pack(anchor="w", padx=10, pady=(0, 8))

            except Exception:
                pass  # widget may have been destroyed

        generator = AIFixGenerator()
        generator.generate_fix_async(issue, issue.code_snippet, _on_fix)

    def _toggle(self, _=None) -> None:
        self._expanded = not self._expanded
        if self._expanded:
            self._detail.pack(fill="x", padx=0, pady=(0, 4))
            self._chevron.configure(text="\u2228")
        else:
            self._detail.pack_forget()
            self._chevron.configure(text="\u203a")


# ── Results Page ──────────────────────────────────────────────────────────

class ResultsPage(ctk.CTkFrame):
    """
    P3 Dashboard:
      Header (title + Quick Scan + Export)
      Stat Cards row (4 cards)
      Charts row (Trend + Pie)
      Recent Scans table
      Score circle + Severity cards + Filter + Issues list
    """

    def __init__(
        self,
        master,
        on_status: Callable[[str, str], None],
        on_navigate: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._on_status  = on_status
        self._on_navigate = on_navigate
        self._result: Optional[ScanResult] = None
        self._history = ScanHistory()
        self._build()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        # ── Header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr,
                     text=f"  \U0001f4ca  {lm.t('dashboard_title')}",
                     font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
                     text_color=tm.c("text"), fg_color="transparent",
                     anchor="w").pack(side="left", padx=16, fill="y")

        self._export_btn = ctk.CTkButton(
            hdr,
            text=f"📄  {lm.t('generate_report')}",
            font=ctk.CTkFont(size=12),
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", corner_radius=6, height=30, width=180,
            command=self._export_pdf, state="disabled",
        )
        self._export_btn.pack(side="right", padx=16, pady=10)

        if self._on_navigate:
            ctk.CTkButton(
                hdr,
                text="🔍  Quick Scan",
                font=ctk.CTkFont(size=11),
                fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
                text_color=tm.c("accent"), corner_radius=6, height=30, width=120,
                command=lambda: self._on_navigate("scanner"),
            ).pack(side="right", padx=(0, 8), pady=10)

        # ── Scrollable body ───────────────────────────────────────────
        self._scroll = _ScrollCanvas(self, bg_color=tm.c("bg"))
        self._scroll.pack(fill="both", expand=True)
        body = self._scroll.inner

        # ── Stat Cards ────────────────────────────────────────────────
        stats_row = ctk.CTkFrame(body, fg_color="transparent")
        stats_row.pack(fill="x", padx=20, pady=(16, 8))

        self._card_scans  = _StatCard(stats_row, "🔍", lm.t("stat_scans"))
        self._card_score  = _StatCard(stats_row, "📊", lm.t("stat_avg_score"),
                                       suffix="/100")
        self._card_issues = _StatCard(stats_row, "⚠️",  lm.t("stat_issues"))
        self._card_files  = _StatCard(stats_row, "📁", lm.t("stat_files"))

        for card in (self._card_scans, self._card_score,
                     self._card_issues, self._card_files):
            card.pack(side="left", fill="both", expand=True, padx=6)

        # ── Charts row ────────────────────────────────────────────────
        charts_row = ctk.CTkFrame(body, fg_color="transparent")
        charts_row.pack(fill="x", padx=20, pady=(0, 8))

        self._trend = _TrendChart(charts_row, scores=[])
        self._trend.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self._pie = _PieChart(charts_row)
        self._pie.pack(side="left", fill="y", padx=(0, 0))

        # ── Recent Scans table ────────────────────────────────────────
        self._recent_table_frame = ctk.CTkFrame(body, fg_color="transparent")
        self._recent_table_frame.pack(fill="x", padx=20, pady=(0, 8))
        self._build_recent_table(self._recent_table_frame)

        # ── Divider ───────────────────────────────────────────────────
        ctk.CTkFrame(body, height=1, fg_color=tm.c("border"),
                     corner_radius=0).pack(fill="x", padx=20, pady=(0, 12))

        # ── Open-criticals banner (shown by display() when needed) ────
        self._critical_banner = ctk.CTkLabel(
            body, text="",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#ffffff", fg_color=tm.c("critical"),
            corner_radius=6, height=36,
        )

        # ── Score circle + severity cards ─────────────────────────────
        top = ctk.CTkFrame(body, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(0, 8))
        self._results_top = top

        self._score_circle = ScoreCircle(top)
        self._score_circle.pack(side="left", padx=(0, 20))

        self._cards_frame = ctk.CTkFrame(top, fg_color="transparent")
        self._cards_frame.pack(side="left", fill="both", expand=True)

        self._cards: dict[str, SeverityCard] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            card = SeverityCard(self._cards_frame, sev, 0)
            card.pack(side="left", fill="both", expand=True, padx=4)
            self._cards[sev] = card

        # ── Filter row ────────────────────────────────────────────────
        filt = ctk.CTkFrame(body, fg_color="transparent")
        filt.pack(fill="x", padx=20, pady=(4, 8))
        ctk.CTkLabel(filt, text=lm.t("filter_by"),
                     font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
                     fg_color="transparent").pack(side="left", padx=(0, 8))

        self._filter_btns: dict[str, ctk.CTkButton] = {}
        self._active_filter = "ALL"
        for key in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"):
            btn = ctk.CTkButton(
                filt, text=key, width=72, height=24, corner_radius=6,
                fg_color=tm.c("accent") if key == "ALL" else tm.c("card"),
                hover_color=tm.c("accent_h"),
                text_color="#ffffff" if key == "ALL" else tm.c("text2"),
                font=ctk.CTkFont(size=9, weight="bold"),
                command=lambda k=key: self._apply_filter(k),
            )
            btn.pack(side="left", padx=2)
            self._filter_btns[key] = btn

        # ── Issues header ─────────────────────────────────────────────
        ctk.CTkLabel(body, text=f"  {lm.t('issues_found')}",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=tm.c("text2"), fg_color=tm.c("bg2"),
                     anchor="w", height=30, corner_radius=0,
                     ).pack(fill="x", padx=20, pady=(4, 0))

        # ── Issue list ────────────────────────────────────────────────
        self._issue_frame = ctk.CTkFrame(body, fg_color="transparent")
        self._issue_frame.pack(fill="x", padx=20, pady=(0, 30))

        self._placeholder = ctk.CTkLabel(
            self._issue_frame, text=lm.t("run_scan_first"),
            font=ctk.CTkFont(size=14), text_color=tm.c("text3"),
            fg_color="transparent")
        self._placeholder.pack(pady=40)

        # Load initial stats
        self._refresh_dashboard()

    def _build_recent_table(self, parent) -> None:
        records = self._history.get_recent(5)
        for w in parent.winfo_children():
            w.destroy()
        table = _RecentTable(parent, records)
        table.pack(fill="x")
        self._recent_tbl = table

    # ------------------------------------------------------------------
    # Dashboard refresh (P1 fix + P3)
    # ------------------------------------------------------------------

    def _refresh_dashboard(self) -> None:
        """Update all stat cards and charts from ScanHistory."""
        stats = self._history.get_stats()

        # Stat cards (P1 FIX: use lambda with default capture, not lbl.configure)
        self._card_scans.set_value(stats.get("total_scans", 0))
        avg = stats.get("avg_score", 0)
        self._card_score.set_value(avg if avg else 0)
        self._card_issues.set_value(stats.get("total_issues", 0))
        self._card_files.set_value(stats.get("total_files", 0))

        # Score trend chart (last 10 scans)
        recent = self._history.get_recent(10)
        scores = [r["score"] for r in reversed(recent)]
        self._trend.update_scores(scores)

    # ------------------------------------------------------------------
    # Display scan results
    # ------------------------------------------------------------------

    def _show_critical_banner(self, result: ScanResult) -> None:
        """Keep a red banner visible while the scan has open CRITICAL findings."""
        text = AlarmCenter.open_critical_banner(result.issues)
        self._critical_banner.pack_forget()
        if text:
            self._critical_banner.configure(text=f"\u26a0  {text}")
            self._critical_banner.pack(
                fill="x", padx=20, pady=(0, 10), before=self._results_top
            )

    def display(self, result: ScanResult) -> None:
        self._result = result
        self._show_critical_banner(result)
        self._score_circle.animate_to(result.risk_score)
        self._cards["CRITICAL"].update_count(result.critical_count)
        self._cards["HIGH"].update_count(result.high_count)
        self._cards["MEDIUM"].update_count(result.medium_count)
        self._cards["LOW"].update_count(result.low_count)
        self._export_btn.configure(state="normal")

        # Update pie chart for current scan
        self._pie.update_counts(
            critical=result.critical_count,
            high=result.high_count,
            medium=result.medium_count,
            low=result.low_count,
        )

        self._apply_filter("ALL")
        # Refresh dashboard stats after brief delay (DB write may still be in flight)
        self.after(600, self._refresh_dashboard)
        self.after(650, lambda: self._build_recent_table(self._recent_table_frame))

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _apply_filter(self, level: str) -> None:
        tm = ThemeManager()
        self._active_filter = level
        for k, btn in self._filter_btns.items():
            active = k == level
            btn.configure(
                fg_color=tm.c("accent") if active else tm.c("card"),
                text_color="#ffffff" if active else tm.c("text2"),
            )
        if self._result:
            self._render_issues(self._result, level)

    def _render_issues(self, result: ScanResult, level: str) -> None:
        for w in self._issue_frame.winfo_children():
            w.destroy()

        issues = result.issues
        if level != "ALL":
            try:
                sev    = Severity[level]
                issues = [i for i in issues if i.severity == sev]
            except KeyError:
                pass

        lm = LanguageManager()
        if not issues:
            ctk.CTkLabel(self._issue_frame, text=lm.t("no_issues"),
                         font=ctk.CTkFont(size=14),
                         text_color=ThemeManager().c("success"),
                         fg_color="transparent").pack(pady=40)
            return

        sorted_issues = sorted(issues, key=lambda i: -i.severity.weight)
        rows: List[IssueAccordion] = []
        for idx, issue in enumerate(sorted_issues):
            row = IssueAccordion(self._issue_frame, issue, idx)
            row.pack_forget()
            rows.append(row)

        AnimationManager.reveal_cards(self._issue_frame, rows, delay_between=40)

    # ------------------------------------------------------------------
    # PDF export
    # ------------------------------------------------------------------

    def _export_pdf(self) -> None:
        if not self._result:
            return
        lm = LanguageManager()
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile="oranovix_security_report.pdf",
        )
        if not save_path:
            return
        self._export_btn.configure(text="⏳  Generating…", state="disabled")
        try:
            from reports.pdf_generator import PDFReportGenerator
            gen = PDFReportGenerator()
            out = gen.generate(self._result, save_path)
            AnimationManager.show_toast(
                self.winfo_toplevel(),
                f"✓  Report saved: {os.path.basename(out)}",
                color=ThemeManager().c("success"),
            )
        except Exception as exc:
            AnimationManager.show_toast(
                self.winfo_toplevel(),
                f"✗  PDF error: {exc}",
                color=ThemeManager().c("error"),
            )
        finally:
            self._export_btn.configure(
                text=f"📄  {lm.t('generate_report')}", state="normal"
            )

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg"))
        self._score_circle.refresh_theme()
