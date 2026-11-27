"""Scrollable Tk canvas for pages with frequently changing content."""
from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from oranovix_guardian.gui.theme_manager import ThemeManager


class ScrollCanvas(ctk.CTkFrame):
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
        self._sb = tk.Scrollbar(
            self, command=self._canvas.yview, background=tm.c("border"),
            activebackground=tm.c("accent"), troughcolor=bg_color,
            borderwidth=0, highlightthickness=0,
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
        """Translate Windows and macOS wheel deltas to scroll units."""
        if event.delta:
            units = -(event.delta // 120) if abs(event.delta) >= 120 else (-1 if event.delta > 0 else 1)
        else:
            return
        self._canvas.yview_scroll(units, "units")

    def _bind_mousewheel(self, _=None) -> None:
        top = self._canvas.winfo_toplevel()
        top.bind("<MouseWheel>", self._on_mousewheel)
        top.bind("<Button-4>", lambda event: self._canvas.yview_scroll(-1, "units"))
        top.bind("<Button-5>", lambda event: self._canvas.yview_scroll(1, "units"))

    def _unbind_mousewheel(self, _=None) -> None:
        top = self._canvas.winfo_toplevel()
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            top.unbind(sequence)
