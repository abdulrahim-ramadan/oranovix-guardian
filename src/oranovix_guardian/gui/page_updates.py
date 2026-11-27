"""Run replaceable page reads off Tk and bound the number of live row widgets."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Sequence, TypeVar

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager

T = TypeVar("T")


class PageRead:
    """One active read and at most one pending replacement, owned by the Tk thread."""

    def __init__(self, widget, on_error: Callable[[str], None]) -> None:
        self.widget = widget
        self.on_error = on_error
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="PageRead")
        self.pending = None
        self.running = False
        self.closed = False

    def request(self, read, display, key=None) -> None:
        if self.closed:
            return
        if self.running:
            self.pending = (read, display, key)
            return
        self.running = True
        future = self.pool.submit(read)

        def poll() -> None:
            if self.closed:
                return
            if not future.done():
                self.widget.after(30, poll)
                return
            self.running = False
            pending = self.pending
            self.pending = None
            if pending is not None:
                self.request(*pending)
            if pending is None or pending[2] == key:
                try:
                    value = future.result()
                except Exception as exc:
                    self.on_error(str(exc))
                else:
                    display(value)

        self.widget.after(1, poll)

    def close(self) -> None:
        self.closed = True
        self.pending = None
        self.pool.shutdown(wait=False, cancel_futures=True)


class RowPager:
    """Keep a bounded page of rows and yield to Tk between small batches."""

    def __init__(self) -> None:
        self.start = 0

    def show(self, parent, items: Sequence[T], draw: Callable[..., None]) -> None:
        size = 12
        self.start = min(self.start, max(0, (len(items) - 1) // size * size))
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x")

        def move(start: int) -> None:
            self.start = start
            frame.destroy()
            self.show(parent, items, draw)

        end = min(self.start + size, len(items))
        if len(items) > size:
            lm = LanguageManager()
            nav = ctk.CTkFrame(frame, fg_color="transparent")
            nav.pack(fill="x", pady=4)
            ctk.CTkLabel(nav, text=f"{self.start + 1}–{end} / {len(items)}").pack(side=lm.pack_side)
            for key, offset in (("previous_page", self.start - size), ("next_page", end)):
                ctk.CTkButton(nav, text=lm.t(key), width=84,
                              state="normal" if 0 <= offset < len(items) else "disabled",
                              command=lambda offset=offset: move(offset)).pack(side=lm.pack_side, padx=4)

        def fill(index: int) -> None:
            stop = min(index + 2, end)
            for i in range(index, stop):
                draw(frame, items[i])
            if stop < end:
                frame.after(1, fill, stop)

        fill(self.start)
