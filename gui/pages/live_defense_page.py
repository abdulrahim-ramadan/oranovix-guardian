"""
Live Defense page: folder, baseline, start/stop and the open integrity events.

The page never runs a monitor itself. It talks to the app-wide
``LiveDefenseController`` and is redrawn from the state the controller
sends. Slow actions (baseline, accept, file scan) run in a worker thread;
their results are picked up on the Tk thread by polling with ``after``.
"""
from __future__ import annotations

import os
import threading
from tkinter import filedialog
from typing import Any, Callable, Dict, List, Optional, Tuple

import customtkinter as ctk

from core.language_manager import LanguageManager
from gui.animation_manager import AnimationManager
from gui.theme_manager import ThemeManager
from live_defense.base import ChangeType, IntegrityEvent
from live_defense.baseline import BaselineError, IgnoreRules
from live_defense.controller import LiveDefenseController, LiveDefenseState
from scanner_engine.base import Language, ScanResult, Severity

Work = Callable[[], Any]
Done = Callable[[Any, str], None]


class LiveDefensePage(ctk.CTkFrame):
    """Sidebar page "Live Defense"."""

    FILTERS = ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW")
    MAX_ROWS = 300

    def __init__(
        self,
        master,
        controller: LiveDefenseController,
        on_status: Callable[[str, str], None],
        on_scan_result: Callable[[ScanResult], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._controller = controller
        self._on_status = on_status
        self._on_scan_result = on_scan_result
        self._filter = "ALL"
        self._busy = False
        self._shown_key: Tuple[Any, ...] = ()
        self._state: Optional[LiveDefenseState] = None
        self._build()
        controller.add_listener(self._show_state)
        self._show_state(controller.state())

    def destroy(self) -> None:
        self._controller.remove_listener(self._show_state)
        super().destroy()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()

        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text=f"  \U0001f6e1  {lm.t('ld_title')}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent", anchor="w",
        ).pack(side="left", padx=16, fill="y")

        body = ctk.CTkScrollableFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        setup = self._card(body)
        setup.pack(fill="x", pady=(0, 12))

        # Folder
        row = ctk.CTkFrame(setup, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(row, text=lm.t("ld_folder"), width=150, anchor="w",
                     font=ctk.CTkFont(size=11), text_color=tm.c("text2")).pack(side="left")
        self._folder_lbl = ctk.CTkLabel(row, text="", anchor="w", font=ctk.CTkFont(size=11),
                                        text_color=tm.c("text"))
        self._folder_lbl.pack(side="left", fill="x", expand=True)
        self._folder_btn = self._button(row, lm.t("ld_choose_folder"), self._choose_folder, primary=False)
        self._folder_btn.pack(side="right")

        # Baseline
        row = ctk.CTkFrame(setup, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text=lm.t("ld_baseline"), width=150, anchor="w",
                     font=ctk.CTkFont(size=11), text_color=tm.c("text2")).pack(side="left")
        self._baseline_lbl = ctk.CTkLabel(row, text="", anchor="w", justify="left",
                                          font=ctk.CTkFont(size=11), wraplength=460)
        self._baseline_lbl.pack(side="left", fill="x", expand=True)
        self._baseline_btn = self._button(row, lm.t("ld_create_baseline"), self._create_baseline, primary=False)
        self._baseline_btn.pack(side="right")

        # Start / stop and interval
        row = ctk.CTkFrame(setup, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text=lm.t("ld_interval"), width=150, anchor="w",
                     font=ctk.CTkFont(size=11), text_color=tm.c("text2")).pack(side="left")
        self._interval_entry = ctk.CTkEntry(
            row, width=70, height=28, fg_color=tm.c("input_bg"),
            border_color=tm.c("border"), text_color=tm.c("text"),
        )
        self._interval_entry.insert(0, str(self._controller.interval))
        self._interval_entry.pack(side="left")
        self._run_lbl = ctk.CTkLabel(row, text="", anchor="w", font=ctk.CTkFont(size=11))
        self._run_lbl.pack(side="left", padx=(12, 0), fill="x", expand=True)
        self._start_btn = self._button(row, lm.t("ld_start"), self._toggle_running)
        self._start_btn.pack(side="right")

        # Ignore patterns
        ctk.CTkLabel(setup, text=lm.t("ld_ignore"), anchor="w",
                     font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
                     ).pack(fill="x", padx=16, pady=(10, 2))
        self._patterns_box = ctk.CTkTextbox(
            setup, height=70, fg_color=tm.c("input_bg"), text_color=tm.c("text"),
            font=ctk.CTkFont(family="Consolas", size=10),
        )
        self._patterns_box.pack(fill="x", padx=16)
        row = ctk.CTkFrame(setup, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(4, 12))
        dirs = ", ".join((*IgnoreRules.SKIPPED_DIRS, *IgnoreRules.SKIPPED_PATHS))
        defaults = ", ".join(IgnoreRules.DEFAULT_FILE_PATTERNS)
        ctk.CTkLabel(row, text=lm.t("ld_ignore_hint", dirs=dirs, files=defaults),
                     anchor="w", justify="left", wraplength=520,
                     font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
                     ).pack(side="left", fill="x", expand=True)
        self._patterns_btn = self._button(row, lm.t("ld_save_patterns"), self._save_patterns, primary=False)
        self._patterns_btn.pack(side="right")

        self._message_lbl = ctk.CTkLabel(body, text="", anchor="w", justify="left",
                                         font=ctk.CTkFont(size=11), wraplength=700)
        self._message_lbl.pack(fill="x", pady=(0, 6))

        # Events
        events = self._card(body)
        events.pack(fill="both", expand=True)
        bar = ctk.CTkFrame(events, fg_color="transparent")
        bar.pack(fill="x", padx=12, pady=(10, 6))
        ctk.CTkLabel(bar, text=lm.t("ld_events"), font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=tm.c("text")).pack(side="left", padx=(4, 12))
        self._filter_btns: Dict[str, ctk.CTkButton] = {}
        for key in self.FILTERS:
            label = lm.t("all") if key == "ALL" else lm.t(key.lower())
            btn = ctk.CTkButton(
                bar, text=label, width=70, height=24, corner_radius=6,
                font=ctk.CTkFont(size=9, weight="bold"),
                hover_color=tm.c("accent_h"),
                command=lambda k=key: self._set_filter(k),
            )
            btn.pack(side="left", padx=2)
            self._filter_btns[key] = btn
        self._accept_all_btn = self._button(bar, lm.t("ld_accept_all"), self._accept_all)
        self._accept_all_btn.pack(side="right")

        self._table = ctk.CTkFrame(events, fg_color="transparent")
        self._table.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._paint_filters()

    @staticmethod
    def _card(master) -> ctk.CTkFrame:
        tm = ThemeManager()
        return ctk.CTkFrame(master, fg_color=tm.c("card"), corner_radius=10,
                            border_width=1, border_color=tm.c("border"))

    @staticmethod
    def _button(master, text: str, command: Callable[[], None], primary: bool = True) -> ctk.CTkButton:
        tm = ThemeManager()
        return ctk.CTkButton(
            master, text=text, height=28, corner_radius=6, command=command,
            width=max(110, 8 * len(text)), font=ctk.CTkFont(size=10),
            fg_color=tm.c("accent") if primary else tm.c("bg3"),
            hover_color=tm.c("accent_h") if primary else tm.c("hover"),
            text_color="#ffffff" if primary else tm.c("text2"),
        )

    # ------------------------------------------------------------------
    # State from the controller
    # ------------------------------------------------------------------

    def _show_state(self, state: LiveDefenseState) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        self._state = state

        self._folder_lbl.configure(text=state.root or lm.t("ld_no_folder"))

        if not state.root:
            text, color = lm.t("ld_no_folder"), tm.c("text3")
        elif not state.baseline_exists:
            text, color = lm.t("ld_baseline_none"), tm.c("warning")
        elif not state.baseline_ok:
            text, color = f"{lm.t('ld_baseline_tampered')}\n{state.baseline_problem}", tm.c("error")
        else:
            created = state.baseline_created_at.strftime("%Y-%m-%d %H:%M") if state.baseline_created_at else ""
            text = lm.t("ld_baseline_info", date=created, count=state.baseline_files)
            color = tm.c("success")
        self._baseline_lbl.configure(text=text, text_color=color)

        if state.running:
            if state.last_check_at:
                run = lm.t("ld_running", time=state.last_check_at.strftime("%H:%M:%S"))
            else:
                run = lm.t("ld_running_wait")
            self._run_lbl.configure(text=run, text_color=tm.c("success"))
            self._start_btn.configure(text=lm.t("ld_stop"))
        else:
            self._run_lbl.configure(text=lm.t("ld_stopped"), text_color=tm.c("text3"))
            self._start_btn.configure(text=lm.t("ld_start"))

        if state.last_error:
            self._message(lm.t("ld_check_error", error=state.last_error), error=True)

        current = self._patterns_box.get("1.0", "end").strip().splitlines()
        if tuple(IgnoreRules.clean(current)) != state.ignore_patterns and not self._patterns_box.edit_modified():
            self._patterns_box.delete("1.0", "end")
            self._patterns_box.insert("1.0", "\n".join(state.ignore_patterns))
            self._patterns_box.edit_modified(False)

        self._set_enabled()
        self._render_events()

    def _set_enabled(self) -> None:
        state = self._state
        has_root = bool(state and state.root)
        has_baseline = bool(state and state.baseline_exists)
        idle = "disabled" if self._busy else "normal"
        self._folder_btn.configure(state=idle)
        self._baseline_btn.configure(state=idle if has_root else "disabled")
        self._start_btn.configure(state=idle if has_baseline or (state and state.running) else "disabled")
        self._patterns_btn.configure(state=idle if has_baseline else "disabled")
        can_accept = bool(state and state.running and any(e.can_accept for e in state.open_events))
        self._accept_all_btn.configure(state=idle if can_accept else "disabled")

    # ------------------------------------------------------------------
    # Events table
    # ------------------------------------------------------------------

    @classmethod
    def filter_events(cls, events: Tuple[IntegrityEvent, ...], level: str) -> List[IntegrityEvent]:
        if level in Severity.__members__:
            return [e for e in events if e.severity is Severity[level]]
        return list(events)

    def _set_filter(self, level: str) -> None:
        self._filter = level
        self._paint_filters()
        self._render_events(force=True)

    def _paint_filters(self) -> None:
        tm = ThemeManager()
        for key, btn in self._filter_btns.items():
            active = key == self._filter
            btn.configure(
                fg_color=tm.c("accent") if active else tm.c("bg3"),
                text_color="#ffffff" if active else tm.c("text2"),
            )

    def _render_events(self, force: bool = False) -> None:
        state = self._state
        events = self.filter_events(state.open_events if state else (), self._filter)[: self.MAX_ROWS]
        key = (self._filter, self._busy, bool(state and state.running), tuple(e.event_id for e in events))
        if key == self._shown_key and not force:
            return
        self._shown_key = key

        for child in self._table.winfo_children():
            child.destroy()
        tm = ThemeManager()
        lm = LanguageManager()
        if not events:
            text = lm.t("ld_no_events") if state and state.running else lm.t("ld_not_monitoring")
            ctk.CTkLabel(self._table, text=text, font=ctk.CTkFont(size=12),
                         text_color=tm.c("text3")).pack(pady=24)
            return

        header = ctk.CTkFrame(self._table, fg_color=tm.c("bg2"), corner_radius=4)
        header.pack(fill="x", pady=(0, 2))
        for text, width in self._columns(lm):
            ctk.CTkLabel(header, text=text, width=width, anchor="w",
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("text3")).pack(side="left", padx=4)
        for event in events:
            self._event_row(event)

    @staticmethod
    def _columns(lm: LanguageManager) -> List[Tuple[str, int]]:
        return [
            (lm.t("ld_col_time"), 60), (lm.t("ld_col_severity"), 70),
            (lm.t("ld_col_change"), 90), (lm.t("ld_col_type"), 60),
            (lm.t("ld_col_path"), 200), (lm.t("ld_col_reason"), 230),
        ]

    def _event_row(self, event: IntegrityEvent) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        running = bool(self._state and self._state.running)
        row = ctk.CTkFrame(self._table, fg_color=tm.c("bg2"), corner_radius=4)
        row.pack(fill="x", pady=1)

        ctk.CTkLabel(row, text=event.detected_at.strftime("%H:%M:%S"), width=60, anchor="w",
                     font=ctk.CTkFont(size=9), text_color=tm.c("text2")).pack(side="left", padx=4)
        ctk.CTkLabel(row, text=f" {lm.t(event.severity.value.lower())} ", width=70,
                     fg_color=tm.c(event.severity.value.lower()), corner_radius=3,
                     font=ctk.CTkFont(size=8, weight="bold"), text_color="#ffffff",
                     ).pack(side="left", padx=4, pady=4)
        ctk.CTkLabel(row, text=lm.t(f"ld_change_{event.change.value}"), width=90, anchor="w",
                     font=ctk.CTkFont(size=9), text_color=tm.c("text")).pack(side="left", padx=4)
        ctk.CTkLabel(row, text=self.type_label(event), width=60, anchor="w",
                     font=ctk.CTkFont(size=9), text_color=tm.c("text3")).pack(side="left", padx=4)
        ctk.CTkLabel(row, text=event.relative_path or event.root, width=200, anchor="w",
                     justify="left", wraplength=200, font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=tm.c("text")).pack(side="left", padx=4)
        ctk.CTkLabel(row, text=event.reason, width=230, anchor="w", justify="left",
                     wraplength=230, font=ctk.CTkFont(size=9),
                     text_color=tm.c("text2")).pack(side="left", padx=4)

        idle = "disabled" if self._busy else "normal"
        scan_ok = event.change in (ChangeType.NEW, ChangeType.MODIFIED) and os.path.isfile(event.path)
        scan_btn = ctk.CTkButton(
            row, text=lm.t("ld_scan_file"), width=74, height=22, corner_radius=4,
            font=ctk.CTkFont(size=9), fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), state=idle if scan_ok else "disabled",
            command=lambda e=event: self._scan_file(e),
        )
        scan_btn.pack(side="right", padx=(2, 6))
        if event.can_accept:
            ctk.CTkButton(
                row, text=lm.t("ld_accept"), width=64, height=22, corner_radius=4,
                font=ctk.CTkFont(size=9), fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
                text_color="#ffffff", state=idle if running else "disabled",
                command=lambda e=event: self._accept(e),
            ).pack(side="right", padx=2)
        else:
            ctk.CTkLabel(row, text=lm.t("ld_tamper_hint"), wraplength=140, width=140,
                         font=ctk.CTkFont(size=8), text_color=tm.c("error")).pack(side="right", padx=2)

    @staticmethod
    def type_label(event: IntegrityEvent) -> str:
        """Language of the file; "Config" for settings files, "File" otherwise."""
        lm = LanguageManager()
        if not event.relative_path:
            return lm.t("language_file")
        language = Language.from_path(event.relative_path)
        if language is Language.CONFIG:
            return lm.t("language_config")
        if language is Language.UNKNOWN:
            return lm.t("language_file")
        return language.value

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _choose_folder(self) -> None:
        lm = LanguageManager()
        folder = filedialog.askdirectory(title=lm.t("ld_choose_folder"))
        if not folder:
            return
        self._controller.set_root(folder)
        self._message("")
        self._controller.notify()

    def _create_baseline(self) -> None:
        lm = LanguageManager()
        patterns = self._patterns_box.get("1.0", "end").splitlines()
        self._message(lm.t("ld_baseline_creating"))
        self._background(
            lambda: self._controller.create_baseline(patterns),
            lambda count, error: self._after_action(
                error, lm.t("ld_baseline_created", count=count) if not error else ""
            ),
        )

    def _toggle_running(self) -> None:
        lm = LanguageManager()
        if self._controller.is_running:
            self._controller.stop()
            self._message("")
            self._controller.notify()
            return
        seconds = self._interval_entry.get().strip()
        if not seconds.isdigit() or int(seconds) < 5:
            self._message(lm.t("ld_interval_invalid", min=5), error=True)
            return
        self._controller.set_interval(int(seconds))
        try:
            self._controller.start()
        except BaselineError as exc:
            self._message(str(exc), error=True)
            return
        self._message("")
        self._controller.notify()

    def _save_patterns(self) -> None:
        lm = LanguageManager()
        patterns = self._patterns_box.get("1.0", "end").splitlines()
        self._background(
            lambda: self._controller.set_ignore_patterns(patterns),
            lambda result, error: self._after_action(error, lm.t("ld_patterns_saved")),
        )
        self._patterns_box.edit_modified(False)

    def _accept(self, event: IntegrityEvent) -> None:
        self._background(
            lambda: self._controller.accept([event.event_id]),
            lambda count, error: self._after_action(error, ""),
        )

    def _accept_all(self) -> None:
        self._background(
            self._controller.accept_all,
            lambda count, error: self._after_action(error, ""),
        )

    def _scan_file(self, event: IntegrityEvent) -> None:
        lm = LanguageManager()
        path = event.path
        self._message(lm.t("ld_scanning_file", file=os.path.basename(path)))

        def work() -> ScanResult:
            from scanner_engine.orchestrator import ScanOrchestrator
            return ScanOrchestrator().scan(path)

        def done(result: Optional[ScanResult], error: str) -> None:
            self._after_action(error, "")
            if result is not None and not error:
                self._on_scan_result(result)

        self._background(work, done)

    def _after_action(self, error: str, success: str) -> None:
        if error:
            self._message(error, error=True)
            self._on_status(error, "error")
        else:
            self._message(success)
        self._controller.notify()

    def _message(self, text: str, error: bool = False) -> None:
        tm = ThemeManager()
        self._message_lbl.configure(text=text, text_color=tm.c("error") if error else tm.c("text2"))

    def _background(self, work: Work, done: Done) -> None:
        """Run *work* in a thread; call *done(result, error)* on the Tk thread."""
        if self._busy:
            return
        self._busy = True
        self._set_enabled()
        outcome: List[Tuple[Any, str]] = []

        def runner() -> None:
            try:
                outcome.append((work(), ""))
            except BaselineError as exc:
                outcome.append((None, str(exc)))
            except Exception as exc:
                outcome.append((None, f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=runner, daemon=True).start()
        self.after(100, self._poll, outcome, done)

    def _poll(self, outcome: List[Tuple[Any, str]], done: Done) -> None:
        if not outcome:
            self.after(100, self._poll, outcome, done)
            return
        self._busy = False
        result, error = outcome[0]
        done(result, error)
        self._set_enabled()
        self._render_events(force=True)

    def refresh_theme(self) -> None:
        self.configure(fg_color=ThemeManager().c("bg"))


def toast_new_events(root, state: LiveDefenseState) -> None:
    """Short toast for new events that do not reach the alarm (MEDIUM / LOW)."""
    quiet = [e for e in state.new_events if e.severity in (Severity.MEDIUM, Severity.LOW)]
    if not quiet:
        return
    lm = LanguageManager()
    AnimationManager.show_toast(
        root, lm.t("ld_new_events_toast", count=len(quiet)), color=ThemeManager().c("warning")
    )
