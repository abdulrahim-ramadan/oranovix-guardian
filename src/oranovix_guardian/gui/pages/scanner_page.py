"""File selection, background target discovery and scanning, and the live scan log."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog
from typing import Callable, List, Optional

import customtkinter as ctk

from oranovix_guardian.gui.theme_manager      import ThemeManager
from oranovix_guardian.gui.animation_manager  import AnimationManager
from oranovix_guardian.gui.asset_helper       import load_logo
from oranovix_guardian.core.language_manager  import LanguageManager
from oranovix_guardian.core.sound_manager     import SoundManager
from oranovix_guardian.core.alarm_center      import AlarmCenter, AlarmLevel
from oranovix_guardian.scanner_engine.base             import Language, ScanResult, ScanStatus, Severity
from oranovix_guardian.scanner_engine.orchestrator     import ScanOrchestrator, ScanProgress


# ── Live Log Console ──────────────────────────────────────────────────────

class LogConsole(ctk.CTkFrame):
    """VS Code-style terminal panel for displaying colour-coded log output.

    Each log line is prefixed with a bracketed severity tag (e.g.
    ``[INFO]``, ``[CRIT]``) and coloured using Tk text tags that map to
    the active theme palette.

    Supports:
        - :meth:`append` — add a single log line with a named severity level.
        - :meth:`clear` — wipe all existing content.
        - :meth:`play_startup_sequence` — animate a series of boot messages
          with configurable inter-line delays.

    The underlying widget is a read-only :class:`tk.Text` (``state="disabled"``
    outside of write operations) to prevent the user from editing the log.

    Args:
        master:   Parent widget.
        **kwargs: Forwarded to :class:`ctk.CTkFrame`.
    """

    # Mapping from level name → (theme colour key, display prefix)
    _LEVELS = {
        "info":     ("log_info",  "INFO"),
        "scan":     ("log_scan",  "SCAN"),
        "found":    ("log_warn",  "FOUND"),
        "critical": ("log_err",   "CRIT"),
        "done":     ("log_ok",    "DONE"),
        "error":    ("log_err",   " ERR"),
        "ok":       ("log_ok",    "  OK"),
    }

    def __init__(self, master, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            fg_color=tm.c("log_bg"),
            corner_radius=8,
            **kwargs,
        )
        self._build()

    def _build(self) -> None:
        """Construct the console header bar, text widget, scrollbar, and colour tags."""
        tm = ThemeManager()

        # Compact header bar mimicking a terminal title strip
        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg3"), corner_radius=0, height=26)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Attempt to show a small app icon in the header; silently skip if
        # Pillow is unavailable or the asset file is missing.
        try:
            img = load_logo(16)
            if img is not None:
                ctk_img = ctk.CTkImage(img, size=img.size)
                ctk.CTkLabel(
                    hdr, image=ctk_img, text="",
                    fg_color="transparent", width=20,
                ).pack(side="left", padx=(6, 0), pady=4)
        except Exception:
            pass

        ctk.CTkLabel(
            hdr,
            text=f"  {LanguageManager().t('console_title')}",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=tm.c("accent"),
            fg_color="transparent",
            anchor="w",
        ).pack(side="left", padx=4, fill="y")

        # "Clear" button — erases all log content via self.clear()
        ctk.CTkButton(
            hdr,
            text=LanguageManager().t("console_clear"),
            width=48,
            height=20,
            corner_radius=4,
            font=ctk.CTkFont(size=9),
            fg_color=tm.c("border"),
            hover_color=tm.c("accent"),
            text_color=tm.c("text2"),
            command=self.clear,
        ).pack(side="right", padx=6, pady=3)

        # Read-only tk.Text widget for log output.
        # state="disabled" outside write operations prevents user edits.
        self._txt = tk.Text(
            self,
            bg=tm.c("log_bg"),
            fg=tm.c("log_text"),
            font=("Consolas", 10),
            relief="flat",
            bd=0,
            wrap="word",
            state="disabled",
            cursor="arrow",                         # hide the text-edit cursor
            insertbackground=tm.c("accent"),
            selectbackground=tm.c("accent"),
        )
        self._txt.pack(fill="both", expand=True, padx=4, pady=(2, 4))

        # Vertical scrollbar linked bidirectionally to the text widget
        sb = ctk.CTkScrollbar(self, command=self._txt.yview)
        sb.pack(side="right", fill="y")
        self._txt.configure(yscrollcommand=sb.set)

        # Register one Tk text tag per severity level so that coloured
        # text can be inserted with a single tag_config lookup.
        tm2 = ThemeManager()
        self._txt.tag_config("info",     foreground=tm2.c("log_info"))
        self._txt.tag_config("scan",     foreground=tm2.c("log_scan"))
        self._txt.tag_config("found",    foreground=tm2.c("log_warn"))
        self._txt.tag_config("critical", foreground=tm2.c("log_err"))
        self._txt.tag_config("done",     foreground=tm2.c("log_ok"))
        self._txt.tag_config("error",    foreground=tm2.c("log_err"))
        self._txt.tag_config("ok",       foreground=tm2.c("log_ok"))

    def append(self, text: str, level: str = "info") -> None:
        """Append a single colour-coded log line to the console.

        The widget is temporarily enabled for writing, a formatted line is
        inserted at the end with the appropriate Tk text tag, and then the
        widget is disabled again.  The view scrolls to the new line
        automatically.

        Args:
            text:  The log message to display.
            level: Severity key — one of ``"info"``, ``"scan"``,
                   ``"found"``, ``"critical"``, ``"done"``, ``"error"``,
                   ``"ok"``.  Unknown levels fall back to ``"INFO"`` style.
        """
        _, prefix = self._LEVELS.get(level, ("log_info", "INFO"))
        line = f"  [{prefix}]  {text}\n"
        self._txt.configure(state="normal")
        self._txt.insert("end", line, level)
        self._txt.configure(state="disabled")
        # Auto-scroll so the latest line is always visible
        self._txt.see("end")

    def clear(self) -> None:
        """Remove all content from the log console."""
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.configure(state="disabled")

    def play_startup_sequence(self, widget) -> None:
        """Show the real state of the application, one line at a time.

        The state (version, rules, vulnerability database, AI setting,
        monitors) is read on a worker thread, because it touches the rule
        files, the OSV database and the credential store; the lines are
        then added on the Tk thread with a short delay between them.

        Args:
            widget: Any Tkinter widget whose ``after()`` method will be
                    used to schedule the deferred calls — typically the
                    parent page frame.
        """
        from oranovix_guardian.gui.startup_report import StartupState, startup_lines
        from oranovix_guardian.gui.ui_thread import on_ui_thread

        def show(state: StartupState) -> None:
            for index, (text, level) in enumerate(startup_lines(state)):
                widget.after(index * 150, lambda m=text, l=level: self._append_quietly(m, l))

        deliver = on_ui_thread(widget, show)
        threading.Thread(target=lambda: deliver(StartupState.collect()), daemon=True).start()

    def _append_quietly(self, message: str, level: str) -> None:
        """Append unless the console was destroyed meanwhile (theme or language rebuild)."""
        try:
            self.append(message, level)
        except tk.TclError:
            pass


# ── Drop Zone ─────────────────────────────────────────────────────────────

class DropZone(ctk.CTkFrame):
    """File and folder picker displaying the selected target path."""

    def __init__(
        self,
        master,
        on_path_selected: Callable[[str], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            fg_color=tm.c("card"),
            corner_radius=12,
            border_width=1,
            border_color=tm.c("border"),
            **kwargs,
        )
        self._on_path  = on_path_selected
        self._path: str = ""
        self._build()

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        self._path_label = ctk.CTkLabel(
            self, text=lm.t("drop_hint"), anchor=lm.text_anchor,
            font=ctk.CTkFont(size=14), text_color=tm.c("text"),
        )
        self._path_label.pack(fill="x", padx=16, pady=(12, 4))
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(4, 12))

        self._folder_button = ctk.CTkButton(
            btn_row,
            text=f"📁  {lm.t('select_folder')}",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=tm.c("accent"),
            hover_color=tm.c("accent_h"),
            text_color="#ffffff",
            corner_radius=8,
            height=34,
            width=160,
            command=self._pick_folder,
        )
        self._folder_button.pack(side=lm.pack_side, padx=4)

        self._file_button = ctk.CTkButton(
            btn_row,
            text=f"📄  {lm.t('select_file')}",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=tm.c("bg3"),
            hover_color=tm.c("hover"),
            text_color=tm.c("text"),
            corner_radius=8,
            height=34,
            width=160,
            command=self._pick_file,
        )
        self._file_button.pack(side=lm.pack_side, padx=4)

    def set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in (self._folder_button, self._file_button):
            button.configure(state=state)

    def _pick_folder(self) -> None:
        """Open a native directory picker dialog and set the chosen path."""
        lm = LanguageManager()
        path = filedialog.askdirectory(title=lm.t("select_folder"))
        if path:
            self._set_path(path)

    def _pick_file(self) -> None:
        """Open a native file picker dialog filtered to supported languages."""
        lm = LanguageManager()
        path = filedialog.askopenfilename(
            title=lm.t("select_file"),
            filetypes=[
                ("All supported", "*.py *.php *.java *.cs *.js *.ts"),
                ("Python",        "*.py"),
                ("PHP",           "*.php"),
                ("Java",          "*.java"),
                ("C#",            "*.cs"),
                ("JavaScript",    "*.js *.ts"),
                ("Dependencies",  "requirements*.txt pyproject.toml Pipfile.lock "
                                  "poetry.lock package.json package-lock.json"),
                ("All files",     "*.*"),
            ],
        )
        if path:
            self._set_path(path)

    def _set_path(self, path: str) -> None:
        """Store the selected path, update the path label, and invoke the callback.

        Args:
            path: Absolute file or directory path chosen by the user.
        """
        self._path = path
        self._path_label.configure(text=path)
        self._on_path(path)


# ── Scanner Page ──────────────────────────────────────────────────────────

class ScannerPage(ctk.CTkFrame):
    """Main scanner page that orchestrates the full scan workflow.

    The Tk thread polls worker results and a queue of scan progress messages.
    Folder traversal and analysis run outside the event loop.

    Args:
        master:           Parent widget (the content area frame).
        on_scan_complete: Callback receiving a
                          :class:`~scanner_engine.base.ScanResult` when a
                          scan finishes successfully.
        on_status:        Callback ``(message: str, level: str)`` that
                          updates the application status bar.
        **kwargs:         Forwarded to :class:`ctk.CTkFrame`.
    """

    def __init__(
        self,
        master,
        on_scan_complete: Callable[[ScanResult], None],
        on_scan_start: Callable[[str], None],
        on_scan_waiting: Callable[[bool], None],
        on_status: Callable[[str, str], None],
        alarm_center: Optional[AlarmCenter] = None,
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._alarm_center = alarm_center
        self._on_complete = on_scan_complete
        self._on_scan_start = on_scan_start
        self._on_scan_waiting = on_scan_waiting
        self._on_status   = on_status
        self._target: str  = ""
        self._scanning     = False
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="Scanner")
        self._preview = None
        self._start_requested = False
        self._build()

    def destroy(self) -> None:
        self._worker.shutdown(wait=False, cancel_futures=True)
        super().destroy()

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        ctk.CTkLabel(
            self, text=lm.t("nav_scanner"), anchor=lm.text_anchor,
            text_color=tm.c("text"), font=ctk.CTkFont(size=21, weight="bold"),
        ).pack(fill="x", padx=20, pady=(16, 0))

        # ── Main body ─────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        # Label above the drop zone
        ctk.CTkLabel(
            body,
            text=lm.t("target_path"),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=tm.c("text2"),
            fg_color="transparent",
            anchor="w",
        ).pack(anchor="w", pady=(0, 4))

        self._drop_zone = DropZone(body, on_path_selected=self._on_path_selected)
        self._drop_zone.pack(fill="x")

        # Scan button + inline progress label in a single row
        ctrl = ctk.CTkFrame(body, fg_color="transparent")
        ctrl.pack(fill="x", pady=10)

        self._scan_btn = ctk.CTkButton(
            ctrl,
            text=f"▶   {lm.t('start_scan')}",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=tm.c("accent"),
            hover_color=tm.c("accent_h"),
            text_color="#ffffff",
            corner_radius=8,
            height=40,
            width=180,
            command=self._start_scan,
        )
        self._scan_btn.pack(side="left")

        # Inline label next to the button for live file-count feedback
        self._prog_lbl = ctk.CTkLabel(
            ctrl,
            text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=tm.c("text2"),
            fg_color="transparent",
            anchor="w",
        )
        self._prog_lbl.pack(side="left", padx=(12, 0))

        # Thin animated progress bar below the controls row
        self._progress = ctk.CTkProgressBar(
            body,
            height=6,
            progress_color=tm.c("accent"),
            fg_color=tm.c("progress_bg"),
            corner_radius=3,
        )
        self._progress.set(0)
        self._progress.pack(fill="x", pady=(0, 8))

        # Log console expands to fill all remaining vertical space
        self._log = LogConsole(body)
        self._log.pack(fill="both", expand=True)

        # Start the boot animation after a short delay so the widget is
        # visible and the event loop is running before the first after() fires.
        self.after(200, lambda: self._log.play_startup_sequence(self))

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _on_path_selected(self, path: str) -> None:
        self._target = path
        if self._preview is not None:
            self._preview.cancel()
        self.cancel_pending_scan()
        self._log.clear()
        self._prog_lbl.configure(text=LanguageManager().t("checking_target"))
        self._preview = self._worker.submit(self._inspect_target, path)
        self._poll_preview(self._preview)

    @staticmethod
    def _inspect_target(path: str):
        files = ScanOrchestrator.scannable_files(path)
        languages = {Language.from_path(f) for f in files}
        source_languages = sorted(languages - {Language.CONFIG, Language.UNKNOWN}, key=lambda lang: lang.value)
        return len(files), source_languages, Language.CONFIG in languages

    def _poll_preview(self, future) -> None:
        if self._preview is not future:
            return
        if not future.done():
            self.after(40, self._poll_preview, future)
            return
        lm = LanguageManager()
        try:
            count, languages, has_config = future.result()
        except Exception as exc:
            self._prog_lbl.configure(text=str(exc))
            self.cancel_pending_scan()
            return
        names = [lang.value for lang in languages]
        if has_config:
            names.append(lm.t("language_config"))
        summary = f"{count} {lm.t('files_found')}  ·  {', '.join(names)}"
        self._prog_lbl.configure(text=summary if count else lm.t("no_scannable_files"))
        if self._start_requested and count:
            self._start_requested = False
            self._launch_scan()
        elif self._start_requested:
            self.cancel_pending_scan()

    def cancel_pending_scan(self) -> None:
        if self._start_requested:
            self._start_requested = False
            self._on_scan_waiting(False)

    def scan_path(self, path: str) -> None:
        """Select *path* and start the normal scan, as if the user had picked it."""
        if self._scanning:
            return
        self._drop_zone._set_path(path)     # shows the name and selects the target
        self._start_scan()

    @staticmethod
    def detected_languages_text(languages: List[Language], files: List[str]) -> str:
        """Languages of the target for the log; config files count as "Config"."""
        names = [language.value for language in languages]
        if any(Language.from_path(f) is Language.CONFIG for f in files):
            names.append(LanguageManager().t("language_config"))
        return ", ".join(names) or Language.UNKNOWN.value

    def _start_scan(self) -> None:
        if self._scanning:
            return
        lm = LanguageManager()
        if not self._target:
            AnimationManager.show_toast(
                self.winfo_toplevel(),
                f"\u26a0  {lm.t('select_target_first')}",
                color=ThemeManager().c("warning"),
            )
            return

        self._start_requested = True
        if self._preview is not None and self._preview.done():
            self._poll_preview(self._preview)
        else:
            self._on_scan_waiting(True)

    def _launch_scan(self) -> None:
        self._scanning = True
        self._drop_zone.set_enabled(False)
        lm = LanguageManager()
        self._scan_btn.configure(state="disabled", text=f"\u23f3  {lm.t('scanning')}")
        self._log.clear()
        self._log.append(f"Starting scan: {self._target}", "info")

        self._progress.set(0)

        self._on_scan_start(self._target)

    def show_scan_progress(self, update: ScanProgress) -> None:
        self._log.append(update.message, update.level)
        self._progress.set(update.fraction)

    def _scan_done(
        self, result: Optional[ScanResult], error: Optional[str]
    ) -> None:
        self._scanning = False
        self._drop_zone.set_enabled(True)
        lm = LanguageManager()
        tm = ThemeManager()

        self._progress.set(1.0 if result and result.status == ScanStatus.COMPLETED else 0)
        self._scan_btn.configure(
            state="normal",
            text=f"▶   {lm.t('start_scan')}",
            fg_color=tm.c("accent"),
        )
        self._prog_lbl.configure(text="")

        if result is not None and result.status == ScanStatus.CANCELLED:
            self._log.append(lm.t("scan_cancelled"), "info")
            self._on_status(lm.t("scan_cancelled"), "info")
            return

        if error or result is None:
            error = error or "Scan returned no result"
            self._log.append(f"Scan failed: {error}", "error")
            self._on_status(f"✗  {error}", "error")
            SoundManager().play("error")
            return

        # Log each finding
        self._log.append(
            f"Analysis complete ({result.scanner_name}) — "
            f"{result.files_scanned} file(s) scanned.",
            "done",
        )
        for issue in result.issues[:20]:
            level = (
                "critical"
                if issue.severity in (Severity.CRITICAL, Severity.HIGH)
                else "found"
            )
            self._log.append(
                f"Line {issue.line_number}: {issue.title} — {issue.severity.value}  "
                f"[{issue.rule_ids_label}]  ({os.path.basename(issue.file_path)})",
                level,
            )
        if result.total_issues > 20:
            self._log.append(
                f"... and {result.total_issues - 20} more issue(s)", "info"
            )

        self._log.append(
            f"Scan done. Score: {result.risk_score}/100 "
            f"({result.risk_label}) — {result.total_issues} issue(s)  "
            f"[{result.severity_counts_label}]",
            "done",
        )

        if result.engine_warnings:
            for warning in result.engine_warnings[:20]:
                self._log.append(f"{lm.t('engine_warning')}: {warning}", "error")
            warning_summary = lm.t(
                "scan_done_with_warnings", count=len(result.engine_warnings)
            )
            self._log.append(warning_summary, "error")
            self._on_status(f"⚠  {warning_summary}", "warn")
        else:
            self._on_status(
                f"✓  Scan complete — {result.total_issues} issue(s)  |  "
                f"risk {result.risk_score}/100  [{result.severity_counts_label}]",
                "ok",
            )

        # Hand off to results page
        self._on_complete(result)

        # The alarm center owns critical/high alerts; it stays silent for
        # findings it has already announced.
        alarm = (
            self._alarm_center.notify(result.issues, result.target_path)
            if self._alarm_center else None
        )
        if alarm is None or alarm.level is not AlarmLevel.CRITICAL:
            SoundManager().play("complete")
        if alarm is None:
            AnimationManager.show_toast(
                self.winfo_toplevel(),
                f"✓  Scan done — {result.total_issues} issue(s)  |  "
                f"Score: {result.risk_score}/100  [{result.severity_counts_label}]",
                color=tm.c("success") if result.total_issues == 0 else tm.c("warning"),
            )

    def refresh_theme(self) -> None:
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg"))
