"""
Scanner page for Oranovix Guardian, providing file/folder selection, real-time scan execution, and live log output.

This module contains three classes that together form the primary scanning
workflow:

- :class:`LogConsole` — A VS Code-style terminal panel that displays
  colour-coded log messages.  It supports an animated startup sequence
  and real-time progress lines emitted during a scan.

- :class:`DropZone` — An animated dashed-border widget with explicit
  "Select Folder" and "Select File" picker buttons.  It notifies the
  parent page when a path is chosen.

- :class:`ScannerPage` — The top-level page frame that composes the
  :class:`DropZone`, a scan-trigger button with pulse animation, a
  real-time :class:`ctk.CTkProgressBar`, and the :class:`LogConsole`.
  Scanning runs in a background ``daemon`` thread via
  :class:`~scanner_engine.factory.ScannerFactory`; results are delivered
  to the results page through a callback supplied by
  :class:`~gui.app.CodeGuardianApp`.

Version: 1.1.0
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog
from typing import Callable, List, Optional

import customtkinter as ctk

from gui.theme_manager      import ThemeManager
from gui.animation_manager  import AnimationManager
from gui.asset_helper       import get_asset_path
from core.language_manager  import LanguageManager
from core.sound_manager     import SoundManager
from core.alarm_center      import AlarmCenter, AlarmLevel
from scanner_engine.factory          import ScannerFactory
from scanner_engine.base             import BaseScanner, ScanResult, Severity
from scanner_engine.orchestrator     import ScanOrchestrator, ScanProgress


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
            from PIL import Image
            ico = get_asset_path("icon.png")
            if os.path.exists(ico):
                img = Image.open(ico).convert("RGBA").resize((16, 16))
                ctk_img = ctk.CTkImage(img, size=(16, 16))
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
        """Schedule an animated series of boot log messages.

        Each line is appended with a 300 ms inter-line delay using
        ``widget.after()`` so the animation runs on the main Tkinter
        thread without blocking the event loop.

        Args:
            widget: Any Tkinter widget whose ``after()`` method will be
                    used to schedule the deferred calls — typically the
                    parent page frame.

        Note:
            This method must be called *after* the widget is visible and
            the Tkinter event loop has started; otherwise ``after()`` calls
            may be silently dropped.
        """
        lines = [
            ("Oranovix Guardian v1.0 initializing...",  "info",  0),
            ("Loading security modules... ✓",            "ok",    300),
            ("Loading AI analyzer... ✓",                 "ok",    600),
            ("Loading language pack... ✓",               "ok",    900),
            ("Checking license... ✓",                    "ok",    1200),
            ("All systems ready. Welcome.",              "done",  1500),
        ]
        # Default-argument capture (m=msg, l=level) prevents the common
        # late-binding closure bug with loop variables.
        for msg, level, delay in lines:
            widget.after(delay, lambda m=msg, l=level: self.append(m, l))


# ── Drop Zone ─────────────────────────────────────────────────────────────

class DropZone(ctk.CTkFrame):
    """Animated file/folder selector with a dashed-border canvas area.

    Displays a :class:`tk.Canvas` with a dashed animated border and a
    centred hint label.  Below the canvas, two :class:`ctk.CTkButton`
    widgets let the user open a folder or file picker dialog.  When a
    path is chosen the :func:`on_path_selected` callback is invoked and
    the canvas label is updated to show the selected name.

    The dashed border is animated by
    :meth:`~gui.animation_manager.AnimationManager.animate_dash` which
    cycles the dash offset on a timer; the animation restarts whenever the
    canvas is resized (``<Configure>`` event).

    Args:
        master:            Parent widget.
        on_path_selected:  Callback receiving the selected absolute path
                           string whenever the user picks a file or folder.
        **kwargs:          Forwarded to :class:`ctk.CTkFrame`.
    """

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
        # Event used to stop the running dash animation before starting a new one
        self._dash_stop: Optional[threading.Event] = None
        self._build()

    def _build(self) -> None:
        """Create the animated canvas and the picker button row."""
        tm = ThemeManager()
        lm = LanguageManager()

        # Canvas renders the animated dashed border and the centred hint icon/label.
        # highlightthickness=0 removes Tk's default focus rectangle.
        self._cv = tk.Canvas(
            self,
            bg=tm.c("card"),
            highlightthickness=0,
            height=120,
        )
        self._cv.pack(fill="x", padx=0, pady=0)

        self._border_id = None
        # _label_id is set lazily by _on_resize; guarded in _set_path to
        # prevent itemconfig calls before the canvas has been drawn.
        self._label_id  = None
        # Redraw dashed border and restart dash animation on every resize
        self._cv.bind("<Configure>", self._on_resize)

        # Row of two picker buttons below the canvas
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=(0, 12))

        ctk.CTkButton(
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
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
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
        ).pack(side="left")

    def _on_resize(self, event) -> None:
        """Redraw canvas contents and restart the dash animation on resize.

        Called every time the canvas ``<Configure>`` event fires (initial
        layout, window resize, or theme rebuild).  Clears all existing
        canvas items, redraws the dashed border rectangle and the centred
        icon/label, then starts a fresh dash animation — stopping any
        previously running one first.

        Args:
            event: Tkinter configure event providing ``width`` and ``height``.
        """
        tm = ThemeManager()
        lm = LanguageManager()
        # Clear all previously drawn canvas items before redrawing
        self._cv.delete("all")
        w, h = event.width, event.height
        pad  = 12   # inset from canvas edges for the dashed border

        # Dashed rounded-rectangle border
        self._border_id = self._cv.create_rectangle(
            pad, pad, w - pad, h - pad,
            outline=tm.c("accent"),
            width=2,
            dash=(8, 6),     # 8px on, 6px off
        )

        # Centred folder emoji icon
        self._cv.create_text(
            w // 2, h // 2 - 20,
            text="📂",
            font=("Segoe UI", 22),
            fill=tm.c("text2"),
        )

        # Show the selected file/folder name when a path is set, otherwise
        # show the localised hint string.
        main_text = os.path.basename(self._path) if self._path else lm.t("drop_hint")
        self._label_id = self._cv.create_text(
            w // 2, h // 2 + 14,
            text=main_text,
            font=("Segoe UI", 10),
            fill=tm.c("accent") if self._path else tm.c("text2"),
        )

        # Stop the previous dash animation (if any) before starting a new one
        # to avoid multiple concurrent animation timers on the same rectangle.
        if self._dash_stop:
            self._dash_stop.set()
        self._dash_stop = AnimationManager.animate_dash(
            self._cv, self._cv, self._border_id
        )

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
                ("All files",     "*.*"),
            ],
        )
        if path:
            self._set_path(path)

    def _set_path(self, path: str) -> None:
        """Store the selected path, update the canvas label, and invoke the callback.

        Args:
            path: Absolute file or directory path chosen by the user.
        """
        self._path = path
        # Only update the canvas text item if the canvas has already been drawn
        # (_label_id is None until the first <Configure> event fires).
        if self._label_id is not None:
            tm = ThemeManager()
            name = os.path.basename(path)
            self._cv.itemconfig(self._label_id, text=name, fill=tm.c("accent"))
        # Notify the parent page so it can update its own state
        self._on_path(path)

    def refresh_theme(self) -> None:
        """Re-apply theme colours to the canvas and redraw its content.

        Constructs a synthetic resize event from the current canvas
        dimensions and passes it to :meth:`_on_resize` to trigger a full
        canvas redraw with the new colour palette.
        """
        tm = ThemeManager()
        self.configure(fg_color=tm.c("card"), border_color=tm.c("border"))
        self._cv.configure(bg=tm.c("card"))
        # Synthesise a minimal event object with the required width/height attrs
        e = type("E", (), {"width": self._cv.winfo_width(),
                           "height": self._cv.winfo_height()})()
        self._on_resize(e)


# ── Scanner Page ──────────────────────────────────────────────────────────

class ScannerPage(ctk.CTkFrame):
    """Main scanner page that orchestrates the full scan workflow.

    Composes a :class:`DropZone` for path selection, a scan button with a
    pulse animation, a real-time :class:`ctk.CTkProgressBar`, and a
    :class:`LogConsole` for live output.

    Scan execution runs in a background ``daemon`` thread
    (:meth:`_run_scan`) to keep the UI responsive.  All UI updates from
    that thread are marshalled back to the main thread via ``self.after()``.
    Once the scan finishes, :meth:`_scan_done` is called on the main thread
    to update the progress bar, log a summary, display a toast notification,
    play a sound alert, and deliver the result to the application via the
    ``on_scan_complete`` callback.

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
        on_status: Callable[[str, str], None],
        alarm_center: Optional[AlarmCenter] = None,
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._alarm_center = alarm_center
        self._on_complete = on_scan_complete
        self._on_status   = on_status
        self._target: str  = ""
        self._scanning     = False
        # Event used to stop the scan-button pulse animation after the scan ends
        self._stop_pulse   = threading.Event()
        self._build()

    def _build(self) -> None:
        """Build all widgets: header with particle canvas, body, controls, and log."""
        tm = ThemeManager()
        lm = LanguageManager()
        # Event used to stop the particle background animation on teardown
        self._particle_stop: Optional[threading.Event] = None

        # ── Page header with particle background ──────────────────────
        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Particle canvas placed absolutely behind the header label so it
        # appears as an ambient animated background, not a separate widget.
        self._particle_cv = tk.Canvas(
            hdr, bg=tm.c("bg2"), highlightthickness=0, height=50,
        )
        self._particle_cv.place(relx=0, rely=0, relwidth=1, relheight=1)

        ctk.CTkLabel(
            hdr,
            # Fall back to the literal "Scanner" string if the translation key
            # is missing (t() returns the key itself when no entry is found).
            text=f"  🔍  {lm.t('nav_scanner') if lm.t('nav_scanner') != 'nav_scanner' else 'Scanner'}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"),
            fg_color="transparent",
            anchor="w",
        ).pack(side="left", padx=16, fill="y")

        # Defer particle start by 300 ms so the header is fully laid out
        # and has valid pixel dimensions before the animation begins.
        def _start_particles():
            self._particle_stop = AnimationManager.particle_bg(
                self, self._particle_cv, dot_count=20,
            )
        self.after(300, _start_particles)

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
        lm = LanguageManager()
        self._log.clear()
        self._log.append(f"Target set: {path}", "ok")

        # Detect language and report
        scanners = ScannerFactory.scanners_for_target(path)
        lang_names = ", ".join(s.language.value for s in scanners) or "Unknown"
        engine_names = ", ".join(s.name for s in scanners) or "N/A"
        count = self._collect_scannable_files(path)
        self._log.append(
            f"{lm.t('detected_language')} {lang_names}  |  "
            f"{lm.t('scan_engine')} {engine_names}",
            "info",
        )
        if count:
            self._log.append(f"Found {count} {lm.t('files_found')}.", "info")
        else:
            self._log.append(lm.t("no_scannable_files"), "error")

    def _collect_scannable_files(self, target: str) -> int:
        """Return count of scannable files under target."""
        extensions = ScannerFactory.all_supported_extensions()
        return len(BaseScanner.collect_files(target, extensions))

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

        count = self._collect_scannable_files(self._target)
        if not count:
            AnimationManager.show_toast(
                self.winfo_toplevel(),
                f"\u26a0  {lm.t('no_scannable_files')}",
                color=ThemeManager().c("warning"),
            )
            return

        self._scanning = True
        self._stop_pulse.clear()
        tm = ThemeManager()

        AnimationManager.pulse_button(
            self, self._scan_btn,
            tm.c("accent"), tm.c("accent_h"),
            interval_ms=500,
            stop_event=self._stop_pulse,
        )
        self._scan_btn.configure(state="disabled", text=f"\u23f3  {lm.t('scanning')}")
        self._log.clear()
        self._log.append(f"Starting scan: {self._target}", "info")

        AnimationManager.animate_progress(self, self._progress, 0.15, duration_ms=300)

        thread = threading.Thread(
            target=self._run_scan,
            daemon=True,
        )
        thread.start()

    def _run_scan(self) -> None:
        """Background thread: run the orchestrator and hand the result to the UI."""
        try:
            result = ScanOrchestrator(on_progress=self._on_scan_progress).scan(self._target)
            self.after(0, self._scan_done, result, None)
        except Exception as exc:
            self.after(0, self._scan_done, None, str(exc))

    def _on_scan_progress(self, progress: ScanProgress) -> None:
        """Called from the scan thread; marshals the update onto the UI thread."""
        self.after(0, self._show_scan_progress, progress)

    def _show_scan_progress(self, progress: ScanProgress) -> None:
        self._log.append(progress.message, progress.level)
        AnimationManager.animate_progress(
            self, self._progress, progress.fraction, duration_ms=200
        )

    def _scan_done(
        self, result: Optional[ScanResult], error: Optional[str]
    ) -> None:
        self._scanning = False
        self._stop_pulse.set()
        lm = LanguageManager()
        tm = ThemeManager()

        AnimationManager.animate_progress(self, self._progress, 1.0, duration_ms=400)
        self._scan_btn.configure(
            state="normal",
            text=f"▶   {lm.t('start_scan')}",
            fg_color=tm.c("accent"),
        )
        self._prog_lbl.configure(text="")

        if error:
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
            for warning in result.engine_warnings:
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
