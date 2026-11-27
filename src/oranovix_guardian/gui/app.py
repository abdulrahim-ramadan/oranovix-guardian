"""
Root application window for Oranovix Guardian.

This module defines :class:`CodeGuardianApp`, the single
:class:`customtkinter.CTk` root window that owns the entire widget tree.
The main window builds the active page first. Sidebar navigation creates
each additional page on demand and reuses it on subsequent visits.

Theme and language changes are handled through the observer pattern
implemented in :class:`~gui.theme_manager.ThemeManager` and
:class:`~core.language_manager.LanguageManager`.  Any change triggers a
full UI rebuild so that every widget reflects the new palette or locale.

Window frame: the main window keeps the native frame, so the taskbar
button, minimize/maximize/close, Snap layouts, Win+Arrow keys and edge
resizing are the system's own. On Windows the frame is colored to match
the theme (:mod:`gui.window_frame`). Closing the window runs
:meth:`CodeGuardianApp._on_close`.

Version: 1.1.0
"""
from __future__ import annotations

from collections import deque
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, SimpleQueue
import tkinter as tk
from typing import TYPE_CHECKING, Any, Optional

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.theme_manager     import ThemeManager
from oranovix_guardian.gui.title_bar         import CustomTitleBar
from oranovix_guardian.gui.sidebar           import Sidebar
from oranovix_guardian.gui.status_bar        import StatusBar
from oranovix_guardian.gui.window_frame      import apply_frame_theme

if TYPE_CHECKING:
    from oranovix_guardian.core.scan_job import ScanJob
    from oranovix_guardian.live_defense.controller import LiveDefenseController, LiveDefenseState
    from oranovix_guardian.threat_intel.hub import HubState, ThreatIntelHub
    from oranovix_guardian.log_sentinel.controller import LogSentinelController
    from oranovix_guardian.log_sentinel.controller import SentinelState as LogSentinelState
# gui.pages and scanner_engine are imported lazily inside methods
# to keep module import independent of page construction


_log = logging.getLogger(__name__)


class CodeGuardianApp(ctk.CTk):
    """Root application window for Oranovix Guardian.

    Responsibilities:
        - Apply the theme and build the first page when Tk is ready.
        - Maintain a page registry (``_pages``) and route sidebar navigation
          requests to the correct :class:`ctk.CTkFrame` page.
        - Relay completed scan results from :class:`~gui.pages.ScannerPage`
          to :class:`~gui.pages.ResultsPage` and persist them via
          :class:`~core.scan_history.ScanHistory`.
        - React to theme and language observer events by scheduling a full
          UI rebuild on the main thread.
    """

    # Default window dimensions in pixels
    APP_WIDTH  = 1140
    APP_HEIGHT = 740

    # The frame color is set by gui.window_frame; CTk's own version hides
    # and re-shows the window to apply it.
    _deactivate_windows_window_header_manipulation = True

    def __init__(self, instance: Optional[Any] = None) -> None:
        """Initialise the application.

        The constructor follows a strict ordering requirement:
        ``ctk.set_appearance_mode`` and ``ctk.set_default_color_theme``
        must be called *before* ``super().__init__()`` so that
        CustomTkinter creates all internal widgets with the correct
        palette from the start.

        Args:
            instance: The single-instance guard of this process, released
                when the window is closed.
        """
        # Apply CTk appearance BEFORE super().__init__() so that the
        # underlying Tk engine initialises with the correct color scheme.
        tm = ThemeManager()
        ctk.set_appearance_mode("dark" if tm.is_dark else "light")
        ctk.set_default_color_theme("blue")

        super().__init__()
        # A second start finds this window by its title to bring it forward.
        self.title("Oranovix Guardian")

        self._tm: ThemeManager  = tm
        self._lm: LanguageManager = LanguageManager()
        # Track which page is currently visible so it can be restored after
        # a theme/language rebuild.
        self._current_page:  str          = "scanner"
        self._scan_result:   Optional[object] = None
        self._live_defense:  Optional[LiveDefenseController] = None
        self._threat_hub:    Optional[ThreatIntelHub] = None
        self._log_sentinel:  Optional[LogSentinelController] = None
        self._feed_report_shown: Optional[object] = None
        self._instance = instance
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Register observers so theme/language changes trigger a rebuild.
        # These registrations persist across UI rebuilds because the
        # manager singletons live for the entire process lifetime.
        self._tm.add_observer(self._on_theme_changed)
        self._lm.add_observer(self._on_lang_changed)

        # Reveal the window once its first page is ready.
        self.withdraw()
        self._setup_geometry()
        # Child dialogs inherit the application icon.
        self._set_icon()

        self._pages: dict = {}
        self._scan_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="CodeScan")
        self._scan_job: Optional[ScanJob] = None
        self._scan_pending_review = False
        self._closing = False
        self._state_jobs = deque()
        self._state_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="MonitorState")
        self._history_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ScanHistory")
        self.after_idle(self._show_main)

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _setup_geometry(self) -> None:
        """Set the window size and centre it on the primary monitor.

        ``update_idletasks()`` is called before reading screen dimensions
        so that Tk has processed any pending geometry requests and
        ``winfo_screenwidth`` / ``winfo_screenheight`` return accurate
        values.
        """
        self.geometry(f"{self.APP_WIDTH}x{self.APP_HEIGHT}")
        self.minsize(880, 580)
        # Flush pending geometry requests before querying screen size.
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        # Calculate top-left corner so the window appears centred.
        x  = (sw - self.APP_WIDTH)  // 2
        y  = (sh - self.APP_HEIGHT) // 2
        self.geometry(f"{self.APP_WIDTH}x{self.APP_HEIGHT}+{x}+{y}")

    def _set_icon(self) -> None:
        """Set ``assets/icon.ico`` as the default icon of every window.

        The call is wrapped in a try/except because ``iconbitmap`` raises
        on some platforms (e.g. Linux without the required Tk extension)
        and the icon is purely cosmetic.
        """
        from oranovix_guardian.gui.asset_helper import get_asset_path
        ico = get_asset_path("icon.ico")
        if os.path.exists(ico):
            try:
                self.iconbitmap(default=ico)
            except Exception:
                pass

    def _show_main(self) -> None:
        """Show the initial page, then schedule monitor startup."""
        if self._closing:
            return
        self._build_ui()
        self.deiconify()
        self._apply_frame_theme()
        self.after(300, self._watch_storage_problems)
        self.after(400, self._offer_resumes)
        self.after(900, self._start_threat_feed)

    def _apply_frame_theme(self) -> None:
        """Color the native frame to match the current theme (Windows only)."""
        tm = ThemeManager()
        try:
            self.update_idletasks()
        except tk.TclError:
            return
        apply_frame_theme(self, dark=tm.is_dark, caption=tm.c("bg2"), text=tm.c("text"))

    def _watch_storage_problems(self) -> None:
        """A write that fails (settings, history, rules) is shown once, not swallowed."""
        from oranovix_guardian.core.storage_problems import StorageProblems
        problems = SimpleQueue()
        StorageProblems.set_listener(problems.put)

        def poll():
            try:
                problem = problems.get_nowait()
            except Empty:
                pass
            else:
                self._show_storage_problem(problem)
            self.after(300, poll)

        poll()

    def _show_storage_problem(self, problem) -> None:
        from tkinter import messagebox
        from oranovix_guardian.core.app_paths import AppPaths
        lm = LanguageManager()
        what_key = "storage_what_" + problem.what.replace(" ", "_")
        what = lm.t(what_key)
        text = lm.t(
            "storage_write_failed",
            what=problem.what if what == what_key else what,
            path=problem.path, reason=problem.reason, folder=str(AppPaths.data_dir()),
        )
        try:
            self._status_bar.set_status(lm.t("storage_write_failed_title"), "error")
        except tk.TclError:
            pass
        messagebox.showwarning(lm.t("storage_write_failed_title"), text, parent=self)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Construct the full widget hierarchy for the main window.

        Called once from :meth:`_show_main` and again after every
        theme/language rebuild.  The layout is:
        ``title bar → separator → [sidebar | separator | content] → status bar``.

        ``lm.pack_side`` returns ``"right"`` for RTL languages (Arabic)
        so the sidebar automatically flips to the correct side.
        """
        tm = ThemeManager()
        lm = LanguageManager()
        self.configure(fg_color=tm.c("bg"))

        # Header under the native title bar: logo, name, language, theme
        self._title_bar = CustomTitleBar(
            self,
            window=self,
            on_theme_toggle=self._toggle_theme,
            on_lang_change=self._change_lang,
        )
        self._title_bar.pack(fill="x")

        # 1-pixel horizontal separator between title bar and body
        ctk.CTkFrame(
            self, height=1, fg_color=tm.c("border"), corner_radius=0
        ).pack(fill="x")

        # Body = sidebar + content area, laid out side by side
        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True)

        # Sidebar packs to the primary side (left for LTR, right for RTL)
        self._sidebar = Sidebar(body, on_navigate=self._navigate)
        self._sidebar.pack(side=lm.pack_side, fill="y")

        # 1-pixel vertical separator between sidebar and content
        ctk.CTkFrame(
            body, width=1, fg_color=tm.c("border"), corner_radius=0
        ).pack(side=lm.pack_side, fill="y")

        # Content area expands to fill all remaining space
        self._content = ctk.CTkFrame(body, fg_color=tm.c("bg"), corner_radius=0)
        self._content.pack(side=lm.opposite_side, fill="both", expand=True)

        # Status bar anchored to the bottom of the root window
        self._status_bar = StatusBar(self)
        self._status_bar.pack(fill="x", side="bottom")

        from oranovix_guardian.gui.scan_activity import ScanActivity

        self._scan_activity = ScanActivity(self, before=self._status_bar)
        if self._scan_pending_review:
            self._show_scan_ready()

        # Create the active page and register the others for navigation.
        self._pages = {}
        self._build_pages()
        self._navigate(self._current_page)

    def _build_pages(self) -> None:
        """Register page constructors and connect shared monitor state."""
        from oranovix_guardian.gui.pages import (
            ScannerPage, ResultsPage, ReportsPage, SettingsPage, LiveDefensePage,
            ThreatFeedPage, ProjectsPage, LogSentinelPage,
        )

        args = dict(master=self._content)

        if getattr(self, "_alarm_center", None) is None:
            from oranovix_guardian.gui.alarm_channels import build_alarm_center
            self._alarm_center = build_alarm_center(self)

        controller = self._live_defense_controller()
        sentinel = self._log_sentinel_controller()
        hub = self._threat_intel_hub()
        self._page_factories = {
            "scanner": lambda: ScannerPage(**args, on_scan_complete=self._on_scan_complete, on_scan_start=self._start_code_scan,
                                            on_scan_waiting=self._set_scan_waiting,
                                            on_status=self._status_bar.set_status, alarm_center=self._alarm_center),
            "dashboard": lambda: ResultsPage(**args, on_status=self._status_bar.set_status, on_navigate=self._navigate),
            "live_defense": lambda: LiveDefensePage(**args, controller=controller, on_status=self._status_bar.set_status,
                                                    on_scan_result=self._on_scan_complete),
            "log_sentinel": lambda: LogSentinelPage(**args, controller=sentinel, on_status=self._status_bar.set_status),
            "threat_feed": lambda: ThreatFeedPage(**args, hub=hub),
            "projects": lambda: ProjectsPage(**args, hub=hub, on_scan=self._scan_project, on_status=self._status_bar.set_status,
                                            on_open_feed=lambda: self._navigate("threat_feed")),
            "reports": lambda: ReportsPage(**args),
            "settings": lambda: SettingsPage(**args, on_theme_toggle=self._toggle_theme,
                                             on_lang_change=self._change_lang, threat_hub=hub),
        }
        self._status_bar.set_monitoring(controller.is_running)
        self._status_bar.set_watching_logs(sentinel.is_running)
        self._sidebar.set_badge("threat_feed", hub.store.unread_for_you())
        sentinel.notify()

    # ------------------------------------------------------------------
    # Live Defense
    # ------------------------------------------------------------------

    def _read_monitor_state(self, read, deliver) -> None:
        """Keep notification order, including individual alarm and sample events."""
        if self._closing:
            return
        self._state_jobs.append((self._state_worker.submit(read), deliver))
        if len(self._state_jobs) == 1:
            self.after(20, self._deliver_monitor_state)

    def _deliver_monitor_state(self) -> None:
        if self._closing:
            return
        future, deliver = self._state_jobs[0]
        if future.done():
            try:
                deliver(future.result())
            except Exception as exc:
                self._status_bar.set_status(str(exc), "error")
            self._state_jobs.popleft()
        if self._state_jobs:
            self.after(20, self._deliver_monitor_state)

    def _live_defense_controller(self) -> LiveDefenseController:
        """The controller outlives UI rebuilds, so a running monitor keeps running."""
        if self._live_defense is None:
            from oranovix_guardian.live_defense.controller import LiveDefenseController
            self._live_defense = LiveDefenseController(
                read_state=self._read_monitor_state,
                dispatch=lambda fn: self.after(0, fn),
                alarm_center=self._alarm_center,
            )
            self._live_defense.add_listener(self._on_live_defense_state)
        return self._live_defense

    def _on_live_defense_state(self, state: LiveDefenseState) -> None:
        from oranovix_guardian.gui.pages.live_defense_page import toast_new_events
        try:
            self._status_bar.set_monitoring(state.running)
            toast_new_events(self, state)
        except tk.TclError:
            pass                # status bar is being rebuilt

    def _offer_resumes(self) -> None:
        """One question after the other: two dialogs must not open at once."""
        if self._closing:
            return
        self._offer_live_defense_resume()
        self._offer_log_sentinel_resume()

    def _offer_live_defense_resume(self) -> None:
        from oranovix_guardian.gui.confirm_dialog import ConfirmDialog
        controller = self._live_defense_controller()
        root = controller.resume_candidate()
        if not root:
            return
        lm = LanguageManager()
        choice = ConfirmDialog.ask(
            self, lm.t("ld_resume_title"), lm.t("ld_resume_text", root=root),
            lm.t("ld_resume_yes"), lm.t("ld_resume_no"),
        )
        if not choice:
            controller.stop()
            return
        try:
            controller.start()
        except Exception as exc:
            self._status_bar.set_status(str(exc), "error")
        controller.notify()

    # ------------------------------------------------------------------
    # Log Sentinel
    # ------------------------------------------------------------------

    def _log_sentinel_controller(self) -> LogSentinelController:
        """Outlives UI rebuilds. Linked to Live Defense for planted files being served."""
        if self._log_sentinel is None:
            from oranovix_guardian.core.secret_store import SecretStore, SERVICE_NAME
            from oranovix_guardian.log_sentinel.controller import LogSentinelController
            from oranovix_guardian.log_sentinel.monitor import IntegrityPlantedPaths
            from oranovix_guardian.log_sentinel.privacy import HashKeyProvider
            live_defense = self._live_defense_controller()
            self._log_sentinel = LogSentinelController(
                read_state=self._read_monitor_state,
                dispatch=lambda fn: self.after(0, fn),
                alarm_center=self._alarm_center,
                key_store=SecretStore(SERVICE_NAME, HashKeyProvider.ENTRY),
                planted=IntegrityPlantedPaths(live_defense.open_events),
            )
            self._log_sentinel.add_listener(self._on_log_sentinel_state)
        return self._log_sentinel

    def _on_log_sentinel_state(self, state: LogSentinelState) -> None:
        try:
            self._status_bar.set_watching_logs(state.running)
            self._sidebar.set_badge("log_sentinel", state.open_alarming)
        except tk.TclError:
            pass                # being rebuilt

    def _offer_log_sentinel_resume(self) -> None:
        from oranovix_guardian.gui.confirm_dialog import ConfirmDialog
        controller = self._log_sentinel_controller()
        logs = controller.resume_candidate()
        if not logs:
            return
        lm = LanguageManager()
        if not ConfirmDialog.ask(
            self, lm.t("ls_resume_title"), lm.t("ls_resume_text", logs="\n".join(logs)),
            lm.t("ls_resume_yes"), lm.t("ls_resume_no"),
        ):
            controller.stop()
            controller.notify()
            return
        try:
            controller.start()
        except Exception as exc:
            self._status_bar.set_status(str(exc), "error")
        controller.notify()

    # ------------------------------------------------------------------
    # Threat Feed and My Projects
    # ------------------------------------------------------------------

    def _threat_intel_hub(self) -> ThreatIntelHub:
        """The hub outlives UI rebuilds, like the Live Defense controller."""
        if self._threat_hub is None:
            from oranovix_guardian.threat_intel.hub import ThreatIntelHub
            self._threat_hub = ThreatIntelHub(
                dispatch=lambda fn: self.after(0, fn),
                alarm_center=self._alarm_center,
            )
            self._threat_hub.add_listener(self._on_threat_feed_state)
        return self._threat_hub

    def _on_threat_feed_state(self, state: HubState) -> None:
        try:
            self._sidebar.set_badge("threat_feed", state.unread_for_you)
            report = state.last_report
            if report is not None and not state.refreshing and report is not self._feed_report_shown:
                self._feed_report_shown = report
                if not report.disabled:
                    self._show_feed_digest(len(report.failures))
        except tk.TclError:
            pass                # sidebar or status bar is being rebuilt

    def _show_feed_digest(self, failed_sources: int = 0) -> None:
        """Status bar: what is new since the last visit, and how many projects are exposed."""
        hub = self._threat_intel_hub()
        self._read_monitor_state(lambda: hub.digest(hub.session_since),
                                 lambda digest: self._display_digest(digest, failed_sources))

    def _display_digest(self, digest, failed_sources: int) -> None:
        text = digest.headline
        if failed_sources:
            text += "  ·  " + LanguageManager().t("tf_refresh_failed", count=failed_sources)
        level = "warn" if digest.exposed_count or failed_sources or not digest.checked else "info"
        self._status_bar.set_status(text, level)

    def _start_threat_feed(self) -> None:
        """First run: ask before anything is downloaded. Then show what is new."""
        from oranovix_guardian.gui.threat_feed_dialogs import FeedConsentDialog
        if self._closing:
            return
        hub = self._threat_intel_hub()
        if not hub.config().asked:
            hub.answer_first_run(bool(FeedConsentDialog.ask(self, hub.hosts())))
        hub.start()
        # With the feed on, the line is shown again when the first refresh is done.
        if hub.store.count():
            self._show_feed_digest()

    def _scan_project(self, path: str) -> None:
        """"Scan now" of a project: the normal scan, started on the scanner page."""
        self._navigate("scanner")
        self._pages["scanner"].scan_path(path)

    def _on_close(self) -> None:
        """Keep Tk dispatching callbacks while monitor threads stop."""
        if self._closing:
            return
        self._closing = True
        job = vars(self).get("_scan_job")
        if job is not None:
            job.cancel()
        self.withdraw()
        self._begin_shutdown()

    def _monitor_action_pending(self) -> bool:
        return any(getattr(page, "action_pending", False) for page in self._pages.values())

    def _begin_shutdown(self) -> None:
        if self._monitor_action_pending():
            self.after(30, self._begin_shutdown)
            return
        self._shutdown_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="Stopping")
        self._shutdown_jobs = [self._shutdown_pool.submit(self._stop_service, service, None)
                               for service in self._services()]
        self._shutdown_jobs.append(self._shutdown_pool.submit(self._stop_workers))
        self._shutdown_pool.shutdown(wait=False)
        self.after(20, self._finish_close)

    def _services(self):
        return [service for service in (self._live_defense, self._threat_hub, self._log_sentinel)
                if service is not None]

    @staticmethod
    def _stop_service(service, timeout: Optional[float] = 2) -> None:
        try:
            service.shutdown(timeout=timeout)
        except Exception:
            _log.exception("%s did not shut down cleanly", type(service).__name__)

    def _stop_workers(self) -> None:
        for name in ("_history_worker", "_state_worker", "_scan_worker"):
            worker = vars(self).get(name)
            if worker is not None:
                worker.shutdown(wait=True, cancel_futures=name == "_state_worker")

    def _finish_close(self) -> None:
        if any(not job.done() for job in self._shutdown_jobs):
            self.after(20, self._finish_close)
            return
        try:
            self.destroy()
        finally:
            if self._instance is not None:
                self._instance.release()
                self._instance = None

    def destroy(self) -> None:
        """Direct destruction also stops services when called outside the close handler."""
        jobs = vars(self).get("_shutdown_jobs")
        if jobs is not None and any(not job.done() for job in jobs):
            return
        try:
            if jobs is None:
                self._closing = True
                job = vars(self).get("_scan_job")
                if job is not None:
                    job.cancel()
                for service in self._services():
                    self._stop_service(service)
                self._stop_workers()
        finally:
            super().destroy()

    def _navigate(self, page_id: str) -> None:
        """Show the requested page and hide all others.

        Args:
            page_id: Logical page identifier (``"scanner"``, ``"dashboard"``,
                ``"results"``, ``"live_defense"``, ``"reports"``, or ``"settings"``).
                Unknown IDs fall back to ``"scanner"``.
        """
        page_id = "dashboard" if page_id == "results" else page_id
        if page_id == "dashboard" and self._scan_pending_review:
            self._scan_pending_review = False
            self._scan_activity.pack_forget()
        if page_id not in self._page_factories:
            page_id = "scanner"
        if page_id not in self._pages:
            page = self._page_factories[page_id]()
            self._pages[page_id] = page
            if page_id == "scanner" and getattr(self, "_saved_target", ""):
                page._drop_zone._set_path(self._saved_target)
                self._saved_target = ""
        page = self._pages[page_id]
        if page_id == "dashboard" and self._scan_result is not None and page._result is not self._scan_result:
            page.display(self._scan_result)
        previous = self._pages.get(self._current_page)
        if previous is not None and previous is not page:
            if hasattr(previous, "on_hidden"):
                previous.on_hidden()
            previous.pack_forget()
        if page:
            page.pack(fill="both", expand=True)
            if hasattr(page, "on_shown"):
                page.on_shown()
        self._current_page = page_id

        # Both "results" and "dashboard" map to the same sidebar button
        sidebar_id = "dashboard" if page_id in ("results", "dashboard") else page_id
        self._sidebar.set_active(sidebar_id)

    # ------------------------------------------------------------------
    # Scan result handling
    # ------------------------------------------------------------------

    def _set_scan_waiting(self, waiting: bool) -> None:
        if waiting:
            self._scan_activity.show_progress(self._cancel_code_scan)
        elif self._scan_pending_review:
            self._show_scan_ready()
        else:
            self._scan_activity.pack_forget()

    def _start_code_scan(self, target: str) -> None:
        from oranovix_guardian.core.scan_job import ScanJob

        self._scan_job = ScanJob(self._scan_worker, target)
        self._scan_pending_review = False
        self._scan_activity.show_progress(self._cancel_code_scan)
        self.after(25, self._poll_code_scan)

    def _cancel_code_scan(self) -> None:
        if self._scan_job is None:
            self._pages["scanner"].cancel_pending_scan()
            self._status_bar.set_status(LanguageManager().t("scan_cancelled"))
            return
        self._scan_job.cancel()
        self._scan_activity.show_cancelling()

    def _poll_code_scan(self) -> None:
        job = self._scan_job
        if self._closing or job is None:
            return
        page = self._pages["scanner"]
        for update in job.updates(limit=12):
            page.show_scan_progress(update)
            if not job.cancelling:
                self._scan_activity.update_progress(update.stage.value, update.fraction)
        if not job.ready:
            self.after(25, self._poll_code_scan)
            return

        self._scan_job = None
        self._scan_activity.pack_forget()
        try:
            result = job.result()
        except Exception as exc:
            page._scan_done(None, str(exc))
        else:
            page._scan_done(result, None)

    def _show_scan_ready(self) -> None:
        warnings = getattr(self._scan_result, "engine_warnings", ())
        self._scan_activity.show_ready(len(warnings), lambda: self._navigate("dashboard"))

    def _on_scan_complete(self, result) -> None:
        """Handle a finished scan delivered by :class:`~gui.pages.ScannerPage`.

        Persists the result to the SQLite history database, navigates to
        the results/dashboard page, and calls ``display()`` to populate it.

        Args:
            result: A :class:`~scanner_engine.base.ScanResult` instance
                returned by the active scanner engine.
        """
        if self._closing:
            return
        def persist():
            from oranovix_guardian.core.scan_history import ScanHistory
            ScanHistory().save_scan(result)

        saved = self._history_worker.submit(persist)
        # The scan may have seen an upgraded dependency: match the feed again.
        # Preserve the active page when the user has moved away from the scanner.
        self._scan_result = result
        if self._current_page == "scanner":
            self._navigate("results")
        elif self._current_page == "dashboard":
            self._pages["dashboard"].display(result)
        else:
            self._scan_pending_review = True
            self._show_scan_ready()
        self._refresh_after_save(saved)

    def _refresh_after_save(self, saved) -> None:
        if not saved.done():
            self.after(80, self._refresh_after_save, saved)
            return
        if self._closing:
            return
        saved.result()
        if self._threat_hub is not None:
            self._threat_hub.recheck_async()
        dashboard = self._pages.get("dashboard")
        if dashboard:
            dashboard.refresh_history()

    # ------------------------------------------------------------------
    # Theme toggle
    # ------------------------------------------------------------------

    def _toggle_theme(self) -> None:
        """Flip the active colour theme between dark and light.

        Delegates to :class:`~gui.theme_manager.ThemeManager`, which
        then notifies all registered observers — including
        :meth:`_on_theme_changed` — via the observer pattern.
        """
        self._tm.toggle()   # triggers _on_theme_changed via observer

    def _on_theme_changed(self) -> None:
        """Observer callback fired by ThemeManager after a theme flip.

        The rebuild is scheduled 10 ms in the future via ``after()`` to
        ensure it runs on the main Tkinter thread even when the toggle
        originates from a non-GUI event.
        """
        self.after(10, self._rebuild_ui)
        self.after(10, self._apply_frame_theme)

    def _rebuild_ui(self) -> None:
        """Coalesce appearance changes and keep active tasks attached until delivery."""
        if self._closing:
            return
        pending = getattr(self, "_pending_rebuild", None)
        if pending:
            self.after_cancel(pending)
        scanner = self._pages.get("scanner")
        dashboard = self._pages.get("dashboard")
        if (self._monitor_action_pending() or self._scan_job is not None or (scanner and scanner._start_requested)
                or (dashboard and dashboard._export_job is not None)):
            self._pending_rebuild = self.after(150, self._rebuild_ui)
            return
        self._pending_rebuild = None
        if scanner:
            self._saved_target = scanner._target
        for child in self.winfo_children():
            child.destroy()
        self._build_ui()

    # ------------------------------------------------------------------
    # Language change
    # ------------------------------------------------------------------

    def _change_lang(self, display_name: str) -> None:
        """Switch the active language by its human-readable display name.

        Args:
            display_name: The display name shown in the language dropdown,
                e.g. ``"Deutsch"`` or ``"العربية"``.
        """
        self._lm.set_language_by_display(display_name)

    def _on_lang_changed(self) -> None:
        """Observer callback fired by LanguageManager after a language switch.

        Schedules a full UI rebuild on the main thread so all translatable
        strings and layout-direction properties are refreshed.
        """
        self.after(10, self._rebuild_ui)
