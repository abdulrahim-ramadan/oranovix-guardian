"""
Root application window for Oranovix Guardian.

This module defines :class:`CodeGuardianApp`, the single
:class:`customtkinter.CTk` root window that owns the entire widget tree.
It follows a splash-first startup pattern: the OS title bar is suppressed
with ``overrideredirect(True)``, a :class:`~gui.splash_screen.SplashScreen`
is shown while heavy page modules are pre-loaded in a background thread,
and then the full UI (custom title bar, sidebar, content area, status bar)
is constructed and the window is revealed.

Navigation is sidebar-driven: each logical page is a :class:`ctk.CTkFrame`
sub-class that lives permanently inside the content area and is simply
shown or hidden via ``pack`` / ``pack_forget``.

Theme and language changes are handled through the observer pattern
implemented in :class:`~gui.theme_manager.ThemeManager` and
:class:`~core.language_manager.LanguageManager`.  Any change triggers a
full UI rebuild so that every widget reflects the new palette or locale.

Custom title bar notes (``overrideredirect=True``):
  - Window dragging is implemented via mouse-event bindings on the title bar.
  - Minimize / Maximise / Close buttons are rendered manually.
  - The Windows taskbar entry is restored via ``ctypes`` after the window
    is shown, because ``overrideredirect`` normally removes it.

Version: 1.1.0
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from typing import Optional

import customtkinter as ctk

# Project root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.language_manager import LanguageManager
from gui.theme_manager     import ThemeManager
from gui.animation_manager import AnimationManager
from gui.splash_screen     import SplashScreen
from gui.title_bar         import CustomTitleBar
from gui.sidebar           import Sidebar
from gui.status_bar        import StatusBar
# gui.pages and scanner_engine are imported lazily inside methods
# to keep startup fast (splash appears before heavy imports load)


class CodeGuardianApp(ctk.CTk):
    """Root application window for Oranovix Guardian.

    Responsibilities:
        - Bootstrap order: apply theme/color settings, hide window, show
          splash, pre-load heavy modules in background, build full UI.
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

    def __init__(self) -> None:
        """Initialise the application.

        The constructor follows a strict ordering requirement:
        ``ctk.set_appearance_mode`` and ``ctk.set_default_color_theme``
        must be called *before* ``super().__init__()`` so that
        CustomTkinter creates all internal widgets with the correct
        palette from the start.
        """
        # Apply CTk appearance BEFORE super().__init__() so that the
        # underlying Tk engine initialises with the correct color scheme.
        tm = ThemeManager()
        ctk.set_appearance_mode("dark" if tm.is_dark else "light")
        ctk.set_default_color_theme("blue")

        super().__init__()

        self._tm: ThemeManager  = tm
        self._lm: LanguageManager = LanguageManager()
        # Track which page is currently visible so it can be restored after
        # a theme/language rebuild.
        self._current_page:  str          = "scanner"
        self._scan_result:   Optional[object] = None
        # Preserve the API key string across UI rebuilds so the user does
        # not have to re-enter it every time they change the theme.
        self._saved_api_key: str          = ""

        # Register observers so theme/language changes trigger a rebuild.
        # These registrations persist across UI rebuilds because the
        # manager singletons live for the entire process lifetime.
        self._tm.add_observer(self._on_theme_changed)
        self._lm.add_observer(self._on_lang_changed)

        # Hide the main window before the splash is shown so the user
        # only ever sees the splash during startup.
        self.withdraw()
        self._apply_overrideredirect()

        # Pre-import heavy page modules in background during splash so
        # that _build_pages() runs quickly after the splash finishes.
        threading.Thread(target=self._preload_modules, daemon=True).start()

        splash = SplashScreen(self, on_done=self._show_main)

    @staticmethod
    def _preload_modules() -> None:
        """Import heavy modules in the background so they are cached by the
        time :meth:`_build_pages` runs after the splash screen finishes.

        Errors are silently swallowed here; if an import fails at this
        stage the user will see a proper error when the page is actually
        instantiated.
        """
        try:
            import gui.pages  # noqa: F401  – page widgets
            import scanner_engine.factory  # noqa: F401  – scanner back-ends
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _apply_overrideredirect(self) -> None:
        """Remove the OS-native title bar and set the initial geometry.

        ``overrideredirect(True)`` strips the platform's window
        decorations so the app can render its own custom title bar.  The
        taskbar entry is restored separately in
        :meth:`_restore_taskbar_entry` after the window becomes visible.
        """
        self.overrideredirect(True)
        self._setup_geometry()

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

    def _restore_taskbar_entry(self) -> None:
        """Ensure the custom-framed window appears in the Windows taskbar.

        ``overrideredirect(True)`` causes Windows to treat the window as a
        tool window (``WS_EX_TOOLWINDOW``), which hides it from the
        taskbar.  This method uses the Win32 API to strip that style flag
        and add ``WS_EX_APPWINDOW`` so the entry reappears.

        The call is a no-op on non-Windows platforms and silently ignores
        any ``ctypes`` errors so as not to crash the application on
        unusual Windows configurations.
        """
        if sys.platform != "win32":
            return
        try:
            import ctypes
            GWL_EXSTYLE      = -20           # index for extended window style
            WS_EX_APPWINDOW  = 0x00040000   # forces taskbar button
            WS_EX_TOOLWINDOW = 0x00000080   # hides taskbar button (applied by overrideredirect)
            SWP_NOMOVE       = 0x0002
            SWP_NOSIZE       = 0x0001
            SWP_NOZORDER     = 0x0004
            SWP_FRAMECHANGED = 0x0020       # instructs the OS to re-read the style
            # Use the tk window id directly — GetParent can return 0 on Win11
            hwnd = self.winfo_id()
            if not hwnd:
                return
            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            # Remove the tool-window bit and set the app-window bit.
            new   = (style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, new)
            # Apply style change without hiding the window
            ctypes.windll.user32.SetWindowPos(
                hwnd, 0, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
            )
        except Exception:
            pass

    def _set_icon(self) -> None:
        """Set the window icon from ``assets/icon.ico``.

        The call is wrapped in a try/except because ``iconbitmap`` raises
        on some platforms (e.g. Linux without the required Tk extension)
        and the icon is purely cosmetic.
        """
        from gui.asset_helper import get_asset_path
        ico = get_asset_path("icon.ico")
        if os.path.exists(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass

    def _show_main(self) -> None:
        """Build the full UI and reveal the main window.

        Called by :class:`~gui.splash_screen.SplashScreen` via the
        ``on_done`` callback once the splash animation has finished.
        The taskbar restoration is deferred by 100 ms to ensure the
        window handle is fully initialised before the Win32 call.
        """
        self._build_ui()
        self._set_icon()
        self.deiconify()
        # Small delay before patching the taskbar entry; the HWND must be
        # fully visible for SetWindowLongW to take effect reliably.
        self.after(100, self._restore_taskbar_entry)

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

        # Custom title bar (replaces the OS window chrome removed by overrideredirect)
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

        # Build all pages and reveal the last-active one
        self._pages: dict = {}
        self._build_pages()
        self._navigate(self._current_page)

    def _build_pages(self) -> None:
        """Instantiate every page widget inside ``self._content``.

        Pages are stored in ``self._pages`` by logical ID.  The
        ``"results"`` key is an alias for ``"dashboard"`` so that both
        IDs resolve to the same :class:`~gui.pages.ResultsPage` instance.
        """
        from gui.pages import ScannerPage, ResultsPage, ReportsPage, SettingsPage

        args = dict(master=self._content)

        self._pages["scanner"] = ScannerPage(
            **args,
            on_scan_complete=self._on_scan_complete,
            on_status=self._status_bar.set_status,
        )
        self._pages["dashboard"] = ResultsPage(
            **args,
            on_status=self._status_bar.set_status,
            on_navigate=self._navigate,
        )
        # "results" is a navigation alias that points to the same widget
        self._pages["results"] = self._pages["dashboard"]
        self._pages["reports"]  = ReportsPage(**args)
        self._pages["settings"] = SettingsPage(
            **args,
            on_theme_toggle=self._toggle_theme,
            on_lang_change=self._change_lang,
        )

    def _navigate(self, page_id: str) -> None:
        """Show the requested page and hide all others.

        Args:
            page_id: Logical page identifier (``"scanner"``, ``"dashboard"``,
                ``"results"``, ``"reports"``, or ``"settings"``).
                Unknown IDs fall back to ``"scanner"``.
        """
        # Unpack every page widget to clear the content area
        for p in set(self._pages.values()):
            p.pack_forget()

        # Resolve the requested page; fall back to scanner if not found
        page = self._pages.get(page_id) or self._pages.get("scanner")
        if page:
            page.pack(fill="both", expand=True)
        self._current_page = page_id

        # Both "results" and "dashboard" map to the same sidebar button
        sidebar_id = "dashboard" if page_id in ("results", "dashboard") else page_id
        self._sidebar.set_active(sidebar_id)

    # ------------------------------------------------------------------
    # Scan result handling
    # ------------------------------------------------------------------

    def _on_scan_complete(self, result) -> None:
        """Handle a finished scan delivered by :class:`~gui.pages.ScannerPage`.

        Persists the result to the SQLite history database, navigates to
        the results/dashboard page, and calls ``display()`` to populate it.

        Args:
            result: A :class:`~scanner_engine.base.ScanResult` instance
                returned by the active scanner engine.
        """
        self._scan_result = result
        # Persist to history database (failures are silent — the scan
        # result is still shown even if persistence fails)
        try:
            from core.scan_history import ScanHistory
            ScanHistory().save_scan(result)
        except Exception:
            pass
        # Navigate to the results page first, then populate it with data
        self._navigate("results")
        self._pages["dashboard"].display(result)

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

    def _rebuild_ui(self) -> None:
        """Destroy all widgets and reconstruct the UI with the new theme/language.

        A translucent overlay frame is placed over the entire window for
        60 ms before the rebuild to create a brief flash transition that
        softens the abrupt widget destruction.  Any transient state (API
        key text) is saved before destruction and will be restored once
        the new SettingsPage is created.
        """
        # Preserve the API key entered by the user before destroying widgets
        if hasattr(self, "_api_entry"):
            self._saved_api_key = self._api_entry.get()

        # Overlay covers the window to create a smooth visual transition
        tm = ThemeManager()
        overlay = tk.Frame(
            self,
            bg=tm.c("bg"),
        )
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.title_bar_title = "Oranovix Guardian"

        def _do_rebuild() -> None:
            # Remove the overlay and destroy every child widget, then
            # rebuild the entire UI from scratch with the new palette.
            overlay.destroy()
            for child in self.winfo_children():
                child.destroy()
            self._build_ui()

        # Short delay ensures the overlay is painted before destruction begins
        self.after(60, _do_rebuild)

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
