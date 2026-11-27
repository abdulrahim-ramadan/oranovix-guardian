"""
My Projects page: the user's projects with their last scan, the state of
their site and the feed items that affect them.

Adding and removing is instant; matching against the feed and the site
check run in the hub's background thread and the table is redrawn when
the hub reports back.
"""
from __future__ import annotations

from typing import Callable, List, Optional, Tuple

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.animation_manager import AnimationManager
from oranovix_guardian.gui.confirm_dialog import ConfirmDialog
from oranovix_guardian.gui.page_updates import PageRead, RowPager
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.gui.threat_feed_dialogs import ProjectDialog
from oranovix_guardian.threat_intel.exposure import ExposureReport, ProjectExposure
from oranovix_guardian.threat_intel.hub import HubState, ProjectRow, ThreatIntelHub
from oranovix_guardian.threat_intel.projects import ProjectError
from oranovix_guardian.threat_intel.uptime import UptimeEventKind


class ProjectsPage(ctk.CTkFrame):
    """Sidebar page "My Projects"."""

    def __init__(
        self,
        master,
        hub: ThreatIntelHub,
        on_status: Callable[[str, str], None],
        on_scan: Callable[[str], None],
        on_open_feed: Callable[[], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._hub = hub
        self._on_status = on_status
        self._on_scan = on_scan
        self._on_open_feed = on_open_feed
        self._shown_key: Tuple[object, ...] = ()
        self._visible = False
        self._reads = PageRead(self, lambda message: on_status(message, "error"))
        self._pager = RowPager()
        self._build()
        hub.add_listener(self._show_state)

    def destroy(self) -> None:
        self._reads.close()
        self._hub.remove_listener(self._show_state)
        super().destroy()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side, far = lm.pack_side, lm.opposite_side

        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text=f"  \U0001f4c1  {lm.t('proj_title')}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        ).pack(side=side, padx=16, fill="y")
        ctk.CTkButton(
            hdr, text=f"+  {lm.t('proj_add')}", height=28, corner_radius=6, width=140,
            font=ctk.CTkFont(size=10), fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", command=self._add,
        ).pack(side=far, padx=16)

        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=12)
        self._notice = ctk.CTkLabel(
            body, text=f"⚠  {lm.t('proj_site_notice')}  {lm.t('proj_uptime_hint')}",
            font=ctk.CTkFont(size=10), text_color=tm.c("text3"), fg_color="transparent",
            anchor=lm.text_anchor, wraplength=780, justify=lm.text_justify,
        )
        self._notice.pack(fill="x", pady=(0, 8))
        # Filled only while a project is exposed.
        self._exposed = ctk.CTkFrame(body, fg_color=tm.c("card"), corner_radius=8,
                                     border_width=1, border_color=tm.c("critical"))
        self._table = ctk.CTkScrollableFrame(body, fg_color=tm.c("bg"), corner_radius=0)
        self._table.pack(fill="both", expand=True)

    @staticmethod
    def columns() -> List[Tuple[str, int]]:
        lm = LanguageManager()
        return [
            (lm.t("proj_col_project"), 180), (lm.t("proj_col_scan"), 130),
            (lm.t("proj_col_site"), 200), (lm.t("proj_col_response"), 70),
            (lm.t("proj_col_feed"), 100),
        ]

    # ------------------------------------------------------------------
    # State from the hub
    # ------------------------------------------------------------------

    def _show_state(self, state: HubState) -> None:
        event = state.uptime_event
        if event is not None:
            lm = LanguageManager()
            tm = ThemeManager()
            down = event.kind is UptimeEventKind.DOWN
            if not down:        # "down" is announced by the alarm center already
                AnimationManager.show_toast(
                    self.winfo_toplevel(), lm.t("proj_site_up_toast", project=event.project),
                    color=tm.c("success"),
                )
            self._on_status(
                lm.t("proj_site_down_toast" if down else "proj_site_up_toast", project=event.project),
                "error" if down else "ok",
            )
        self._render()

    def _render(self, force: bool = False) -> None:
        if not self._visible:
            return

        def read():
            exposure = self._hub.exposure()
            return self._hub.project_rows(exposure), exposure

        self._reads.request(read, lambda snapshot: self._display(snapshot[0], snapshot[1], force))

    def on_hidden(self) -> None:
        self._visible = False

    def on_shown(self) -> None:
        self._visible = True
        self._render()

    def _display(self, rows, exposure, force: bool) -> None:
        if not self._visible:
            return
        exposed = self.exposed_lines(exposure)
        key = (tuple(rows), tuple(exposed))
        if key == self._shown_key and not force:
            return
        self._shown_key = key
        for child in self._table.winfo_children():
            child.destroy()

        tm = ThemeManager()
        lm = LanguageManager()
        side = lm.pack_side
        self._render_exposed(exposed)
        if not rows:
            ctk.CTkLabel(self._table, text=lm.t("proj_empty"), font=ctk.CTkFont(size=12),
                         text_color=tm.c("text3")).pack(pady=28)
            return
        header = ctk.CTkFrame(self._table, fg_color=tm.c("bg2"), corner_radius=4)
        header.pack(fill="x", pady=(0, 2))
        for text, width in self.columns():
            ctk.CTkLabel(header, text=text, width=width, anchor=lm.text_anchor,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("text3")).pack(side=side, padx=4)
        self._pager.show(self._table, rows, self._project_row)

    def _render_exposed(self, lines: List[str]) -> None:
        """The panel above the table: one line per exposed project."""
        tm = ThemeManager()
        lm = LanguageManager()
        for child in self._exposed.winfo_children():
            child.destroy()
        if not lines:
            self._exposed.pack_forget()
            return
        ctk.CTkLabel(
            self._exposed, text=f"⚠  {lm.t('proj_exposed_title')}",
            font=ctk.CTkFont(size=12, weight="bold"), text_color=tm.c("critical"),
            fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x", padx=12, pady=(8, 2))
        ctk.CTkLabel(
            self._exposed, text="\n".join(lines), font=ctk.CTkFont(size=10),
            text_color=tm.c("text"), fg_color="transparent", anchor=lm.text_anchor,
            wraplength=760, justify=lm.text_justify,
        ).pack(fill="x", padx=12, pady=(0, 8))
        if not self._exposed.winfo_ismapped():
            # "after" the notice: the scrollable table is not a pack slave itself.
            self._exposed.pack(fill="x", pady=(0, 8), after=self._notice)

    @classmethod
    def exposed_lines(cls, report: ExposureReport) -> List[str]:
        return [cls.exposed_line(entry) for entry in report.exposed]

    @staticmethod
    def exposed_line(entry: ProjectExposure) -> str:
        """The worst open item of a project and the first fixed version that is known."""
        lm = LanguageManager()
        worst = entry.worst
        if worst is None:
            return ""
        fix = entry.first_fix
        package = lm.t(
            "proj_exposed_fix" if fix else "proj_exposed_no_fix",
            package=worst.match.package, version=worst.match.version, fix=fix,
        )
        line = lm.t("proj_exposed_line", project=entry.project.name,
                    item=worst.stored.item.title, package=package)
        if len(entry.open) > 1:
            line += "  " + lm.t("proj_exposed_more", count=len(entry.open) - 1)
        return line

    def _project_row(self, parent, row: ProjectRow) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side, far = lm.pack_side, lm.opposite_side
        widths = [width for _, width in self.columns()]

        frame = ctk.CTkFrame(parent, fg_color=tm.c("card"), corner_radius=6,
                             border_width=1, border_color=tm.c("border"))
        frame.pack(fill="x", pady=2)

        name = ctk.CTkFrame(frame, fg_color="transparent", width=widths[0])
        name.pack(side=side, padx=4, pady=6)
        ctk.CTkLabel(name, text=row.project.name, width=widths[0], anchor=lm.text_anchor,
                     font=ctk.CTkFont(size=12, weight="bold"), text_color=tm.c("text")).pack()
        ctk.CTkLabel(name, text=self.path_text(row), width=widths[0], anchor=lm.text_anchor,
                     wraplength=widths[0], justify=lm.text_justify,
                     font=ctk.CTkFont(size=9), text_color=tm.c("text3")).pack()

        scan_text, scan_level = self.scan_text(row)
        site_text, site_level = self.site_text(row)
        feed_text, feed_level = self.feed_text(row)
        cells = [
            (scan_text, widths[1], scan_level), (site_text, widths[2], site_level),
            (self.response_text(row), widths[3], "text2"),
        ]
        for text, width, level in cells:
            ctk.CTkLabel(frame, text=text, width=width, anchor=lm.text_anchor, wraplength=width,
                         justify=lm.text_justify, font=ctk.CTkFont(size=10),
                         text_color=tm.c(level)).pack(side=side, padx=4)

        feed = ctk.CTkFrame(frame, fg_color="transparent", width=widths[4])
        feed.pack(side=side, padx=4)
        if row.affecting:
            ctk.CTkButton(
                feed, text=feed_text, width=widths[4], height=22, corner_radius=4,
                font=ctk.CTkFont(size=9, weight="bold"), fg_color=tm.c("critical"),
                hover_color=tm.c("accent_h"), text_color="#ffffff", command=self._on_open_feed,
            ).pack()
        else:
            ctk.CTkLabel(feed, text=feed_text, width=widths[4], anchor=lm.text_anchor,
                         font=ctk.CTkFont(size=10), text_color=tm.c(feed_level)).pack()
        if row.affecting and row.accepted:
            ctk.CTkLabel(feed, text=self.accepted_text(row), width=widths[4], height=14,
                         font=ctk.CTkFont(size=9), text_color=tm.c("text3")).pack()

        ctk.CTkButton(
            frame, text=lm.t("proj_remove"), width=70, height=22, corner_radius=4,
            font=ctk.CTkFont(size=9), fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), command=lambda n=row.project.name: self._remove(n),
        ).pack(side=far, padx=(2, 8))
        ctk.CTkButton(
            frame, text=lm.t("proj_scan_now"), width=80, height=22, corner_radius=4,
            font=ctk.CTkFont(size=9), fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", command=lambda p=row.project.path: self._on_scan(p),
        ).pack(side=far, padx=2)

    # ------------------------------------------------------------------
    # Cell texts (theme colour key as second value)
    # ------------------------------------------------------------------

    @staticmethod
    def path_text(row: ProjectRow) -> str:
        lm = LanguageManager()
        return f"{row.project.path}\n{lm.t('proj_packages', count=row.packages)}"

    @staticmethod
    def scan_text(row: ProjectRow) -> Tuple[str, str]:
        lm = LanguageManager()
        scan = row.scan
        if scan is None:
            return lm.t("proj_never_scanned"), "text3"
        date = scan.scanned_at.strftime("%Y-%m-%d %H:%M") if scan.scanned_at else ""
        text = lm.t("proj_scan_summary", date=date, critical=scan.critical, high=scan.high)
        level = "critical" if scan.critical else "warning" if scan.high else "success"
        return text, level

    @staticmethod
    def site_text(row: ProjectRow) -> Tuple[str, str]:
        lm = LanguageManager()
        if not row.project.site_url:
            return lm.t("proj_site_none"), "text3"
        check = row.check
        if check is None:
            return f"{row.project.site_url}\n{lm.t('proj_site_pending')}", "text3"
        if row.down_since is not None:
            since = row.down_since.astimezone().strftime("%Y-%m-%d %H:%M")
            return f"{row.project.site_url}\n{lm.t('proj_site_down', time=since)}", "error"
        if not check.ok:
            return f"{row.project.site_url}\n{lm.t('proj_site_failing', error=check.error)}", "warning"
        return f"{row.project.site_url}\n{lm.t('proj_site_up', status=check.status)}", "success"

    @staticmethod
    def response_text(row: ProjectRow) -> str:
        check = row.check
        if check is None or not check.ok:
            return "—"
        return LanguageManager().t("proj_ms", ms=check.response_ms)

    @staticmethod
    def feed_text(row: ProjectRow) -> Tuple[str, str]:
        lm = LanguageManager()
        if row.affecting:
            # Read or unread makes no difference: the project is exposed.
            return lm.t("proj_feed_affecting", count=row.affecting), "critical"
        if row.accepted:
            return lm.t("proj_feed_accepted", count=row.accepted), "text3"
        if not row.checked:
            return lm.t("proj_feed_unchecked"), "warning"
        return lm.t("proj_feed_clear"), "text3"

    @staticmethod
    def accepted_text(row: ProjectRow) -> str:
        return LanguageManager().t("proj_feed_accepted", count=row.accepted) if row.accepted else ""

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _add(self) -> None:
        added: List[Optional[str]] = []

        def validate(name: str, folder: str, site_url: str) -> str:
            try:
                project = self._hub.add_project(name, folder, site_url or None)
            except ProjectError as exc:
                return str(exc)
            added.append(project.site_url)
            return ""

        if ProjectDialog.ask(self, validate) is None:
            return
        lm = LanguageManager()
        if added and added[0]:
            self._on_status(lm.t("proj_site_notice"), "warn")
        self._render(force=True)

    def _remove(self, name: str) -> None:
        lm = LanguageManager()
        if not ConfirmDialog.ask(
            self, lm.t("proj_remove_title"), lm.t("proj_remove_text", name=name),
            lm.t("proj_remove"), lm.t("proj_cancel"),
        ):
            return
        self._hub.remove_project(name)
        self._render(force=True)

    def refresh_theme(self) -> None:
        self.configure(fg_color=ThemeManager().c("bg"))
