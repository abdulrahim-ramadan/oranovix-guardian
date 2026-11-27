"""
Threat Feed page: security news and exploited vulnerabilities, with the
items that concern the user's projects first.

The page only shows what the local store holds. Refreshing runs in the
hub's background thread; the page is redrawn from the state the hub
sends, so the window never waits for the network.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.gui.threat_feed_dialogs import FeedConsentDialog, LinkOpener, RiskDialog
from oranovix_guardian.threat_intel.fetcher import CertificateError
from oranovix_guardian.threat_intel.hub import HubState, ThreatIntelHub
from oranovix_guardian.threat_intel.models import (
    AcceptedRisk,
    ProjectMatch,
    Relevance,
    RiskKey,
    SourceHealth,
    StoredItem,
    project_key,
)
from oranovix_guardian.threat_intel.sources import SourceConfig


class ThreatFeedPage(ctk.CTkFrame):
    """Sidebar page "Threat Feed" with the tabs For you, All and Sources."""

    TABS = ("for_you", "all", "sources")
    BATCH = 20          # rows built per step; a long list must not freeze the window
    # Tk cannot scroll a frame higher than 32767 pixels. A page ends before that.
    MAX_LIST_HEIGHT = 26000

    _BADGE_COLORS = {
        Relevance.AFFECTS_YOU: "critical",
        Relevance.POSSIBLE: "warning",
        Relevance.GENERAL: "text3",
    }

    def __init__(
        self,
        master,
        hub: ThreatIntelHub,
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._hub = hub
        self._tab = "for_you"
        # First row of the page shown in each tab; "Show more" turns the page.
        self._offsets: Dict[str, int] = {"for_you": 0, "all": 0}
        self._state: Optional[HubState] = None
        self._shown_key: Tuple[object, ...] = ()
        self._shown_rows = 0
        self._fill_run = 0          # changes whenever the list is rebuilt
        self._show_read = True      # read guesses; affecting items are always shown
        self._risks: Dict[RiskKey, AcceptedRisk] = {}
        self._scaling = ctk.ScalingTracker.get_widget_scaling(self)
        self._fonts: Dict[Tuple[int, bool], tkfont.Font] = {}
        self._build()
        hub.add_listener(self._show_state)
        self._show_state(hub.state())

    def destroy(self) -> None:
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
            hdr, text=f"  \U0001f4e1  {lm.t('tf_title')}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        ).pack(side=side, padx=16, fill="y")
        self._refresh_btn = self._button(hdr, lm.t("tf_refresh"), self._refresh)
        self._refresh_btn.pack(side=far, padx=16)
        self._updated_lbl = ctk.CTkLabel(
            hdr, text="", font=ctk.CTkFont(size=10), text_color=tm.c("text3"),
            fg_color="transparent",
        )
        self._updated_lbl.pack(side=far, padx=(0, 4))

        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        self._digest_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=12, weight="bold"), text_color=tm.c("text"),
            fg_color="transparent", anchor=lm.text_anchor,
        )
        self._digest_lbl.pack(fill="x", pady=(0, 6))

        # Shown while the feed is switched off.
        self._off_bar = ctk.CTkFrame(body, fg_color=tm.c("card"), corner_radius=8,
                                     border_width=1, border_color=tm.c("border"))
        ctk.CTkLabel(
            self._off_bar, text=lm.t("tf_off_banner"), font=ctk.CTkFont(size=11),
            text_color=tm.c("warning"), fg_color="transparent", anchor=lm.text_anchor,
            wraplength=560, justify=lm.text_justify,
        ).pack(side=side, padx=12, pady=8, fill="x", expand=True)
        self._button(self._off_bar, lm.t("tf_switch_on"), self._switch_on).pack(side=far, padx=12)

        self._note_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=10), text_color=tm.c("warning"),
            fg_color="transparent", anchor=lm.text_anchor, wraplength=760, justify=lm.text_justify,
        )

        bar = ctk.CTkFrame(body, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 6))
        self._bar = bar
        self._tab_btns: Dict[str, ctk.CTkButton] = {}
        for key in self.TABS:
            btn = ctk.CTkButton(
                bar, text=lm.t(f"tf_tab_{key}"), width=110, height=26, corner_radius=6,
                font=ctk.CTkFont(size=10, weight="bold"), hover_color=tm.c("accent_h"),
                command=lambda k=key: self._set_tab(k),
            )
            btn.pack(side=side, padx=2)
            self._tab_btns[key] = btn
        self._read_all_btn = self._button(bar, lm.t("tf_mark_all_read"), self._mark_all_read, primary=False)
        self._read_all_btn.pack(side=far)
        self._show_read_switch = ctk.CTkSwitch(
            bar, text=lm.t("tf_show_read"), font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
            progress_color=tm.c("accent"), command=self._toggle_show_read,
        )
        self._show_read_switch.select()
        self._show_read_switch.pack(side=far, padx=12)

        self._list = ctk.CTkScrollableFrame(body, fg_color=tm.c("bg"), corner_radius=0)
        self._list.pack(fill="both", expand=True)
        self._paint_tabs()

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
    # State from the hub
    # ------------------------------------------------------------------

    def _show_state(self, state: HubState) -> None:
        lm = LanguageManager()
        self._state = state

        self._updated_lbl.configure(text=self.updated_text(state))
        self._refresh_btn.configure(
            text=lm.t("tf_refreshing") if state.refreshing else lm.t("tf_refresh"),
            state="disabled" if state.refreshing else "normal",
        )
        self._digest_lbl.configure(text=self._hub.digest(self._hub.session_since).headline)

        if state.enabled:
            self._off_bar.pack_forget()
        elif not self._off_bar.winfo_ismapped():
            self._off_bar.pack(fill="x", pady=(0, 8), before=self._bar)

        note = self.note_text(state, has_projects=bool(self._hub.registry.list()))
        self._note_lbl.configure(text=note)
        if note and not self._note_lbl.winfo_ismapped():
            self._note_lbl.pack(fill="x", pady=(0, 6), before=self._bar)
        elif not note:
            self._note_lbl.pack_forget()

        self._render()

    @staticmethod
    def updated_text(state: HubState) -> str:
        lm = LanguageManager()
        if state.last_success is None:
            return lm.t("tf_never_updated")
        local = state.last_success.astimezone()
        text = lm.t("tf_last_update", time=local.strftime("%Y-%m-%d %H:%M"))
        report = state.last_report
        if report is not None and report.offline:
            text = f"{lm.t('tf_offline')}  {text}"
        return text

    @staticmethod
    def note_text(state: HubState, has_projects: bool) -> str:
        """Hints above the list: no projects yet, or no vulnerability database."""
        lm = LanguageManager()
        notes = []
        if not has_projects:
            notes.append(lm.t("tf_no_projects_hint"))
        elif not state.database_ready:
            notes.append(lm.t("tf_db_missing"))
        return "\n".join(notes)

    # ------------------------------------------------------------------
    # Tabs and list
    # ------------------------------------------------------------------

    def _set_tab(self, tab: str) -> None:
        self._tab = tab
        self._paint_tabs()
        self._render(force=True)

    def _paint_tabs(self) -> None:
        tm = ThemeManager()
        for key, btn in self._tab_btns.items():
            active = key == self._tab
            btn.configure(
                fg_color=tm.c("accent") if active else tm.c("bg3"),
                text_color="#ffffff" if active else tm.c("text2"),
            )

    def _render(self, force: bool = False) -> None:
        if self._tab == "sources":
            health = self._hub.source_health()
            key: Tuple[object, ...] = ("sources", tuple((c, h) for c, h in health))
            if key == self._shown_key and not force:
                return
            self._shown_key = key
            self._clear()
            self._read_all_btn.configure(state="disabled")
            self._render_sources(health)
            return

        for_you = self._tab == "for_you"
        state = self._state or self._hub.state()
        items, total, key = self._list_content(state)
        if key == self._shown_key and not force:
            return
        self._shown_key = key
        self._clear()
        self._read_all_btn.configure(
            state="normal" if any(not i.read for i in items) else "disabled"
        )
        self._show_read_switch.configure(state="normal" if for_you else "disabled")

        tm = ThemeManager()
        offset = self._offsets[self._tab]
        if not items and not offset:
            empty = self.empty_text(state, for_you)
            ctk.CTkLabel(self._list, text=empty, font=ctk.CTkFont(size=12),
                         text_color=tm.c("text3"), wraplength=700).pack(pady=28)
            return
        if offset:
            self._button(
                self._list, LanguageManager().t("tf_show_newest"), self._show_newest, primary=False
            ).pack(pady=(0, 8))
        self._fill(self._fill_run, items, 0, total - offset)

    def _list_content(self, state: HubState) -> Tuple[List[StoredItem], int, Tuple[object, ...]]:
        """Items of the current page, the size of the whole tab, and a key for "unchanged"."""
        for_you = self._tab == "for_you"
        offset = self._offsets[self._tab]
        items = self._hub.items(for_you, self._hub.PAGE_SIZE, offset, show_read=self._show_read)
        total = self._hub.item_count(for_you, show_read=self._show_read)
        self._risks = self._hub.accepted_risks()
        key = (self._tab, offset, total, state.check, self._show_read,
               tuple((i.id, i.read, i.relevance, i.matches) for i in items),
               tuple(sorted((k, r.reason) for k, r in self._risks.items())))
        return items, total, key

    def _fill(self, run: int, items: Sequence[StoredItem], start: int, available: int) -> None:
        """Build the next rows, then come back for the rest.

        Each batch sits in its own frame that is shown when complete, so the
        scroll area is laid out once per batch and not once per widget.
        *available* is how many items the tab has from this page on.
        """
        try:
            if run != self._fill_run or not self.winfo_exists():
                return
            self._list.update_idletasks()
            full = start > 0 and self._list.winfo_reqheight() > self.MAX_LIST_HEIGHT
            end = start if full else min(start + self.BATCH, len(items))
            batch = ctk.CTkFrame(self._list, fg_color="transparent")
            for item in items[start:end]:
                self._item_row(batch, item)
            last = full or end >= len(items)
            if last and available > end:
                self._button(
                    batch, LanguageManager().t("tf_show_more", count=available - end),
                    self._show_more, primary=False,
                ).pack(pady=8)
            batch.pack(fill="x")
            self._shown_rows = end
            if not last:
                self.after(1, self._fill, run, items, end, available)
        except tk.TclError:
            pass        # the page was rebuilt meanwhile

    def _show_more(self) -> None:
        """The next, older page."""
        self._offsets[self._tab] += self._shown_rows
        self._turn_page()

    def _show_newest(self) -> None:
        self._offsets[self._tab] = 0
        self._turn_page()

    def _turn_page(self) -> None:
        self._render(force=True)
        self._list._parent_canvas.yview_moveto(0)

    @staticmethod
    def empty_text(state: HubState, for_you: bool) -> str:
        """Text of an empty tab. "Nothing affects you" only when that was really checked."""
        lm = LanguageManager()
        if not for_you:
            return lm.t("tf_empty_all")
        return state.not_checked_text(lm.t) or lm.t("tf_empty_for_you")

    def _clear(self) -> None:
        self._fill_run += 1         # a fill that is still running stops
        self._shown_rows = 0
        for child in self._list.winfo_children():
            child.destroy()

    def _item_row(self, master, stored: StoredItem) -> None:
        """One card. Only the card itself is a CTk widget; its content is plain Tk.

        A CTk widget costs several milliseconds to draw, and a page has up
        to 200 rows of about ten widgets.
        """
        tm = ThemeManager()
        lm = LanguageManager()
        # Tk wants literals; the language manager hands out plain strings.
        side: Any = lm.pack_side
        far: Any = lm.opposite_side
        justify: Any = lm.text_justify
        anchor: Any = lm.text_anchor
        item = stored.item
        px = self._px
        card = tm.c("card")

        row = ctk.CTkFrame(master, fg_color=card, corner_radius=8,
                           border_width=1, border_color=tm.c("border"))
        row.pack(fill="x", pady=3, padx=(0, 6))

        top = tk.Frame(row, bg=card)
        top.pack(fill="x", padx=px(10), pady=(px(8), 0))
        self._tag(top, self.badge_text(stored.relevance),
                  tm.c(self._BADGE_COLORS[stored.relevance])).pack(side=side)
        if item.is_known_exploited:
            self._tag(top, lm.t("tf_exploited"), tm.c("high")).pack(side=side, padx=px(4))
        tk.Label(
            top, text=self.meta_text(stored), font=self._font(10), bg=card, fg=tm.c("text3"),
        ).pack(side=side, padx=px(8))

        if not stored.read:
            self._row_button(
                top, lm.t("tf_mark_read"), lambda i=stored.id: self._mark_read(i),
                tm.c("bg3"), tm.c("hover"), tm.c("text2"),
            ).pack(side=far, padx=(px(4), 0))
        if stored.relevance is Relevance.AFFECTS_YOU:
            if self.open_matches(stored, self._risks):
                self._row_button(
                    top, lm.t("tf_accept_risk"), lambda s=stored: self._accept_risk(s),
                    tm.c("bg3"), tm.c("hover"), tm.c("text2"),
                ).pack(side=far, padx=(px(4), 0))
            else:
                self._row_button(
                    top, lm.t("tf_withdraw_risk"), lambda s=stored: self._withdraw_risk(s),
                    tm.c("bg3"), tm.c("hover"), tm.c("text2"),
                ).pack(side=far, padx=(px(4), 0))
        self._row_button(
            top, lm.t("tf_open_link"), lambda s=stored: self._open(s),
            tm.c("accent"), tm.c("accent_h"), "#ffffff",
        ).pack(side=far)

        lines = self.match_lines(stored, risks=self._risks)
        accepted = self.accepted_lines(stored, self._risks)
        tk.Label(
            row, text=item.title, wraplength=px(720), justify=justify, anchor=anchor,
            font=self._font(12, bold=not stored.read), bg=card,
            fg=tm.c("text2") if stored.read else tm.c("text"),
        ).pack(fill="x", padx=px(10), pady=(px(4), 0 if lines or accepted else px(9)))

        if accepted:
            tk.Label(
                row, text="\n".join(accepted), wraplength=px(720), justify=justify, anchor=anchor,
                font=self._font(10), bg=card, fg=tm.c("text3"),
            ).pack(fill="x", padx=px(10), pady=(px(2), 0 if lines else px(9)))
        if lines:
            # Read or not: an open match keeps its colour.
            color = tm.c("critical") if stored.relevance is Relevance.AFFECTS_YOU else tm.c("warning")
            tk.Label(
                row, text="\n".join(lines), wraplength=px(720), justify=justify,
                anchor=anchor, font=self._font(10, bold=True), bg=card, fg=color,
            ).pack(fill="x", padx=px(10), pady=(px(2), px(9)))

    def _px(self, value: float) -> int:
        """Plain Tk widgets do not follow the display scaling on their own."""
        return round(value * self._scaling)

    def _font(self, size: int, bold: bool = False) -> tkfont.Font:
        key = (size, bold)
        if key not in self._fonts:
            self._fonts[key] = tkfont.Font(
                family=ctk.CTkFont(size=size).cget("family"), size=-self._px(size),
                weight="bold" if bold else "normal",
            )
        return self._fonts[key]

    def _tag(self, master, text: str, color: str) -> tk.Label:
        return tk.Label(
            master, text=text, bg=color, fg="#ffffff", font=self._font(9, bold=True),
            padx=self._px(6), pady=self._px(2),
        )

    def _row_button(
        self, master, text: str, command: Callable[[], None], color: str, hover: str, text_color: str,
    ) -> tk.Label:
        button = tk.Label(
            master, text=text, bg=color, fg=text_color, font=self._font(9), cursor="hand2",
            padx=self._px(12), pady=self._px(4),
        )
        button.bind("<Button-1>", lambda _event: command())
        button.bind("<Enter>", lambda _event: button.configure(bg=hover))
        button.bind("<Leave>", lambda _event: button.configure(bg=color))
        return button

    @staticmethod
    def badge_text(relevance: Relevance) -> str:
        return LanguageManager().t(f"tf_badge_{relevance.value}")

    @staticmethod
    def meta_text(stored: StoredItem) -> str:
        """Source and date, e.g. ``CISA KEV  ·  2026-11-10``."""
        published = stored.item.published
        if published is None:
            return stored.item.source
        return f"{stored.item.source}  ·  {published.astimezone().strftime('%Y-%m-%d')}"

    @staticmethod
    def open_matches(
        stored: StoredItem, risks: Optional[Mapping[RiskKey, AcceptedRisk]] = None,
    ) -> List[ProjectMatch]:
        """Matches whose risk was not accepted."""
        risks = risks or {}
        return [
            match for match in stored.matches
            if (stored.id, project_key(match.project_path)) not in risks
        ]

    @classmethod
    def accepted_lines(
        cls, stored: StoredItem, risks: Optional[Mapping[RiskKey, AcceptedRisk]] = None,
    ) -> List[str]:
        """Matches whose risk was accepted, with the reason. Shown in grey."""
        lm = LanguageManager()
        lines = []
        for match in stored.matches:
            risk = (risks or {}).get((stored.id, project_key(match.project_path)))
            if risk is not None:
                lines.append(f"{cls._match_line(match)}  ·  {lm.t('tf_risk_accepted', reason=risk.reason)}")
        return lines

    @classmethod
    def match_lines(
        cls, stored: StoredItem, limit: int = 4,
        risks: Optional[Mapping[RiskKey, AcceptedRisk]] = None,
    ) -> List[str]:
        """Which project and package matched; a guess is labelled as one.

        Matches with an accepted risk are not in here, see ``accepted_lines``.
        """
        lm = LanguageManager()
        matches = cls.open_matches(stored, risks)
        lines = [cls._match_line(match) for match in matches[:limit]]
        hidden = len(matches) - limit
        if hidden > 0:
            lines.append(lm.t("tf_more_matches", count=hidden))
        if lines and stored.relevance is Relevance.POSSIBLE:
            lines.insert(0, lm.t("tf_possible_hint"))
        return lines

    @staticmethod
    def _match_line(match: ProjectMatch) -> str:
        lm = LanguageManager()
        line = lm.t(
            "tf_match_line", project=match.project, package=match.package, version=match.version
        ).rstrip()
        if match.advisory_id:
            line += f" ({match.advisory_id})"
        if match.fixed_version:
            line += "  →  " + lm.t("tf_match_fix", version=match.fixed_version)
        elif match.confirmed:
            # A confirmed hit without a fix must not look like a line that was cut off.
            line += "  →  " + lm.t("tf_match_no_fix")
        return line

    def _render_sources(self, health: Sequence[Tuple[SourceConfig, SourceHealth]]) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        side = lm.pack_side
        columns = [
            (lm.t("tf_src_name"), 150), (lm.t("tf_src_host"), 190), (lm.t("tf_src_language"), 70),
            (lm.t("tf_src_last_success"), 130), (lm.t("tf_src_status"), 220),
        ]
        header = ctk.CTkFrame(self._list, fg_color=tm.c("bg2"), corner_radius=4)
        header.pack(fill="x", pady=(0, 2))
        for text, width in columns:
            ctk.CTkLabel(header, text=text, width=width, anchor=lm.text_anchor,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=tm.c("text3")).pack(side=side, padx=4)
        for config, state in health:
            status, level = self.source_status(config, state)
            success = (
                state.last_success.astimezone().strftime("%Y-%m-%d %H:%M")
                if state.last_success else lm.t("tf_src_never")
            )
            row = ctk.CTkFrame(self._list, fg_color=tm.c("card"), corner_radius=4)
            row.pack(fill="x", pady=1)
            cells = [
                (config.name, 150, tm.c("text")), (config.host, 190, tm.c("text2")),
                (config.language.upper(), 70, tm.c("text2")), (success, 130, tm.c("text2")),
                (status, 220, tm.c(level)),
            ]
            for text, width, color in cells:
                ctk.CTkLabel(row, text=text, width=width, anchor=lm.text_anchor, wraplength=width,
                             justify=lm.text_justify, font=ctk.CTkFont(size=10),
                             text_color=color).pack(side=side, padx=4, pady=4)

    @staticmethod
    def source_status(config: SourceConfig, health: SourceHealth) -> Tuple[str, str]:
        """Status text of a source and the theme colour for it."""
        lm = LanguageManager()
        if not config.enabled:
            return lm.t("tf_src_disabled"), "text3"
        if health.ok:
            return lm.t("tf_src_ok"), "success"
        if CertificateError.is_text_of(health.last_error):
            detail = CertificateError.detail_of(health.last_error)
            return f"{lm.t('tf_src_cert_untrusted')}\n{detail}", "error"
        if health.last_error:
            return health.last_error, "error"
        return lm.t("tf_src_never"), "text3"

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if not self._hub.config().enabled:
            self._switch_on()
            return
        self._hub.refresh_async()

    def _switch_on(self) -> None:
        """The same question as on first run; nothing is contacted without a yes."""
        if FeedConsentDialog.ask(self, self._hub.hosts()):
            self._hub.set_enabled(True)
        else:
            self._hub.set_enabled(False)

    def _mark_read(self, item_id: str) -> None:
        self._hub.store.mark_read([item_id])
        self._hub.notify()

    def _toggle_show_read(self) -> None:
        self._show_read = bool(self._show_read_switch.get())
        self._offsets["for_you"] = 0
        self._render(force=True)

    def _accept_risk(self, stored: StoredItem) -> None:
        projects = sorted({match.project for match in self.open_matches(stored, self._risks)})
        reason = RiskDialog.ask(self, stored.item.title, projects)
        if reason:
            self._hub.accept_risk(stored.id, reason)

    def _withdraw_risk(self, stored: StoredItem) -> None:
        self._hub.withdraw_risk(stored.id)

    def _mark_all_read(self) -> None:
        relevances = [Relevance.AFFECTS_YOU, Relevance.POSSIBLE] if self._tab == "for_you" else None
        self._hub.store.mark_all_read(relevances)
        self._hub.notify()

    def _open(self, stored: StoredItem) -> None:
        if LinkOpener.open(self, stored.item.url) and self.read_when_opened(stored):
            self._mark_read(stored.id)

    @staticmethod
    def read_when_opened(stored: StoredItem) -> bool:
        """Opening the link of a news item counts as reading it.

        An item that affects a project stays unread, and in the badge,
        until the user presses "Mark read" or "Mark all read".
        """
        return stored.relevance is not Relevance.AFFECTS_YOU

    def on_shown(self) -> None:
        """The user opened the page: from now on "new" means newer than this visit.

        Only the visit time is stored. No item becomes read by this.
        """
        self._hub.store.set_last_visit()

    def refresh_theme(self) -> None:
        self.configure(fg_color=ThemeManager().c("bg"))
