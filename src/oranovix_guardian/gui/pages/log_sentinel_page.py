"""
Log Sentinel page: the watched logs, the settings, and the attacks found.

The monitor runs in its own thread inside the controller; this page only
shows the state the controller sends and hands actions back to it.
Slow actions (start, stop, analysing a file) run in a worker thread.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.gui.page_updates import PageRead, RowPager
from oranovix_guardian.gui.scroll_canvas import ScrollCanvas
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.log_sentinel.controller import LogSentinelController, SentinelState
from oranovix_guardian.log_sentinel.events import EventState, SecurityEvent
from oranovix_guardian.log_sentinel.parsers import LogFormat
from oranovix_guardian.log_sentinel.store import Attacker, EventFilter
from oranovix_guardian.scanner_engine.base import Severity


class LogSentinelPage(ctk.CTkFrame):
    """Sidebar page "Log Sentinel"."""

    MAX_ROWS = 200
    SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    _SEVERITY_COLORS = {
        Severity.CRITICAL: "critical", Severity.HIGH: "high", Severity.MEDIUM: "warning", Severity.LOW: "text3",
    }

    def __init__(
        self,
        master,
        controller: LogSentinelController,
        on_status: Callable[[str, str], None],
        **kwargs,
    ) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._controller = controller
        self._on_status = on_status
        self._severity: Optional[Severity] = None
        self._rule: str = ""
        self._open_only = True
        self._settings_open = not controller.options().logs
        self._shown_key: Tuple[object, ...] = ()
        self._fonts: Dict[Tuple[int, bool], tkfont.Font] = {}
        self._scaling = ctk.ScalingTracker.get_widget_scaling(self)
        self._visible = False
        self._reads = PageRead(self, lambda message: on_status(message, "error"))
        self._pager = RowPager()
        self._actions = ThreadPoolExecutor(max_workers=1, thread_name_prefix="SentinelAction")
        self._pending_actions = 0
        self._build()
        controller.add_listener(self._show_state)
        controller.notify()

    def destroy(self) -> None:
        self._actions.shutdown(wait=False)
        self._reads.close()
        self._controller.remove_listener(self._show_state)
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
            hdr, text=f"  \U0001f9fe  {lm.t('ls_title')}",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        ).pack(side=side, padx=16, fill="y")
        self._start_btn = self._button(hdr, lm.t("ls_start"), self._toggle_running)
        self._start_btn.pack(side=far, padx=(4, 16))
        self._sample_btn = self._button(hdr, lm.t("ls_analyse_sample"), self._analyse_sample, primary=False)
        self._sample_btn.pack(side=far, padx=4)
        self._settings_btn = self._button(hdr, lm.t("ls_settings"), self._toggle_settings, primary=False)
        self._settings_btn.pack(side=far, padx=4)
        self._status_lbl = ctk.CTkLabel(hdr, text="", font=ctk.CTkFont(size=10), text_color=tm.c("text3"))
        self._status_lbl.pack(side=far, padx=8)

        body = ctk.CTkFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=10)
        self._body = body

        self._banner = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff",
            fg_color=tm.c("critical"), corner_radius=6, anchor=lm.text_anchor, height=34,
        )
        ctk.CTkLabel(
            body, text=lm.t("ls_detection_only"), font=ctk.CTkFont(size=10), text_color=tm.c("text3"),
            fg_color="transparent", anchor=lm.text_anchor,
        ).pack(fill="x")
        self._settings_card = self._build_settings(body)

        bar = ctk.CTkFrame(body, fg_color="transparent")
        bar.pack(fill="x", pady=(8, 4))
        self._bar = bar
        self._severity_menu = ctk.CTkOptionMenu(
            bar, values=self.severity_choices(), width=150, height=26, font=ctk.CTkFont(size=10),
            fg_color=tm.c("bg3"), button_color=tm.c("bg3"), text_color=tm.c("text"),
            command=self._set_severity,
        )
        self._severity_menu.pack(side=side, padx=(0, 4))
        self._rule_menu = ctk.CTkOptionMenu(
            bar, values=[lm.t("ls_filter_all_rules")], width=220, height=26, font=ctk.CTkFont(size=10),
            fg_color=tm.c("bg3"), button_color=tm.c("bg3"), text_color=tm.c("text"),
            command=self._set_rule,
        )
        self._rule_menu.pack(side=side, padx=4)
        self._open_switch = ctk.CTkSwitch(
            bar, text=lm.t("ls_open_only"), font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
            progress_color=tm.c("accent"), command=self._toggle_open_only,
        )
        self._open_switch.select()
        self._open_switch.pack(side=side, padx=8)
        self._export_btn = self._button(bar, lm.t("ls_export_csv"), self._export_csv, primary=False)
        self._export_btn.pack(side=far)
        self._ack_all_btn = self._button(bar, lm.t("ls_ack_all"), self._acknowledge_all, primary=False)
        self._ack_all_btn.pack(side=far, padx=4)

        self._attackers_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=10), text_color=tm.c("text2"), fg_color="transparent",
            anchor=lm.text_anchor, justify=lm.text_justify, wraplength=860,
        )
        self._attackers_lbl.pack(fill="x", pady=(0, 4))

        scroll = ScrollCanvas(body, bg_color=tm.c("bg"))
        scroll.pack(fill="both", expand=True)
        self._list = scroll.inner

    def _build_settings(self, master) -> ctk.CTkFrame:
        tm = ThemeManager()
        lm = LanguageManager()
        side, far = lm.pack_side, lm.opposite_side
        options = self._controller.options()

        card = ctk.CTkFrame(master, fg_color=tm.c("card"), corner_radius=8, border_width=1,
                            border_color=tm.c("border"))
        self._logs_frame = ctk.CTkFrame(card, fg_color="transparent")
        self._logs_frame.pack(fill="x", padx=12, pady=(10, 4))

        add_row = ctk.CTkFrame(card, fg_color="transparent")
        add_row.pack(fill="x", padx=12, pady=(0, 6))
        self._format_menu = ctk.CTkOptionMenu(
            add_row, values=[lm.t(f"ls_format_{f.value}") for f in LogFormat], width=150, height=26,
            font=ctk.CTkFont(size=10), fg_color=tm.c("bg3"), button_color=tm.c("bg3"), text_color=tm.c("text"),
        )
        self._format_menu.pack(side=side)
        self._button(add_row, lm.t("ls_add_log"), self._add_log).pack(side=side, padx=6)

        grid = ctk.CTkFrame(card, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=4)
        self._interval = self._field(grid, lm.t("ls_interval"), str(options.interval), 80)
        self._retention = self._field(grid, lm.t("ls_retention"), str(options.retention_days), 80)
        self._proxies = self._field(grid, lm.t("ls_trusted_proxies"), ", ".join(options.trusted_proxies), 300,
                                    hint=lm.t("ls_trusted_hint"))
        self._allowlist = self._field(grid, lm.t("ls_allowlist"), ", ".join(options.allowlist), 300,
                                      hint=lm.t("ls_allowlist_hint"))

        privacy = ctk.CTkFrame(card, fg_color="transparent")
        privacy.pack(fill="x", padx=12, pady=(4, 0))
        self._full_ip_switch = ctk.CTkSwitch(
            privacy, text=lm.t("ls_keep_full"), font=ctk.CTkFont(size=11), text_color=tm.c("text"),
            progress_color=tm.c("accent"),
        )
        if options.keep_full_ips:
            self._full_ip_switch.select()
        self._full_ip_switch.pack(side=side)
        ctk.CTkLabel(
            card, text=lm.t("ls_dsgvo_note"), font=ctk.CTkFont(size=10), text_color=tm.c("text3"),
            fg_color="transparent", anchor=lm.text_anchor, justify=lm.text_justify, wraplength=820,
        ).pack(fill="x", padx=12, pady=(2, 6))
        save_row = ctk.CTkFrame(card, fg_color="transparent")
        save_row.pack(fill="x", padx=12, pady=(0, 10))
        self._button(save_row, lm.t("ls_save"), self._save_settings).pack(side=far)
        self._render_logs()
        return card

    def _field(self, master, label: str, value: str, width: int, hint: str = "") -> ctk.CTkEntry:
        tm = ThemeManager()
        lm = LanguageManager()
        row = ctk.CTkFrame(master, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=label, width=190, anchor=lm.text_anchor, font=ctk.CTkFont(size=11),
                     text_color=tm.c("text2")).pack(side=lm.pack_side)
        entry = ctk.CTkEntry(row, width=width, height=26, fg_color=tm.c("input_bg"),
                             border_color=tm.c("border"), text_color=tm.c("text"))
        entry.insert(0, value)
        entry.pack(side=lm.pack_side, padx=4)
        if hint:
            ctk.CTkLabel(row, text=hint, font=ctk.CTkFont(size=9), text_color=tm.c("text3")).pack(
                side=lm.pack_side, padx=4)
        return entry

    def _render_logs(self) -> None:
        tm = ThemeManager()
        lm = LanguageManager()
        for child in self._logs_frame.winfo_children():
            child.destroy()
        logs = self._controller.options().logs
        ctk.CTkLabel(self._logs_frame, text=lm.t("ls_logs"), font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=tm.c("text"), anchor=lm.text_anchor).pack(fill="x")
        if not logs:
            ctk.CTkLabel(self._logs_frame, text=lm.t("ls_no_logs"), font=ctk.CTkFont(size=10),
                         text_color=tm.c("text3"), anchor=lm.text_anchor).pack(fill="x")
        for log in logs:
            row = ctk.CTkFrame(self._logs_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=f"{log.path}   ({lm.t(f'ls_format_{log.log_format.value}')})",
                         font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
                         anchor=lm.text_anchor).pack(side=lm.pack_side, fill="x", expand=True)
            ctk.CTkButton(row, text=lm.t("ls_remove"), width=70, height=22, corner_radius=4,
                          font=ctk.CTkFont(size=9), fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
                          text_color=tm.c("text2"),
                          command=lambda p=log.path: self._remove_log(p)).pack(side=lm.opposite_side)

    @staticmethod
    def _button(master, text: str, command: Callable[[], None], primary: bool = True) -> ctk.CTkButton:
        tm = ThemeManager()
        return ctk.CTkButton(
            master, text=text, height=28, corner_radius=6, command=command,
            width=max(100, 7 * len(text)), font=ctk.CTkFont(size=10),
            fg_color=tm.c("accent") if primary else tm.c("bg3"),
            hover_color=tm.c("accent_h") if primary else tm.c("hover"),
            text_color="#ffffff" if primary else tm.c("text2"),
            border_width=0 if primary else 1, border_color=tm.c("border"),
        )

    # ------------------------------------------------------------------
    # State from the controller
    # ------------------------------------------------------------------

    def _show_state(self, state: SentinelState) -> None:
        lm = LanguageManager()
        self._status_lbl.configure(text=self.status_text(state))
        self._start_btn.configure(text=lm.t("ls_stop") if state.running else lm.t("ls_start"))
        self._sample_btn.configure(
            text=lm.t("ls_analysing") if state.analysing else lm.t("ls_analyse_sample"),
            state="disabled" if state.analysing else "normal",
        )
        banner = self.banner_text(state)
        self._banner.configure(text=f"   ⚠  {banner}")
        if banner and not self._banner.winfo_ismapped():
            self._banner.pack(fill="x", pady=(0, 6), before=self._body.winfo_children()[1])
        elif not banner:
            self._banner.pack_forget()
        if self._settings_open and not self._settings_card.winfo_ismapped():
            self._settings_card.pack(fill="x", pady=(6, 0), before=self._bar)
        self._render()
        report = state.last_report
        if state.new_events and report is not None and report.files and report.files[0].path.endswith("sample_access.log"):
            self._on_status(lm.t("ls_sample_done", count=len(state.new_events)), "warn")

    @staticmethod
    def status_text(state: SentinelState) -> str:
        lm = LanguageManager()
        if state.analysing:
            return lm.t("ls_analysing")
        if not state.options.logs:
            return lm.t("ls_status_no_logs")
        if state.last_error:
            return lm.t("ls_status_error", error=state.last_error)
        if state.running:
            text = lm.t("ls_status_running", count=len(state.options.logs))
            report = state.last_report
            malformed = sum(f.malformed for f in report.files) if report else 0
            if malformed:
                text += "  ·  " + lm.t("ls_malformed", count=malformed)
            return text
        return lm.t("ls_status_stopped")

    @staticmethod
    def banner_text(state: SentinelState) -> str:
        """Red banner: only for open CRITICAL events."""
        if not state.open_critical:
            return ""
        return LanguageManager().t("ls_banner_critical", count=state.open_critical)

    # ------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------

    @classmethod
    def severity_choices(cls) -> List[str]:
        lm = LanguageManager()
        return [lm.t("ls_filter_all_severities")] + [lm.t(f"ls_severity_{s.value.lower()}") for s in cls.SEVERITIES]

    def _filter(self) -> EventFilter:
        return EventFilter(
            severities=(self._severity,) if self._severity else (),
            rule_ids=(self._rule,) if self._rule else (),
            state=EventState.OPEN if self._open_only else None,
        )

    def _update_rule_menu(self, rules) -> None:
        lm = LanguageManager()
        values = [lm.t("ls_filter_all_rules")] + [self.rule_choice(rule) for rule in rules]
        self._rule_menu.configure(values=values)
        self._rule_ids = {self.rule_choice(rule): rule for rule in rules}

    @staticmethod
    def rule_choice(rule_id: str) -> str:
        return f"{rule_id}  {LanguageManager().t(f'ls_rule_{rule_id.lower()}')}"

    def _render(self, force: bool = False) -> None:
        if not self._visible:
            return
        event_filter = self._filter()
        if force:
            self._pager.start = 0

        def read():
            events = self._controller.events(event_filter, self.MAX_ROWS)
            return events, self._controller.top_attackers(5), self._controller.store.rule_ids()

        self._reads.request(read, lambda data: self._display(data[0], data[1], data[2], force), key=event_filter)

    def on_hidden(self) -> None:
        self._visible = False

    def on_shown(self) -> None:
        self._visible = True
        self._render()

    def _display(self, events, attackers, rules, force: bool) -> None:
        if not self._visible:
            return
        self._update_rule_menu(rules)
        key = (tuple((e.id, e.hits, e.state) for e in events), tuple(attackers))
        if key == self._shown_key and not force:
            return
        self._shown_key = key
        lm = LanguageManager()
        tm = ThemeManager()
        self._attackers_lbl.configure(text=self.attackers_text(attackers))
        self._ack_all_btn.configure(state="normal" if any(e.is_open for e in events) else "disabled")
        for child in self._list.winfo_children():
            child.destroy()
        if not events:
            ctk.CTkLabel(self._list, text=lm.t("ls_empty"), font=ctk.CTkFont(size=12),
                         text_color=tm.c("text3"), wraplength=700).pack(pady=28)
            return
        self._pager.show(self._list, events, self._event_row)

    @staticmethod
    def attackers_text(attackers: Sequence[Attacker]) -> str:
        if not attackers:
            return ""
        lm = LanguageManager()
        parts = [lm.t("ls_attacker", ip=a.ip, hits=a.hits, severity=a.worst.value) for a in attackers]
        return f"{lm.t('ls_top_attackers')}:  " + "   ·   ".join(parts)

    @staticmethod
    def row_texts(event: SecurityEvent) -> Tuple[str, str, str, str, str, str]:
        """Time, rule title, address, request, status, reason (with the number of requests)."""
        lm = LanguageManager()
        reason = event.reason_text(lm.t)
        if event.hits > 1:
            reason = f"{lm.t('ls_hits', count=event.hits)}  ·  {reason}"
        return (
            event.time.astimezone().strftime("%Y-%m-%d %H:%M:%S"), lm.t(event.title_key), event.ip,
            event.request, str(event.status or "-"), reason,
        )

    def _event_row(self, master, event: SecurityEvent) -> None:
        """Plain Tk widgets inside one frame: a list of 200 events must draw quickly."""
        tm = ThemeManager()
        lm = LanguageManager()
        side: Any = lm.pack_side
        far: Any = lm.opposite_side
        anchor: Any = lm.text_anchor
        justify: Any = lm.text_justify
        px = self._px
        card = tm.c("card")
        time_text, title, ip, request, status, reason = self.row_texts(event)

        row = tk.Frame(master, bg=card, highlightthickness=1, highlightbackground=tm.c("border"))
        row.pack(fill="x", pady=px(2), padx=(0, px(6)))
        top = tk.Frame(row, bg=card)
        top.pack(fill="x", padx=px(8), pady=(px(6), 0))
        tk.Label(top, text=f" {event.severity.value} ", bg=tm.c(self._SEVERITY_COLORS[event.severity]),
                 fg="#ffffff", font=self._font(9, True)).pack(side=side)
        tk.Label(top, text=f"{time_text}   {title}", bg=card, fg=tm.c("text") if event.is_open else tm.c("text3"),
                 font=self._font(11, event.is_open)).pack(side=side, padx=px(8))
        tk.Label(top, text=f"{ip}   ·   {status}", bg=card, fg=tm.c("text2"), font=self._font(10)).pack(side=side)
        if event.is_open:
            button = tk.Label(top, text=lm.t("ls_ack"), bg=tm.c("bg3"), fg=tm.c("text2"), font=self._font(9),
                              cursor="hand2", padx=px(10), pady=px(2))
            button.bind("<Button-1>", lambda _e, i=event.id: self._acknowledge(i))
            button.pack(side=far)
        else:
            tk.Label(top, text=lm.t("ls_state_acknowledged"), bg=card, fg=tm.c("text3"),
                     font=self._font(9)).pack(side=far)
        tk.Label(row, text=request, bg=card, fg=tm.c("text2"), font=self._mono(), anchor=anchor,
                 justify=justify, wraplength=px(820)).pack(fill="x", padx=px(8))
        tk.Label(row, text=reason, bg=card, fg=tm.c(self._SEVERITY_COLORS[event.severity]) if event.is_open
                 else tm.c("text3"), font=self._font(10), anchor=anchor, justify=justify,
                 wraplength=px(820)).pack(fill="x", padx=px(8), pady=(0, px(6)))

    def _px(self, value: float) -> int:
        return round(value * self._scaling)

    def _font(self, size: int, bold: bool = False) -> tkfont.Font:
        key = (size, bold)
        if key not in self._fonts:
            self._fonts[key] = tkfont.Font(
                family=ctk.CTkFont(size=size).cget("family"), size=-self._px(size),
                weight="bold" if bold else "normal",
            )
        return self._fonts[key]

    def _mono(self) -> tkfont.Font:
        key = (-1, False)
        if key not in self._fonts:
            self._fonts[key] = tkfont.Font(family="Consolas", size=-self._px(10))
        return self._fonts[key]

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    @property
    def action_pending(self) -> bool:
        return self._pending_actions > 0

    def _run_action(self, work, done=None) -> None:
        self._pending_actions += 1
        self._start_btn.configure(state="disabled")
        self._export_btn.configure(state="disabled")
        job = self._actions.submit(work)

        def finish():
            if not job.done():
                self.after(40, finish)
                return
            self._pending_actions -= 1
            if not self.action_pending:
                self._start_btn.configure(state="normal")
                self._export_btn.configure(state="normal")
            try:
                value = job.result()
            except Exception as exc:
                self._on_status(str(exc), "error")
            else:
                if done is not None:
                    done(value)
            self._controller.notify()

        self.after(1, finish)

    def _toggle_running(self) -> None:
        self._run_action(self._controller.stop if self._controller.is_running else self._controller.start)

    def _analyse_sample(self) -> None:
        self._controller.analyse_sample()

    def _toggle_settings(self) -> None:
        self._settings_open = not self._settings_open
        if self._settings_open:
            self._settings_card.pack(fill="x", pady=(6, 0), before=self._bar)
        else:
            self._settings_card.pack_forget()

    def _add_log(self) -> None:
        lm = LanguageManager()
        path = filedialog.askopenfilename(parent=self, title=lm.t("ls_add_log"),
                                          filetypes=[(lm.t("ls_log_files"), "*.log *.txt *.json *"), ("*", "*")])
        if not path:
            return
        chosen = self._format_menu.get()
        log_format = next((f for f in LogFormat if lm.t(f"ls_format_{f.value}") == chosen), LogFormat.AUTO)
        self._run_action(lambda: self._controller.add_log(path, log_format), lambda _: self._render_logs())

    def _remove_log(self, path: str) -> None:
        self._run_action(lambda: self._controller.remove_log(path), lambda _: self._render_logs())

    def _save_settings(self) -> None:
        lm = LanguageManager()
        interval, retention = self._interval.get(), self._retention.get()
        proxies, allowlist = self._proxies.get(), self._allowlist.get()
        keep_ips = bool(self._full_ip_switch.get())

        def save():
            self._controller.set_interval(interval)
            self._controller.set_retention(retention)
            invalid = self._controller.set_networks(proxies, allowlist)
            self._controller.set_keep_full_ips(keep_ips)
            return invalid

        def report(invalid):
            if invalid:
                self._on_status(lm.t("ls_invalid_networks", entries=", ".join(invalid)), "warn")
            else:
                self._on_status(lm.t("ls_saved"), "ok")

        self._run_action(save, report)

    def _set_severity(self, choice: str) -> None:
        lm = LanguageManager()
        self._severity = next((s for s in self.SEVERITIES if lm.t(f"ls_severity_{s.value.lower()}") == choice), None)
        self._render(force=True)

    def _set_rule(self, choice: str) -> None:
        self._rule = getattr(self, "_rule_ids", {}).get(choice, "")
        self._render(force=True)

    def _toggle_open_only(self) -> None:
        self._open_only = bool(self._open_switch.get())
        self._render(force=True)

    def _acknowledge(self, event_id: int) -> None:
        self._controller.acknowledge([event_id])

    def _acknowledge_all(self) -> None:
        self._controller.acknowledge_all(EventFilter(
            severities=(self._severity,) if self._severity else (),
            rule_ids=(self._rule,) if self._rule else (),
        ))

    def _export_csv(self) -> None:
        lm = LanguageManager()
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")], initialfile="log_sentinel_events.csv")
        if not path:
            return
        selected = self._filter()
        self._run_action(
            lambda: self._controller.export_csv(path, selected),
            lambda count: self._on_status(lm.t("ls_exported", count=count, file=os.path.basename(path)), "ok"),
        )

    def refresh_theme(self) -> None:
        self.configure(fg_color=ThemeManager().c("bg"))
