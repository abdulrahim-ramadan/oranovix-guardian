"""
The "Notifications" section of the settings page.

Master switch (off by default), daily time, instant CRITICAL alerts,
hidden project names, truncated networks; per channel the fields, a
"Send test" button and the last delivery status; "Preview" shows the
message that would be sent now.

A channel is switched on only after the consent (host, what is sent,
what never is). For email the consent is for the server typed: when the
server changes, the channel goes off and asks again. "Find my chat"
also contacts Telegram, so it asks for the consent first.

Anything that touches the network or the databases runs on a worker
thread; the result comes back through ``after``.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from typing import Any, Callable, Optional

import customtkinter as ctk

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.core.secret_store import SecretStoreError
from oranovix_guardian.gui.notify_dialogs import ChatPickerDialog, NotifyConsentDialog, PreviewDialog
from oranovix_guardian.gui.theme_manager import ThemeManager
from oranovix_guardian.notify.mail import EmailError, EmailSettings
from oranovix_guardian.notify.service import NotificationService
from oranovix_guardian.notify.settings import NotifyConfig
from oranovix_guardian.notify.telegram import TelegramError


class NotificationsPanel(ctk.CTkFrame):
    def __init__(self, master, service: NotificationService, **kwargs: Any) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._service = service
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NotifySettings")
        self._switches: dict = {}
        self._status: dict = {}
        self._build(service.config())

    def destroy(self) -> None:
        self._worker.shutdown(wait=False)
        super().destroy()

    # ------------------------------------------------------------------
    # Layout helpers
    # ------------------------------------------------------------------

    def _switch_row(self, parent, text: str, value: bool, command: Callable[[], None]) -> ctk.CTkSwitch:
        tm = ThemeManager()
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=(4, 0))
        ctk.CTkLabel(row, text=text, font=ctk.CTkFont(size=12), text_color=tm.c("text"),
                     fg_color="transparent").pack(side="left")
        switch = ctk.CTkSwitch(row, text="", onvalue=True, offvalue=False, fg_color=tm.c("border"),
                               progress_color=tm.c("accent"), command=command)
        switch.pack(side="right")
        switch.select() if value else switch.deselect()
        return switch

    def _hint(self, parent, text: str) -> None:
        tm = ThemeManager()
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=9), text_color=tm.c("text3"), fg_color="transparent",
                     anchor="w", justify="left", wraplength=540).pack(anchor="w", pady=(2, 6))

    def _entry(self, parent, label: str, value: str = "", width: int = 260, show: str = "",
               placeholder: str = "") -> ctk.CTkEntry:
        tm = ThemeManager()
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=label, width=150, anchor="w", font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
                     fg_color="transparent").pack(side="left")
        entry = ctk.CTkEntry(row, width=width, height=28, fg_color=tm.c("input_bg"), border_color=tm.c("border"),
                             text_color=tm.c("text"), show=show, placeholder_text=placeholder)
        if value:
            entry.insert(0, value)
        entry.pack(side="left", padx=(8, 0))
        return entry

    def _button(self, parent, text: str, command: Callable[[], None], primary: bool = False) -> ctk.CTkButton:
        tm = ThemeManager()
        button = ctk.CTkButton(parent, text=text, height=28, corner_radius=6, font=ctk.CTkFont(size=10),
                               fg_color=tm.c("accent") if primary else tm.c("bg3"),
                               hover_color=tm.c("accent_h") if primary else tm.c("hover"),
                               text_color="#ffffff" if primary else tm.c("text"), command=command)
        button.pack(side="left", padx=(0, 8))
        return button

    def _status_label(self, parent, channel: str) -> None:
        tm = ThemeManager()
        label = ctk.CTkLabel(parent, text="", font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
                             fg_color="transparent", anchor="w", justify="left", wraplength=540)
        label.pack(anchor="w", pady=(4, 0))
        self._status[channel] = label
        self._show_status(channel)

    def _subheading(self, parent, text: str) -> None:
        tm = ThemeManager()
        ctk.CTkFrame(parent, height=1, fg_color=tm.c("border"), corner_radius=0).pack(fill="x", pady=(12, 6))
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=12, weight="bold"), text_color=tm.c("text"),
                     fg_color="transparent").pack(anchor="w")

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self, config: NotifyConfig) -> None:
        lm = LanguageManager()
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=10)

        self._switches["enabled"] = self._switch_row(body, lm.t("nt_ui_enable"), config.enabled,
                                                     lambda: self._toggle_option("enabled"))
        self._hint(body, lm.t("nt_ui_hint"))
        self._time = self._entry(body, lm.t("nt_ui_time"), config.daily_time, width=70)
        self._time.bind("<FocusOut>", lambda _e: self._save_time())
        self._time.bind("<Return>", lambda _e: self._save_time())
        for name, key in (("instant_critical", "nt_ui_instant"), ("hide_projects", "nt_ui_hide"),
                          ("include_network", "nt_ui_network")):
            self._switches[name] = self._switch_row(body, lm.t(key), getattr(config, name),
                                                    lambda name=name: self._toggle_option(name))
        self._hint(body, lm.t("nt_ui_options_hint"))

        # Email
        self._subheading(body, lm.t("nt_ui_email"))
        self._switches["email"] = self._switch_row(body, lm.t("nt_ui_channel_on"), config.email.enabled
                                                   and config.email.consented, lambda: self._toggle_channel("email"))
        email = config.email
        self._smtp_host = self._entry(body, lm.t("nt_ui_smtp_host"), email.host, placeholder="smtp.gmail.com")
        self._smtp_port = self._entry(body, lm.t("nt_ui_smtp_port"), str(email.port), width=70)
        self._smtp_user = self._entry(body, lm.t("nt_ui_smtp_user"), email.username)
        self._smtp_password = self._entry(body, lm.t("nt_ui_smtp_password"), show="•",
                                          placeholder=lm.t("nt_ui_saved") if self._service.has_secret("email") else "")
        self._smtp_from = self._entry(body, lm.t("nt_ui_from"), email.from_addr)
        self._smtp_to = self._entry(body, lm.t("nt_ui_to"), ", ".join(email.to_addrs), width=360)
        self._hint(body, lm.t("nt_ui_app_password_hint"))
        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x", pady=(4, 0))
        self._button(row, lm.t("nt_ui_save"), self._save_email, primary=True)
        self._button(row, lm.t("nt_ui_test"), lambda: self._send_test("email"))
        self._status_label(body, "email")

        # Telegram
        self._subheading(body, lm.t("nt_ui_telegram"))
        telegram = config.telegram
        self._switches["telegram"] = self._switch_row(body, lm.t("nt_ui_channel_on"), telegram.enabled
                                                      and telegram.consented, lambda: self._toggle_channel("telegram"))
        self._hint(body, lm.t("nt_ui_tg_steps"))
        self._tg_token = self._entry(body, lm.t("nt_ui_tg_token"), show="•", width=360,
                                     placeholder=lm.t("nt_ui_saved") if self._service.has_secret("telegram") else "")
        self._tg_chat = self._entry(body, lm.t("nt_ui_tg_chat"), telegram.chat_id, width=160)
        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x", pady=(4, 0))
        self._button(row, lm.t("nt_ui_save"), self._on_save_telegram, primary=True)
        self._button(row, lm.t("nt_ui_find_chat"), self._find_chat)
        self._button(row, lm.t("nt_ui_test"), lambda: self._send_test("telegram"))
        self._status_label(body, "telegram")

        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x", pady=(14, 0))
        self._button(row, lm.t("nt_ui_preview"), self._preview)

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------

    def _toggle_option(self, name: str) -> None:
        self._service.update(**{name: bool(self._switches[name].get())})

    def _save_time(self) -> None:
        value = NotifyConfig.valid_time(self._time.get())
        self._service.update(daily_time=value)
        self._time.delete(0, "end")
        self._time.insert(0, value)

    # ------------------------------------------------------------------
    # Channels and consent
    # ------------------------------------------------------------------

    def _ask_consent(self, channel: str) -> bool:
        """The consent dialog for *channel*; remembered when accepted."""
        config = self._service.config()
        host = NotificationService.host_of(channel, config)
        if not host:
            self._set_status(channel, LanguageManager().t("nt_ui_need_host"), error=True)
            return False
        if not NotifyConsentDialog.ask(self, host):
            return False
        self._service.set_channel(channel, consented=True)
        return True

    def _toggle_channel(self, channel: str) -> None:
        switch = self._switches[channel]
        if not switch.get():
            self._service.set_channel(channel, enabled=False)
            return
        if not self._service.config().channel(channel).consented and not self._ask_consent(channel):
            switch.deselect()
            self._service.set_channel(channel, enabled=False)
            return
        self._service.set_channel(channel, enabled=True)

    def _save_email(self) -> None:
        lm = LanguageManager()
        old = self._service.config().email
        try:
            port = int(self._smtp_port.get().strip() or "0")
        except ValueError:
            port = 0
        recipients = tuple(part.strip() for part in self._smtp_to.get().replace(";", ",").split(",") if part.strip())
        new = EmailSettings(
            enabled=old.enabled, consented=old.consented, host=self._smtp_host.get().strip(), port=port,
            username=self._smtp_user.get().strip(), from_addr=self._smtp_from.get().strip(), to_addrs=recipients,
        )
        try:
            new = new.validate()
        except EmailError as exc:
            self._set_status("email", str(exc), error=True)
            return
        message = lm.t("nt_ui_saved_ok")
        if old.consented and new.host != old.host:
            # The consent named the old server.
            new = replace(new, enabled=False, consented=False)
            self._switches["email"].deselect()
            message = lm.t("nt_ui_reconsent")
        password = self._smtp_password.get()
        if password:
            try:
                self._service.set_secret("email", password)
            except (SecretStoreError, ValueError) as exc:
                self._set_status("email", str(exc), error=True)
                return
            self._smtp_password.delete(0, "end")
        self._service.update(email=new)
        self._set_status("email", message)

    def _on_save_telegram(self) -> None:
        self._save_telegram()

    def _save_telegram(self) -> bool:
        lm = LanguageManager()
        token = self._tg_token.get().strip()
        if token:
            try:
                self._service.set_secret("telegram", token)
            except (SecretStoreError, ValueError) as exc:
                self._set_status("telegram", str(exc), error=True)
                return False
            self._tg_token.delete(0, "end")
        chat = self._tg_chat.get().strip()
        if chat and not chat.lstrip("-").isdigit():
            self._set_status("telegram", lm.t("nt_ui_bad_chat"), error=True)
            return False
        self._service.set_channel("telegram", chat_id=chat)
        self._set_status("telegram", lm.t("nt_ui_saved_ok"))
        return True

    # ------------------------------------------------------------------
    # Network actions (worker thread)
    # ------------------------------------------------------------------

    def _run(self, work: Callable[[], Any], done: Callable[[Future], None]) -> None:
        future = self._worker.submit(work)

        def poll() -> None:
            if not future.done():
                self.after(100, poll)
                return
            try:
                done(future)
            except Exception:
                pass        # the panel was rebuilt meanwhile

        self.after(100, poll)

    def _send_test(self, channel: str) -> None:
        lm = LanguageManager()
        if channel not in self._service.config().active_channels():
            self._set_status(channel, lm.t("nt_not_active"), error=True)
            return
        self._set_status(channel, lm.t("nt_ui_sending"))

        def done(future: Future) -> None:
            self._show_status(channel)

        self._run(lambda: self._service.send_test(channel), done)

    def _find_chat(self) -> None:
        lm = LanguageManager()
        if not self._save_telegram():
            return
        if not self._service.has_secret("telegram"):
            self._set_status("telegram", lm.t("nt_tg_token_shape"), error=True)
            return
        if not self._service.config().telegram.consented and not self._ask_consent("telegram"):
            return
        self._set_status("telegram", lm.t("nt_ui_searching"))

        def done(future: Future) -> None:
            try:
                chats = future.result()
            except TelegramError as exc:
                self._set_status("telegram", str(exc), error=True)
                return
            if not chats:
                self._set_status("telegram", lm.t("nt_ui_no_chat"), error=True)
                return
            choice = ChatPickerDialog.ask(self, chats)
            if choice is None:
                self._set_status("telegram", "")
                return
            self._service.set_channel("telegram", chat_id=choice[0], chat_name=choice[1])
            self._tg_chat.delete(0, "end")
            self._tg_chat.insert(0, choice[0])
            self._set_status("telegram", lm.t("nt_ui_chat_chosen", name=choice[1]))

        self._run(self._service.find_chats, done)

    def _preview(self) -> None:
        config = self._service.config()
        channel = (config.active_channels() or ("telegram",))[0]

        def done(future: Future) -> None:
            PreviewDialog(self, future.result())

        self._run(lambda: self._service.preview(channel), done)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def _set_status(self, channel: str, text: str, error: bool = False) -> None:
        tm = ThemeManager()
        label: Optional[ctk.CTkLabel] = self._status.get(channel)
        if label is not None:
            label.configure(text=text, text_color=tm.c("error") if error else tm.c("text2"))

    def _show_status(self, channel: str) -> None:
        lm = LanguageManager()
        status = self._service.status(channel)
        if status is None:
            self._set_status(channel, lm.t("nt_ui_never_sent"))
            return
        when = status.at.strftime("%d.%m.%Y %H:%M")
        if status.ok:
            self._set_status(channel, lm.t("nt_ui_last_ok", time=when))
        else:
            self._set_status(channel, lm.t("nt_ui_last_error", time=when, error=status.error), error=True)
