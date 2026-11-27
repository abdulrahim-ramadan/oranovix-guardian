"""
The notification feature as one object for the GUI and the app.

It owns the outbox, the scheduler, the instant-alarm channel and the
monitor thread. Notifiers are built for each send from the current
settings, so a changed setting needs no restart. A channel is only
built when it is active (master switch, channel switch, consent):
without that there is no notifier and so no network call.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.core.secret_store import SERVICE_NAME, SecretStore
from oranovix_guardian.threat_intel.fetcher import Fetcher

from .alarms import NotifyChannel
from .mail import EmailNotifier
from .models import DeliveryResult, Notifier, OutboundMessage
from .outbox import Clock, DeliveryStatus, Outbox, local_now
from .redaction import safe_error_text
from .render import ReportRenderer
from .report import DailyReport, ProjectAliases, ReportOptions, ReportState
from .scheduler import DailySchedule, NotificationMonitor, NotificationScheduler
from .settings import CHANNELS, NotifyConfig, NotifySettings
from .telegram import API_HOST, TelegramNotifier, valid_token

TELEGRAM_TOKEN_ENTRY = "telegram_bot_token"
SMTP_PASSWORD_ENTRY = "smtp_password"

EMPTY_STATE = ReportState(feed_items=(), projects=(), feed_checked=False, sites=(), sentinel_events=(),
                          integrity_events=(), last_scan=None)


class NotificationService:
    def __init__(
        self,
        settings: Optional[NotifySettings] = None,
        outbox: Optional[Outbox] = None,
        secrets: Optional[Mapping[str, Callable[[], str]]] = None,
        secret_stores: Optional[Mapping[str, Any]] = None,
        collect: Callable[[], Optional[ReportState]] = lambda: None,
        clock: Clock = local_now,
        fetcher: Optional[Fetcher] = None,
    ) -> None:
        self._settings = settings or NotifySettings()
        self._stores = dict(secret_stores or {
            "email": SecretStore(SERVICE_NAME, SMTP_PASSWORD_ENTRY),
            "telegram": SecretStore(SERVICE_NAME, TELEGRAM_TOKEN_ENTRY),
        })
        self._secrets = dict(secrets or {name: store.get for name, store in self._stores.items()})
        self._clock = clock
        self.outbox = outbox or Outbox(clock=clock)
        self._collect = collect
        self.fetcher = fetcher
        self._monitor: Optional[NotificationMonitor] = None
        self.alarm_channel = NotifyChannel(self.outbox, self.config, lambda: self.config().active_channels(),
                                           clock=clock, wake=self._wake)
        self.scheduler = NotificationScheduler(
            self.outbox, self.config, lambda: self.notifiers(), self._daily_message, clock,
            fold_due=self.alarm_channel.fold_due,
        )

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def config(self) -> NotifyConfig:
        return self._settings.load()

    def update(self, **changes: Any) -> NotifyConfig:
        return self._settings.update(**changes)

    def set_channel(self, name: str, **changes: Any) -> NotifyConfig:
        config = self.config()
        if name == "email":
            return self.update(email=replace(config.email, **changes))
        return self.update(telegram=replace(config.telegram, **changes))

    def set_secret(self, name: str, value: str) -> None:
        """Into the credential store; a token of the wrong shape is refused, not stored."""
        value = value.strip()
        if name == "telegram" and not valid_token(value):
            raise ValueError(LanguageManager().t("nt_tg_token_shape"))
        self._stores[name].set(value)

    def has_secret(self, name: str) -> bool:
        return bool(self._secrets[name]())

    def delete_secret(self, name: str) -> None:
        self._stores[name].delete()

    @staticmethod
    def host_of(name: str, config: NotifyConfig) -> str:
        """The one host a channel contacts, as named in the consent."""
        return API_HOST if name == "telegram" else config.email.host.strip()

    # ------------------------------------------------------------------
    # Notifiers
    # ------------------------------------------------------------------

    def notifier(self, name: str, config: Optional[NotifyConfig] = None) -> Notifier:
        config = config or self.config()
        if name == "email":
            return EmailNotifier(config.email, password=self._secrets["email"])
        return TelegramNotifier(self._secrets["telegram"], config.telegram.chat_id, fetcher=self.fetcher)

    def notifiers(self) -> Dict[str, Notifier]:
        config = self.config()
        return {name: self.notifier(name, config) for name in config.active_channels()}

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def build_report(self, since: datetime, now: datetime, config: Optional[NotifyConfig] = None) -> DailyReport:
        config = config or self.config()
        state = self._collect() or EMPTY_STATE
        aliases = ProjectAliases(dict(config.aliases), on_change=self._save_aliases)
        options = ReportOptions(hide_projects=config.hide_projects, include_network=config.include_network)
        return DailyReport.build(state, now=now, since=since, options=options, aliases=aliases)

    def _save_aliases(self, mapping: Dict[str, str]) -> None:
        self.update(aliases=tuple(mapping.items()))

    def _daily_message(self, channel: str, since: datetime, now: datetime) -> OutboundMessage:
        return ReportRenderer.for_current_language().message(self.build_report(since, now), kind="daily")

    def preview(self, channel: str = "telegram") -> OutboundMessage:
        """Exactly the report that would go out on *channel* now."""
        now = self._clock()
        config = self.config()
        since = DailySchedule(DailySchedule.parse(config.daily_time)).since(self.outbox.channel_state(channel), now)
        return self._daily_message(channel, since, now)

    def send_test(self, name: str) -> DeliveryResult:
        """A short test message, now, on an active channel. The status line shows the result."""
        config = self.config()
        if name not in config.active_channels():
            raise PermissionError(LanguageManager().t("nt_not_active"))
        lm = LanguageManager()
        now = self._clock()
        message = ReportRenderer.for_current_language().simple(
            f"test-{now.timestamp()}", "test", lm.t("nt_test_subject"),
            [lm.t("nt_test_text", channel=lm.t(f"nt_channel_{name}"))], now)
        try:
            result = self.notifier(name, config).send(message)
        except Exception as exc:
            result = DeliveryResult(ok=False, error=safe_error_text(exc, [self._secrets[name]()]))
        self.outbox.set_status(name, DeliveryStatus(now, result.ok, result.error))
        return result

    def find_chats(self) -> List[Tuple[str, str]]:
        """Telegram setup helper: one getUpdates call. Raises ``TelegramError`` (redacted)."""
        return TelegramNotifier(self._secrets["telegram"], "", fetcher=self.fetcher).find_chats()

    def status(self, name: str) -> Optional[DeliveryStatus]:
        return self.outbox.last_status(name)

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------

    def tick(self) -> None:
        self.scheduler.tick()

    def start(self) -> None:
        if self._monitor is None:
            self._monitor = NotificationMonitor(self.tick)
        self._monitor.start()

    def shutdown(self, timeout: Optional[float] = 2) -> None:
        if self._monitor is not None:
            self._monitor.stop(timeout)

    def _wake(self) -> None:
        if self._monitor is not None:
            self._monitor.wake()


__all__ = ["NotificationService", "TELEGRAM_TOKEN_ENTRY", "SMTP_PASSWORD_ENTRY", "CHANNELS"]
