"""Settings, secrets, consent, preview and the collector of local state."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

import pytest

from oranovix_guardian.notify.models import DeliveryResult, OutboundMessage
from oranovix_guardian.notify.outbox import Outbox
from oranovix_guardian.notify.service import NotificationService, TELEGRAM_TOKEN_ENTRY, SMTP_PASSWORD_ENTRY
from oranovix_guardian.notify.settings import EmailSettings, NotifyConfig, NotifySettings, TelegramSettings

from notify_fakes import Clock, full_state, smtp_password, telegram_token

UTC = timezone.utc


class MemorySecret:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def delete(self) -> None:
        self.value = ""


def service(tmp_path: Path, config: NotifyConfig, clock: Clock, secrets: Dict[str, MemorySecret] = None) -> NotificationService:  # type: ignore[assignment]
    settings = NotifySettings(str(tmp_path / "settings.json"))
    settings.save(config)
    stores = secrets or {"telegram": MemorySecret(telegram_token()), "email": MemorySecret(smtp_password())}
    return NotificationService(settings=settings, outbox=Outbox(tmp_path / "notify.db", clock=clock),
                               secrets={name: store.get for name, store in stores.items()},
                               secret_stores=stores, collect=full_state, clock=clock)


ON = NotifyConfig(enabled=True, telegram=TelegramSettings(enabled=True, consented=True, chat_id="4242"))


def test_defaults_are_off_and_minimal() -> None:
    config = NotifyConfig()
    assert (config.enabled, config.instant_critical, config.hide_projects, config.include_network) == (False,) * 4
    assert config.daily_time == "08:00"
    assert config.email.port == 587 and not config.email.enabled and not config.telegram.enabled


def test_settings_round_trip_without_secrets(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = NotifySettings(str(path))
    config = NotifyConfig(enabled=True, daily_time="07:30", instant_critical=True, hide_projects=True,
                          include_network=True,
                          email=EmailSettings(enabled=True, consented=True, host="smtp.example.com", port=465,
                                              username="me@example.com", from_addr="me@example.com",
                                              to_addrs=("a@example.com",)),
                          telegram=TelegramSettings(enabled=True, consented=True, chat_id="4242", chat_name="Rim"))
    settings.save(config)
    assert settings.load() == config
    raw = path.read_text(encoding="utf-8")
    assert "password" not in raw.lower() and "token" not in raw.lower()


def test_unknown_or_broken_values_fall_back_to_safe_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"notifications": {"enabled": "yes", "daily_time": "99:99", "email": {"port": "x"},
                                                  "telegram": "nonsense"}}), encoding="utf-8")
    config = NotifySettings(str(path)).load()
    assert config.enabled is False and config.daily_time == "08:00" and config.email.port == 587


def test_secrets_go_to_the_secret_store_not_the_settings_file(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 6, tzinfo=UTC))
    stores = {"telegram": MemorySecret(), "email": MemorySecret()}
    svc = service(tmp_path, ON, clock, stores)
    svc.set_secret("telegram", telegram_token())
    svc.set_secret("email", smtp_password())
    assert stores["telegram"].value == telegram_token() and stores["email"].value == smtp_password()
    raw = (tmp_path / "settings.json").read_text(encoding="utf-8")
    assert telegram_token() not in raw and smtp_password() not in raw
    assert TELEGRAM_TOKEN_ENTRY != SMTP_PASSWORD_ENTRY


def test_a_token_of_the_wrong_shape_is_not_saved(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 6, tzinfo=UTC))
    stores = {"telegram": MemorySecret(), "email": MemorySecret()}
    svc = service(tmp_path, ON, clock, stores)
    with pytest.raises(ValueError):
        svc.set_secret("telegram", "123:short")
    assert stores["telegram"].value == ""


def test_preview_is_exactly_what_would_be_sent(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    svc = service(tmp_path, ON, clock)
    preview = svc.preview("telegram")
    sent: List[OutboundMessage] = []

    class Capture:
        channel, host = "telegram", "api.telegram.org"

        def send(self, message: OutboundMessage) -> DeliveryResult:
            sent.append(message)
            return DeliveryResult(ok=True)

    svc.notifiers = lambda: {"telegram": Capture()}          # type: ignore[method-assign]
    svc.tick()
    assert len(sent) == 1
    assert (sent[0].subject, sent[0].text, sent[0].telegram_html, sent[0].email_html) == \
           (preview.subject, preview.text, preview.telegram_html, preview.email_html)


def test_send_test_reports_the_redacted_status(tmp_path: Path) -> None:
    from feed_fakes import FakeFetcher
    from oranovix_guardian.threat_intel.fetcher import FetchError

    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    url = "https://api.telegram.org/bot" + telegram_token() + "/sendMessage"
    svc = service(tmp_path, ON, clock)
    svc.fetcher = FakeFetcher({url: FetchError(f"timed out for {url}")})
    result = svc.send_test("telegram")
    assert not result.ok and telegram_token() not in result.error
    status = svc.status("telegram")
    assert status is not None and not status.ok and telegram_token() not in status.error


def test_hosts_named_in_the_consent(tmp_path: Path) -> None:
    from oranovix_guardian.gui.notify_dialogs import NotifyConsentDialog

    text = NotifyConsentDialog.consent_text("smtp.example.com")
    assert "smtp.example.com" in text
    from oranovix_guardian.core.language_manager import LanguageManager
    lm = LanguageManager()
    assert lm.t("nt_consent_sent") in text and lm.t("nt_consent_never") in text
    assert NotificationService.host_of("telegram", NotifyConfig()) == "api.telegram.org"
    assert NotificationService.host_of("email", NotifyConfig(email=EmailSettings(host="mail.gmx.net"))) == "mail.gmx.net"


def test_switching_a_channel_on_needs_consent(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    svc = service(tmp_path, NotifyConfig(enabled=True), clock)
    svc.set_channel("telegram", enabled=True, consented=False)
    assert svc.config().active_channels() == ()
    svc.set_channel("telegram", enabled=True, consented=True)
    assert svc.config().telegram.enabled and svc.config().telegram.consented


def test_the_collector_reads_only_events_since_the_report(tmp_path: Path) -> None:
    from oranovix_guardian.log_sentinel.store import SecurityEventStore
    from notify_fakes import sentinel_event
    from oranovix_guardian.scanner_engine.base import Severity

    store = SecurityEventStore(str(tmp_path / "events.db"))
    now = datetime(2026, 11, 22, 8, tzinfo=UTC)
    store.add([sentinel_event("LS101", Severity.HIGH, at=now - timedelta(hours=30)),
               sentinel_event("LS109", Severity.MEDIUM, ip="203.0.113.9", at=now - timedelta(hours=2))])
    recent = store.events_since(now - timedelta(hours=24))
    assert [event.rule_id for event in recent] == ["LS109"]


def test_scan_history_gives_the_last_scan_with_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.scan_history import ScanHistory
    from oranovix_guardian.scanner_engine.base import ScanResult

    history = ScanHistory()
    result = ScanResult(str(tmp_path / "shop"), "shop")
    history.save_scan(result)
    last = history.last_scan()
    assert last is not None
    assert last["target"] == "shop" and set(last["counts"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
