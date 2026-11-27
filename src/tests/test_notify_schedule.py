"""Scheduler, outbox and instant alarms; the network is never touched."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmLevel
from oranovix_guardian.notify.alarms import NotifyChannel
from oranovix_guardian.notify.models import DeliveryResult, Notifier, OutboundMessage
from oranovix_guardian.notify.outbox import Outbox
from oranovix_guardian.notify.scheduler import ChannelState, DailySchedule, NotificationScheduler
from oranovix_guardian.notify.settings import NotifyConfig
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory

from notify_fakes import BERLIN, Clock, telegram_token

UTC = timezone.utc


class Recorder(Notifier):
    def __init__(self, name: str, fail: int = 0, error: str = "timed out") -> None:
        self.channel = name
        self.host = f"{name}.example"
        self.sent: List[OutboundMessage] = []
        self.fail = fail
        self.error = error

    def send(self, message: OutboundMessage) -> DeliveryResult:
        if self.fail:
            self.fail -= 1
            return DeliveryResult(ok=False, error=self.error)
        self.sent.append(message)
        return DeliveryResult(ok=True)


def daily(kind: str = "daily") -> Any:
    def build(channel: str, since: datetime, now: datetime) -> OutboundMessage:
        return OutboundMessage(id="", kind=kind, subject=f"report {now:%d.%m.%Y}", text="t", telegram_html="t",
                               email_html="t", created_at=now)
    return build


class Rig:
    def __init__(self, tmp_path: Path, clock: Clock, config: NotifyConfig = NotifyConfig(enabled=True),
                 channels: Any = None) -> None:
        self.clock = clock
        self.outbox = Outbox(tmp_path / "notify.db", clock=clock)
        self.channels: Dict[str, Notifier] = channels if channels is not None else {"telegram": Recorder("telegram")}
        self.config = config
        self.scheduler = self.start()

    def start(self) -> NotificationScheduler:
        """A new start of the app: a new scheduler on the same outbox."""
        self.scheduler = NotificationScheduler(
            outbox=self.outbox, config=lambda: self.config, channels=lambda: self.channels,
            build_daily=daily(), clock=self.clock,
        )
        return self.scheduler

    def sent(self, channel: str = "telegram") -> List[OutboundMessage]:
        return getattr(self.channels[channel], "sent")


# ---------------------------------------------------------------------------
# Daily report time
# ---------------------------------------------------------------------------

def test_the_report_goes_out_at_the_chosen_time(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 6, 59, tzinfo=UTC))      # 07:59 Berlin
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    assert rig.sent() == []
    clock.advance(minutes=1)                                    # 08:00 Berlin
    rig.scheduler.tick()
    assert len(rig.sent()) == 1 and rig.sent()[0].subject == "report 22.11.2026"


def test_never_twice_on_the_same_day(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock)
    for _ in range(10):
        rig.scheduler.tick()
        clock.advance(minutes=30)
    rig.start().tick()                                          # a restart later that day
    assert len(rig.sent()) == 1
    clock.set_local(2026, 11, 23, 8, 0)
    rig.scheduler.tick()
    assert len(rig.sent()) == 2


def test_a_chosen_time_other_than_eight(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock, NotifyConfig(enabled=True, daily_time="18:30"))
    rig.scheduler.tick()
    assert rig.sent() == []
    clock.set_local(2026, 11, 22, 18, 30)
    rig.scheduler.tick()
    assert len(rig.sent()) == 1


def test_a_missed_day_is_sent_once_at_the_next_start(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 20, 7, 0, tzinfo=UTC))      # 20.11. 08:00 sent
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    assert len(rig.sent()) == 1
    clock.set_local(2026, 11, 22, 7, 15)                       # PC was off on the 21st at 08:00
    rig.start().tick()
    assert len(rig.sent()) == 2                                 # sent at start, before 08:00
    clock.set_local(2026, 11, 22, 8, 0)
    rig.scheduler.tick()
    assert len(rig.sent()) == 2                                 # not again on the same day


def test_no_catch_up_when_yesterday_was_sent(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 21, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    clock.set_local(2026, 11, 22, 7, 0)                        # start before 08:00, yesterday's went out
    rig.start().tick()
    assert len(rig.sent()) == 1


def test_a_missed_late_evening_report_is_caught_up_once(tmp_path: Path) -> None:
    """Yesterday 23:30 was missed; the start next morning (31.5 h later) sends it."""
    clock = Clock(datetime(2026, 11, 20, 22, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock, NotifyConfig(enabled=True, daily_time="23:30"))
    rig.scheduler.tick()                                        # 20.11. 23:00 Berlin: not yet
    clock.set_local(2026, 11, 20, 23, 30)
    rig.scheduler.tick()
    assert len(rig.sent()) == 1
    clock.set_local(2026, 11, 22, 7, 0)                        # off on the 21st at 23:30
    rig.start().tick()
    assert len(rig.sent()) == 2                                 # 31.5 h: caught up
    clock.set_local(2026, 11, 22, 23, 30)
    rig.scheduler.tick()
    assert len(rig.sent()) == 2


def test_catch_up_only_at_start_not_on_a_later_tick(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 20, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    clock.set_local(2026, 11, 22, 7, 0)
    rig.config = NotifyConfig(enabled=False)
    rig.start().tick()                                          # off at start: nothing
    rig.config = NotifyConfig(enabled=True)
    clock.advance(minutes=5)
    rig.scheduler.tick()                                        # first enabled tick still counts as the start
    assert len(rig.sent()) == 2


def test_spring_forward_sends_once_at_eight(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 3, 28, 7, 0, tzinfo=UTC))       # Sat 08:00 CET
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    clock.set_local(2026, 3, 29, 7, 59)                        # Sunday, summer time since 02:00
    assert clock().utcoffset() == timedelta(hours=2)
    rig.scheduler.tick()
    assert len(rig.sent()) == 1
    clock.advance(minutes=1)                                    # 08:00 CEST = 06:00 UTC
    rig.scheduler.tick()
    assert len(rig.sent()) == 2
    assert clock.utc == datetime(2026, 3, 29, 6, 0, tzinfo=UTC)


def test_spring_forward_with_a_time_that_does_not_exist(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 3, 29, 0, 59, tzinfo=UTC))      # 01:59 CET
    rig = Rig(tmp_path, clock, NotifyConfig(enabled=True, daily_time="02:30"))
    rig.scheduler.tick()
    assert rig.sent() == []
    clock.advance(minutes=1)                                    # 03:00 CEST: 02:30 was skipped
    rig.scheduler.tick()
    assert len(rig.sent()) == 1
    for _ in range(4):
        clock.advance(minutes=30)
        rig.scheduler.tick()
    assert len(rig.sent()) == 1


def test_fall_back_sends_once_although_the_hour_repeats(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 10, 25, 0, 0, tzinfo=UTC))      # 02:00 CEST, first time
    rig = Rig(tmp_path, clock, NotifyConfig(enabled=True, daily_time="02:30"))
    sent_at = []
    for _ in range(12):                                         # 02:00 CEST .. 03:50 CET
        rig.scheduler.tick()
        sent_at.append(len(rig.sent()))
        clock.advance(minutes=10)
    assert sent_at[-1] == 1
    assert sent_at.index(1) == 3                                # 02:30 CEST, the first 02:30


def test_fall_back_at_eight(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 10, 24, 6, 0, tzinfo=UTC))      # Sat 08:00 CEST
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    clock.set_local(2026, 10, 25, 8, 0)                        # Sun 08:00 CET = 07:00 UTC, 25 h later
    rig.scheduler.tick()
    assert len(rig.sent()) == 2 and clock.utc == datetime(2026, 10, 25, 7, 0, tzinfo=UTC)


def test_daily_schedule_parses_the_time() -> None:
    assert DailySchedule.parse("07:05") == time(7, 5)
    for bad in ("", "25:00", "8", "08:60", "x"):
        assert DailySchedule.parse(bad) == time(8, 0)


def test_last_sent_date_is_stored_per_channel(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock, channels={"telegram": Recorder("telegram"), "email": Recorder("email")})
    rig.scheduler.tick()
    for name in ("telegram", "email"):
        state = rig.outbox.channel_state(name)
        assert state.last_sent_date is not None and state.last_sent_date.isoformat() == "2026-11-22"
    assert rig.outbox.channel_state("other") == ChannelState()


def test_a_newly_enabled_channel_gets_todays_report(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock)
    rig.scheduler.tick()
    rig.channels["email"] = Recorder("email")
    clock.advance(minutes=1)
    rig.scheduler.tick()
    assert len(rig.sent("telegram")) == 1 and len(rig.sent("email")) == 1


# ---------------------------------------------------------------------------
# Off and consent
# ---------------------------------------------------------------------------

def test_master_switch_off_means_no_delivery_at_all(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    rig = Rig(tmp_path, clock, NotifyConfig(enabled=False))
    rig.outbox.enqueue("telegram", replace(daily()("telegram", clock(), clock()), id="queued"))
    rig.scheduler.tick()
    assert rig.sent() == []


def test_channels_need_enabled_and_consent() -> None:
    from oranovix_guardian.notify.settings import EmailSettings, TelegramSettings
    config = NotifyConfig(enabled=True, email=EmailSettings(enabled=True, consented=False),
                          telegram=TelegramSettings(enabled=True, consented=True, chat_id="1"))
    assert config.active_channels() == ("telegram",)
    assert NotifyConfig(enabled=False, telegram=TelegramSettings(enabled=True, consented=True, chat_id="1")).active_channels() == ()
    assert NotifyConfig().enabled is False and NotifyConfig().active_channels() == ()


def test_disabled_service_makes_no_network_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None) -> None:
    from oranovix_guardian.notify.service import NotificationService
    from oranovix_guardian.notify.settings import NotifySettings, TelegramSettings
    settings = NotifySettings(str(tmp_path / "settings.json"))
    settings.save(NotifyConfig(enabled=False, telegram=TelegramSettings(enabled=True, consented=True, chat_id="1")))
    service = NotificationService(settings=settings, outbox=Outbox(tmp_path / "n.db"),
                                  secrets={"telegram": telegram_token, "email": lambda: ""},
                                  collect=lambda: None, clock=Clock(datetime(2026, 11, 22, 7, tzinfo=UTC)))
    service.tick()
    assert service.notifiers() == {}


def test_no_consent_means_no_send(tmp_path: Path, no_network: None) -> None:
    from oranovix_guardian.notify.service import NotificationService
    from oranovix_guardian.notify.settings import NotifySettings, TelegramSettings
    settings = NotifySettings(str(tmp_path / "settings.json"))
    settings.save(NotifyConfig(enabled=True, telegram=TelegramSettings(enabled=True, consented=False, chat_id="1")))
    service = NotificationService(settings=settings, outbox=Outbox(tmp_path / "n.db"),
                                  secrets={"telegram": telegram_token, "email": lambda: ""},
                                  collect=lambda: None, clock=Clock(datetime(2026, 11, 22, 7, tzinfo=UTC)))
    service.tick()
    assert service.notifiers() == {}
    with pytest.raises(PermissionError):
        service.send_test("telegram")


# ---------------------------------------------------------------------------
# Outbox
# ---------------------------------------------------------------------------

def queued(outbox: Outbox, clock: Clock, id_: str = "m1", channel: str = "telegram") -> bool:
    return outbox.enqueue(channel, OutboundMessage(id=id_, kind="daily", subject="s", text="t", telegram_html="t",
                                                   email_html="t", created_at=clock()))


def test_failed_delivery_is_retried_with_backoff(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)
    notifier = Recorder("telegram", fail=10)
    attempts = []
    for minute in range(0, 200):
        before = notifier.fail
        outbox.deliver_due({"telegram": notifier})
        if notifier.fail != before:
            attempts.append(minute)
        clock.advance(minutes=1)
    assert attempts[:5] == [0, 1, 6, 21, 81]                    # 1, 5, 15, 60 min, then every 60
    assert attempts[5] == 141


def test_a_delivered_message_is_not_sent_again(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)
    notifier = Recorder("telegram", fail=1)
    outbox.deliver_due({"telegram": notifier})
    clock.advance(minutes=1)
    outbox.deliver_due({"telegram": notifier})
    clock.advance(minutes=60)
    outbox.deliver_due({"telegram": notifier})
    assert len(notifier.sent) == 1
    status = outbox.last_status("telegram")
    assert status is not None and status.ok


def test_dropped_after_48_hours_with_a_visible_status(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)
    notifier = Recorder("telegram", fail=10_000)
    for _ in range(49):
        outbox.deliver_due({"telegram": notifier})
        clock.advance(hours=1)
    assert outbox.pending("telegram") == []
    status = outbox.last_status("telegram")
    assert status is not None and not status.ok and status.dropped
    assert "48" in status.error


def test_dedup_by_message_id(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    assert queued(outbox, clock, "same")
    assert not queued(outbox, clock, "same")
    notifier = Recorder("telegram")
    outbox.deliver_due({"telegram": notifier})
    assert not queued(outbox, clock, "same")                    # also after it was delivered
    outbox.deliver_due({"telegram": notifier})
    assert len(notifier.sent) == 1


def test_a_permanent_error_is_not_retried(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)

    class Broken(Recorder):
        def send(self, message: OutboundMessage) -> DeliveryResult:
            self.calls = getattr(self, "calls", 0) + 1
            return DeliveryResult(ok=False, error="Unauthorized", permanent=True)

    broken = Broken("telegram")
    for _ in range(5):
        outbox.deliver_due({"telegram": broken})
        clock.advance(hours=1)
    assert getattr(broken, "calls") == 1
    status = outbox.last_status("telegram")
    assert status is not None and status.dropped and "Unauthorized" in status.error


def test_outbox_never_stores_the_token(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)
    token = telegram_token()
    outbox.deliver_due({"telegram": Recorder("telegram", fail=1, error=f"failed for bot{token}/sendMessage")})
    raw = (tmp_path / "n.db").read_bytes()
    assert token.encode() not in raw and token.split(":")[1].encode() not in raw
    status = outbox.last_status("telegram")
    assert status is not None and token not in status.error


def test_a_message_for_a_switched_off_channel_waits(tmp_path: Path) -> None:
    clock = Clock(datetime(2026, 11, 22, 7, 0, tzinfo=UTC))
    outbox = Outbox(tmp_path / "n.db", clock=clock)
    queued(outbox, clock)
    outbox.deliver_due({})
    assert len(outbox.pending("telegram")) == 1


# ---------------------------------------------------------------------------
# Instant CRITICAL alarms
# ---------------------------------------------------------------------------

def alarm(n: int, level: AlarmLevel = AlarmLevel.CRITICAL, ip: str = "198.51.100.77") -> Alarm:
    issue = Issue(rule_id="LS101", title=f"SQL injection attempt ({ip})", description=f"GET /x?id=1 from {ip}",
                  severity=Severity.CRITICAL, file_path="C:\\Users\\alice\\logs\\access.log", line_number=0,
                  category=IssueCategory.ATTACK)
    return Alarm(level=level, title="Critical security finding", message=f"Critical\n{issue.title}\ncounts",
                 worst_issue=issue, counts_by_language={"Web log": 1}, finding_ids=(f"fid-{n}",))


class AlarmRig:
    def __init__(self, tmp_path: Path, instant: bool = True) -> None:
        self.clock = Clock(datetime(2026, 11, 22, 9, 0, tzinfo=UTC))
        self.outbox = Outbox(tmp_path / "n.db", clock=self.clock)
        self.config = NotifyConfig(enabled=True, instant_critical=instant)
        self.notifier = Recorder("telegram")
        self.woken = 0
        self.channel = NotifyChannel(self.outbox, config=lambda: self.config, channels=lambda: ("telegram",),
                                     clock=self.clock, wake=self.wake)

    def wake(self) -> None:
        self.woken += 1

    def flush(self) -> List[OutboundMessage]:
        self.channel.fold_due()
        self.outbox.deliver_due({"telegram": self.notifier})
        return self.notifier.sent


def test_only_critical_alarms_are_pushed(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    assert rig.channel.levels == frozenset({AlarmLevel.CRITICAL})


def test_a_critical_alarm_is_pushed_at_once_without_the_address(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    rig.channel.deliver(alarm(1))
    sent = rig.flush()
    assert len(sent) == 1 and rig.woken == 1
    for text in (sent[0].text, sent[0].telegram_html, sent[0].email_html, sent[0].subject):
        assert "198.51.100" not in text and "alice" not in text and "GET /x" not in text


def test_instant_alerts_off_pushes_nothing(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path, instant=False)
    rig.channel.deliver(alarm(1))
    assert rig.flush() == []


def test_at_most_five_per_hour_then_one_fold_up_message(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    for n in range(12):
        rig.channel.deliver(alarm(n))
        rig.clock.advance(minutes=1)
    assert len(rig.flush()) == 5
    rig.clock.set_local(2026, 11, 22, 10, 59)                  # still the same hour (10:00-10:59 Berlin)
    assert len(rig.flush()) == 5
    rig.clock.set_local(2026, 11, 22, 11, 0)
    sent = rig.flush()
    assert len(sent) == 6 and "7" in sent[-1].text and sent[-1].kind == "fold"
    rig.clock.advance(hours=2)
    assert len(rig.flush()) == 6                                # the fold-up is sent once


def test_the_same_alarm_is_never_pushed_twice(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    rig.channel.deliver(alarm(1))
    rig.channel.deliver(alarm(1))
    rig.clock.advance(hours=3)
    rig.channel.deliver(alarm(1))
    assert len(rig.flush()) == 1


def test_a_new_hour_has_its_own_five(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    for n in range(5):
        rig.channel.deliver(alarm(n))
    rig.clock.advance(hours=1)
    for n in range(5, 10):
        rig.channel.deliver(alarm(n))
    assert len(rig.flush()) == 10


def test_master_switch_off_pushes_nothing(tmp_path: Path) -> None:
    rig = AlarmRig(tmp_path)
    rig.config = NotifyConfig(enabled=False, instant_critical=True)
    rig.channel.deliver(alarm(1))
    assert rig.flush() == [] and rig.outbox.pending("telegram") == []
