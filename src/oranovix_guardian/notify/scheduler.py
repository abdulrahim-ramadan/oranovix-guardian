"""
When the daily report goes out.

``NotificationScheduler.tick`` runs in ``NotificationMonitor``, a
``Monitor`` like the feed refresher and the uptime check (no new kind of
thread). Each tick:

* sends the daily report at the chosen local time (default 08:00), once
  per channel and day (``last_sent_date`` per channel in the outbox);
* at the first tick after a start, sends a report that was missed while
  the PC was off: the previous day's slot was not sent and the last
  report is more than 20 h old;
* queues the fold-up of instant alarms of finished hours, and delivers
  what is due from the outbox.

Local time is the wall clock: 08:00 is 08:00 in winter and in summer;
on the day the clock jumps forward, a time inside the skipped hour is
sent at the first tick after it, and the repeated hour in October does
not send twice (same date).

With the master switch off nothing is built, queued or sent.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import replace
from datetime import datetime, time, timedelta
from typing import Callable, Mapping, Optional

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.live_defense.base import IntegrityEvent, Monitor

from .models import Notifier, OutboundMessage
from .outbox import ChannelState, Clock, Outbox, local_now
from .settings import NotifyConfig

__all__ = ["ChannelState", "DailySchedule", "NotificationScheduler", "NotificationMonitor"]

_log = logging.getLogger(__name__)
BuildDaily = Callable[[str, datetime, datetime], OutboundMessage]


class DailySchedule:
    CATCH_UP_AFTER = timedelta(hours=20)
    LONGEST_PERIOD = timedelta(days=7)

    def __init__(self, at: time) -> None:
        self.at = at

    @staticmethod
    def parse(text: str) -> time:
        value = NotifyConfig.valid_time(text)
        hour, minute = value.split(":")
        return time(int(hour), int(minute))

    def due(self, now: datetime, state: ChannelState, at_start: bool) -> bool:
        today = now.date()
        if state.last_sent_date == today:
            return False
        # Same tzinfo object: compared as wall-clock times.
        slot = now.replace(hour=self.at.hour, minute=self.at.minute, second=0, microsecond=0)
        if now >= slot:
            return True
        if not at_start or state.last_sent_date is None or state.last_sent_at is None:
            return False
        missed = state.last_sent_date < today - timedelta(days=1)
        old = now.timestamp() - state.last_sent_at.timestamp() > self.CATCH_UP_AFTER.total_seconds()
        return missed and old

    def since(self, state: ChannelState, now: datetime) -> datetime:
        """The period of the report: since the last one, at most a week, a day for the first."""
        if state.last_sent_at is None:
            return now - timedelta(days=1)
        return max(state.last_sent_at.astimezone(now.tzinfo), now - self.LONGEST_PERIOD)


class NotificationScheduler:
    def __init__(
        self,
        outbox: Outbox,
        config: Callable[[], NotifyConfig],
        channels: Callable[[], Mapping[str, Notifier]],
        build_daily: BuildDaily,
        clock: Clock = local_now,
        fold_due: Callable[[], None] = lambda: None,
    ) -> None:
        self._outbox = outbox
        self._config = config
        self._channels = channels
        self._build_daily = build_daily
        self._clock = clock
        self._fold_due = fold_due
        self._started = False

    def tick(self) -> None:
        config = self._config()
        if not config.enabled:
            return                          # off: no report, no delivery, no network
        at_start = not self._started
        self._started = True
        now = self._clock()
        notifiers = dict(self._channels())
        schedule = DailySchedule(DailySchedule.parse(config.daily_time))
        for name in notifiers:
            state = self._outbox.channel_state(name)
            if not schedule.due(now, state, at_start):
                continue
            message = self._build_daily(name, schedule.since(state, now), now)
            self._outbox.enqueue(name, replace(message, id=f"daily-{name}-{now.date().isoformat()}"))
            self._outbox.set_channel_state(name, now.date(), now)
        self._fold_due()
        self._outbox.deliver_due(notifiers)


class NotificationMonitor(Monitor):
    """Ticks the scheduler on the monitor thread; ``wake`` delivers an instant alarm now."""

    INTERVAL_SECONDS = 30

    def __init__(self, tick: Callable[[], None], interval_seconds: float = INTERVAL_SECONDS,
                 root: Optional[str] = None) -> None:
        super().__init__(root or str(AppPaths.data_dir()), interval_seconds=interval_seconds)
        self._tick = tick
        self._wake = threading.Event()

    def check(self) -> list[IntegrityEvent]:
        self._tick()
        return []

    def wake(self) -> None:
        self._wake.set()

    def stop(self, timeout: Optional[float] = 10.0) -> bool:
        self._stop.set()
        self._wake.set()
        return super().stop(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                _log.exception("notification tick failed")
            self._wake.wait(self.interval)
            self._wake.clear()
