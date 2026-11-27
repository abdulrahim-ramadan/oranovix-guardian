"""
Instant push of CRITICAL alarms (optional, off by default).

``NotifyChannel`` is one more ``AlarmChannel`` of the ``AlarmCenter``,
which already announces a finding only once. The message id comes from
the alarm's finding ids, so the outbox refuses a second push of the same
alarm too.

At most five alarms per channel and hour are pushed. Further ones in
that hour are counted, and one "N more critical alarms" message goes
out when the hour is over.

The text is built here, not taken from ``Alarm.message``: a Log
Sentinel title carries the client address and an uptime title the full
URL. It names the rule and the file name only; addresses and URLs are
removed from anything else.
"""
from __future__ import annotations

import hashlib
from typing import Callable, Sequence

from oranovix_guardian.core.alarm_center import Alarm, AlarmChannel, AlarmLevel
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.scanner_engine.categories import IssueCategory

from .models import OutboundMessage
from .outbox import Clock, Outbox, local_now
from .redaction import scrub_addresses
from .render import ReportRenderer
from .settings import NotifyConfig


class NotifyChannel(AlarmChannel):
    levels = frozenset({AlarmLevel.CRITICAL})
    MAX_PER_HOUR = 5

    def __init__(
        self,
        outbox: Outbox,
        config: Callable[[], NotifyConfig],
        channels: Callable[[], Sequence[str]],
        clock: Clock = local_now,
        wake: Callable[[], None] = lambda: None,
        renderer: Callable[[], ReportRenderer] = ReportRenderer.for_current_language,
    ) -> None:
        self._outbox = outbox
        self._config = config
        self._channels = channels
        self._clock = clock
        self._wake = wake
        self._renderer = renderer

    @staticmethod
    def _hour(moment) -> str:
        return moment.strftime("%Y-%m-%dT%H")

    def deliver(self, alarm: Alarm) -> None:
        config = self._config()
        if not (config.enabled and config.instant_critical) or alarm.level is not AlarmLevel.CRITICAL:
            return
        now = self._clock()
        key = hashlib.sha256("|".join(sorted(alarm.finding_ids)).encode("utf-8")).hexdigest()[:24]
        message = self.message(alarm, f"alarm-{key}", now)
        queued = False
        for channel in self._channels():
            if self._outbox.has(channel, message.id):
                continue
            if self._outbox.count_alarm(channel, self._hour(now), self.MAX_PER_HOUR):
                queued = self._outbox.enqueue(channel, message) or queued
            else:
                self._outbox.remember_folded(channel, message)
        if queued:
            self._wake()

    def fold_due(self) -> None:
        """One message per finished hour that had more than five alarms."""
        now = self._clock()
        renderer = self._renderer()
        lm = LanguageManager()
        for channel, hour, folded in self._outbox.folds_due(self._hour(now)):
            text = lm.t("nt_fold_text", count=folded, hour=hour[-2:] + ":00")
            fold = renderer.simple(f"fold-{hour}", "fold", lm.t("nt_alarm_subject"), [text], now)
            self._outbox.enqueue(channel, fold)
            self._outbox.mark_fold_queued(channel, hour)

    def message(self, alarm: Alarm, message_id: str, now) -> OutboundMessage:
        lm = LanguageManager()
        issue = alarm.worst_issue
        if issue.category is IssueCategory.ATTACK:
            key = f"ls_rule_{issue.rule_id.lower()}"
            rule = lm.t(key)
            if rule == key:
                rule = issue.rule_id
            where = lm.t("language_web_log")
        else:
            fallback = issue.rule_id if issue.category is IssueCategory.NETWORK else issue.title
            rule = lm.rule_title((issue.rule_id, *issue.also_detected_by), fallback)
            where = issue.filename
        rule, where = scrub_addresses(rule) or issue.rule_id, scrub_addresses(where)
        counts = ", ".join(f"{scrub_addresses(name)} {count}" for name, count in alarm.counts_by_language.items())
        body = [lm.t("nt_alarm_text", rule=rule, file=where), lm.t("alarm_counts", counts=counts)]
        return self._renderer().simple(message_id, "alarm", lm.t("nt_alarm_subject"), body, now)
