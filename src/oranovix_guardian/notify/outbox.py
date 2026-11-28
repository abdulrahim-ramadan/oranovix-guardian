"""
Messages waiting to go out, in ``notify.db`` in the data folder.

A failed delivery is tried again after 1, 5, 15 and 60 minutes, then
every 60 minutes, and dropped 48 hours after it was queued; the drop is
shown as the channel's last status. A message id is stored once: the
same daily report, alarm or fold-up is never queued twice. Delivered
rows are kept for 30 days for that check.

The table also keeps, per channel, the date and time of the last daily
report, and the instant-alarm counts per hour.

Error texts are redacted by the notifiers; they are passed through
``safe_error_text`` once more before they are stored.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Tuple, Union

from oranovix_guardian.core.app_paths import AppPaths

from .models import DeliveryResult, Notifier, OutboundMessage
from .redaction import safe_error_text

Clock = Callable[[], datetime]
BACKOFF_MINUTES = (1, 5, 15, 60)
DROP_AFTER = timedelta(hours=48)
KEEP_DELIVERED = timedelta(days=30)


def local_now() -> datetime:
    return datetime.now().astimezone()


@dataclass(frozen=True)
class ChannelState:
    last_sent_date: Optional[date] = None
    last_sent_at: Optional[datetime] = None


@dataclass(frozen=True)
class DeliveryStatus:
    at: datetime
    ok: bool
    error: str = ""
    dropped: bool = False


class Outbox:
    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS outbox (
            id TEXT NOT NULL,
            channel TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL,
            next_attempt REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'pending',
            last_error TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (channel, id)
        );
        CREATE INDEX IF NOT EXISTS outbox_due ON outbox (state, next_attempt);
        CREATE TABLE IF NOT EXISTS channel_state (
            channel TEXT PRIMARY KEY,
            last_sent_date TEXT,
            last_sent_at REAL
        );
        CREATE TABLE IF NOT EXISTS channel_status (
            channel TEXT PRIMARY KEY,
            at REAL NOT NULL,
            ok INTEGER NOT NULL,
            error TEXT NOT NULL,
            dropped INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alarm_hours (
            channel TEXT NOT NULL,
            hour TEXT NOT NULL,
            pushed INTEGER NOT NULL DEFAULT 0,
            folded INTEGER NOT NULL DEFAULT 0,
            fold_queued INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (channel, hour)
        );
    """

    def __init__(self, path: Optional[Union[str, Path]] = None, clock: Clock = local_now) -> None:
        self._path = Path(path) if path else AppPaths.data_dir() / "notify.db"
        self._clock = clock
        self._lock = threading.RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(self._SCHEMA)

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10)

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------

    def enqueue(self, channel: str, message: OutboundMessage) -> bool:
        """Queue *message*; ``False`` when a message with this id was queued before."""
        now = self._clock().timestamp()
        with self._lock, closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO outbox (id, channel, payload, created_at, next_attempt) VALUES (?, ?, ?, ?, ?)",
                (message.id, channel, json.dumps(message.to_json(), ensure_ascii=False), now, now),
            )
            return cursor.rowcount == 1

    def remember_folded(self, channel: str, message: OutboundMessage) -> None:
        """An alarm counted into the hour's fold-up: never pushed, but known (no second count)."""
        now = self._clock().timestamp()
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR IGNORE INTO outbox (id, channel, payload, created_at, next_attempt, state) "
                "VALUES (?, ?, ?, ?, ?, 'folded')",
                (message.id, channel, json.dumps(message.to_json(), ensure_ascii=False), now, now),
            )

    def has(self, channel: str, message_id: str) -> bool:
        with self._lock, closing(self._connect()) as conn:
            return conn.execute("SELECT 1 FROM outbox WHERE channel = ? AND id = ?",
                                (channel, message_id)).fetchone() is not None

    def pending(self, channel: str) -> List[OutboundMessage]:
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute("SELECT payload FROM outbox WHERE channel = ? AND state = 'pending' "
                                "ORDER BY created_at", (channel,)).fetchall()
        return [OutboundMessage.from_json(json.loads(row[0])) for row in rows]

    def deliver_due(self, notifiers: Mapping[str, Notifier]) -> int:
        """Send what is due on the given (active) channels. Returns how many went out."""
        now = self._clock()
        stamp = now.timestamp()
        self._drop_expired(now)
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, channel, payload, attempts FROM outbox WHERE state = 'pending' AND next_attempt <= ? "
                "ORDER BY created_at", (stamp,),
            ).fetchall()
        delivered = 0
        for message_id, channel, payload, attempts in rows:
            notifier = notifiers.get(channel)
            if notifier is None:
                continue                    # switched off: waits (and is dropped after 48 h)
            try:
                result = notifier.send(OutboundMessage.from_json(json.loads(payload)))
            except Exception as exc:        # a notifier must not raise; if it does, it is a failure
                result = DeliveryResult(ok=False, error=safe_error_text(exc))
            self._record(channel, message_id, attempts + 1, result, now)
            delivered += result.ok
        self._purge(now)
        return delivered

    def _record(self, channel: str, message_id: str, attempts: int, result: DeliveryResult, now: datetime) -> None:
        error = safe_error_text(result.error) if result.error else ""
        with self._lock, closing(self._connect()) as conn, conn:
            if result.ok:
                conn.execute("UPDATE outbox SET state = 'sent', attempts = ?, last_error = '' WHERE channel = ? AND id = ?",
                             (attempts, channel, message_id))
            elif result.permanent:
                conn.execute("UPDATE outbox SET state = 'dropped', attempts = ?, last_error = ? WHERE channel = ? AND id = ?",
                             (attempts, error, channel, message_id))
            else:
                wait = BACKOFF_MINUTES[min(attempts, len(BACKOFF_MINUTES)) - 1]
                conn.execute("UPDATE outbox SET attempts = ?, next_attempt = ?, last_error = ? WHERE channel = ? AND id = ?",
                             (attempts, (now + timedelta(minutes=wait)).timestamp(), error, channel, message_id))
        self.set_status(channel, DeliveryStatus(now, result.ok, error, dropped=bool(not result.ok and result.permanent)))

    def _drop_expired(self, now: datetime) -> None:
        cutoff = (now - DROP_AFTER).timestamp()
        with self._lock, closing(self._connect()) as conn, conn:
            rows = conn.execute("SELECT channel, id, last_error FROM outbox WHERE state = 'pending' AND created_at <= ?",
                                (cutoff,)).fetchall()
            conn.execute("UPDATE outbox SET state = 'dropped' WHERE state = 'pending' AND created_at <= ?", (cutoff,))
        for channel, _, last_error in rows:
            reason = "Not delivered within 48 h; the message was dropped."
            if last_error:
                reason += f" Last error: {last_error}"
            self.set_status(channel, DeliveryStatus(now, False, reason, dropped=True))

    def _purge(self, now: datetime) -> None:
        cutoff = (now - KEEP_DELIVERED).timestamp()
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM outbox WHERE state != 'pending' AND created_at < ?", (cutoff,))
            conn.execute("DELETE FROM alarm_hours WHERE hour < ?", ((now - KEEP_DELIVERED).strftime("%Y-%m-%dT%H"),))

    # ------------------------------------------------------------------
    # Status and daily state
    # ------------------------------------------------------------------

    def set_status(self, channel: str, status: DeliveryStatus) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO channel_status (channel, at, ok, error, dropped) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(channel) DO UPDATE SET at = excluded.at, ok = excluded.ok, error = excluded.error, "
                "dropped = excluded.dropped",
                (channel, status.at.timestamp(), int(status.ok), safe_error_text(status.error) if status.error else "",
                 int(status.dropped)),
            )

    def last_status(self, channel: str) -> Optional[DeliveryStatus]:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT at, ok, error, dropped FROM channel_status WHERE channel = ?",
                               (channel,)).fetchone()
        if row is None:
            return None
        return DeliveryStatus(datetime.fromtimestamp(row[0], timezone.utc).astimezone(), bool(row[1]), row[2],
                              bool(row[3]))

    def channel_state(self, channel: str) -> ChannelState:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT last_sent_date, last_sent_at FROM channel_state WHERE channel = ?",
                               (channel,)).fetchone()
        if row is None:
            return ChannelState()
        return ChannelState(date.fromisoformat(row[0]) if row[0] else None,
                            datetime.fromtimestamp(row[1], timezone.utc) if row[1] is not None else None)

    def set_channel_state(self, channel: str, sent_date: date, sent_at: datetime) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO channel_state (channel, last_sent_date, last_sent_at) VALUES (?, ?, ?) "
                "ON CONFLICT(channel) DO UPDATE SET last_sent_date = excluded.last_sent_date, "
                "last_sent_at = excluded.last_sent_at",
                (channel, sent_date.isoformat(), sent_at.timestamp()),
            )

    # ------------------------------------------------------------------
    # Instant alarms per hour
    # ------------------------------------------------------------------

    def count_alarm(self, channel: str, hour: str, limit: int) -> bool:
        """Count one alarm in *hour*; ``True`` when it may be pushed, ``False`` when folded."""
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("INSERT OR IGNORE INTO alarm_hours (channel, hour) VALUES (?, ?)", (channel, hour))
            pushed = conn.execute("SELECT pushed FROM alarm_hours WHERE channel = ? AND hour = ?",
                                  (channel, hour)).fetchone()[0]
            column = "pushed" if pushed < limit else "folded"
            conn.execute(f"UPDATE alarm_hours SET {column} = {column} + 1 WHERE channel = ? AND hour = ?",
                         (channel, hour))
            return column == "pushed"

    def folds_due(self, before_hour: str) -> List[Tuple[str, str, int]]:
        """``(channel, hour, folded)`` of finished hours whose fold-up is not queued yet."""
        with self._lock, closing(self._connect()) as conn:
            return [tuple(row) for row in conn.execute(  # type: ignore[misc]
                "SELECT channel, hour, folded FROM alarm_hours WHERE folded > 0 AND fold_queued = 0 AND hour < ?",
                (before_hour,))]

    def mark_fold_queued(self, channel: str, hour: str) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("UPDATE alarm_hours SET fold_queued = 1 WHERE channel = ? AND hour = ?", (channel, hour))
