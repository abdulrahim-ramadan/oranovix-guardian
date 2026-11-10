"""
Central alarm for dangerous findings.

``AlarmCenter.notify`` receives findings from any source (a finished
scan today, a background monitor later), decides the alarm level,
skips findings that already triggered an alarm, and hands the alarm to
its channels (sound, toast, taskbar flash).  It has no GUI dependency:
channels are injected.

Sound and taskbar flash are reserved for CRITICAL findings the engine is
confident about.  A low-confidence finding ("needs review") is shown,
never sounded.

The loud alarm fires once per finding.  A finding that disappears from
a full scan is forgotten, so it alarms again if it is reintroduced.
Open criticals stay visible through ``AlarmCenter.open_critical_banner``.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from core.language_manager import LanguageManager
from core.scan_history import ScanHistory
from core.sound_manager import SoundManager
from scanner_engine.base import Issue, Severity


class AlarmLevel(Enum):
    """How loudly a group of new findings is announced."""

    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Alarm:
    """One alarm, ready to be delivered by any channel."""

    level: AlarmLevel
    title: str
    message: str
    worst_issue: Issue
    counts_by_language: Dict[str, int]
    finding_ids: Tuple[str, ...]
    needs_review: bool = False


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------

class AlarmChannel(ABC):
    """One way of announcing an alarm (sound, toast, taskbar...)."""

    levels: FrozenSet[AlarmLevel] = frozenset(AlarmLevel)

    @abstractmethod
    def deliver(self, alarm: Alarm) -> None:
        """Announce *alarm*.  May be called from any thread."""


class SoundAlarmChannel(AlarmChannel):
    """Plays the critical tone; silent for HIGH and for low-confidence findings."""

    levels = frozenset({AlarmLevel.CRITICAL})

    def deliver(self, alarm: Alarm) -> None:
        SoundManager().play("critical")


# ---------------------------------------------------------------------------
# Memory of findings that already raised an alarm
# ---------------------------------------------------------------------------

class SeenFindingStore(ABC):
    """Remembers which finding IDs already triggered an alarm, per scan root."""

    @abstractmethod
    def unseen(self, finding_ids: Sequence[str]) -> Set[str]:
        """Return the subset of *finding_ids* never alarmed before."""

    @abstractmethod
    def mark_seen(self, finding_ids: Sequence[str], scan_root: str) -> None:
        """Record *finding_ids* as alarmed for *scan_root*."""

    @abstractmethod
    def forget_missing(self, scan_root: str, present_ids: Sequence[str]) -> int:
        """Drop IDs of *scan_root* that are not in *present_ids*; return how many."""


class SqliteSeenFindingStore(SeenFindingStore):
    """SQLite-backed store; shares the scan history database by default."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or ScanHistory._resolve_db_path()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS alarmed_findings ("
                "finding_id TEXT PRIMARY KEY, first_alarmed_at TEXT NOT NULL, "
                "scan_root TEXT NOT NULL DEFAULT '')"
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(alarmed_findings)")}
            if "scan_root" not in columns:
                conn.execute(
                    "ALTER TABLE alarmed_findings ADD COLUMN scan_root TEXT NOT NULL DEFAULT ''"
                )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def unseen(self, finding_ids: Sequence[str]) -> Set[str]:
        remaining = set(finding_ids)
        with self._connect() as conn:
            for finding_id in finding_ids:
                row = conn.execute(
                    "SELECT 1 FROM alarmed_findings WHERE finding_id = ?", (finding_id,)
                ).fetchone()
                if row:
                    remaining.discard(finding_id)
        return remaining

    def mark_seen(self, finding_ids: Sequence[str], scan_root: str) -> None:
        now = datetime.now().isoformat()
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO alarmed_findings "
                "(finding_id, first_alarmed_at, scan_root) VALUES (?, ?, ?)",
                [(finding_id, now, scan_root) for finding_id in finding_ids],
            )

    def forget_missing(self, scan_root: str, present_ids: Sequence[str]) -> int:
        present = set(present_ids)
        with self._connect() as conn:
            stored = [
                row[0] for row in conn.execute(
                    "SELECT finding_id FROM alarmed_findings WHERE scan_root = ?",
                    (scan_root,),
                )
            ]
            gone = [finding_id for finding_id in stored if finding_id not in present]
            conn.executemany(
                "DELETE FROM alarmed_findings WHERE finding_id = ?",
                [(finding_id,) for finding_id in gone],
            )
        return len(gone)


# ---------------------------------------------------------------------------
# Alarm center
# ---------------------------------------------------------------------------

class AlarmCenter:
    """Decides whether findings deserve an alarm and delivers it once."""

    _ALARM_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)

    def __init__(
        self,
        store: Optional[SeenFindingStore] = None,
        channels: Iterable[AlarmChannel] = (),
    ) -> None:
        self._store = store or SqliteSeenFindingStore()
        self._channels: List[AlarmChannel] = list(channels)
        self._lock = threading.Lock()

    def add_channel(self, channel: AlarmChannel) -> None:
        self._channels.append(channel)

    def notify(
        self,
        findings: Iterable[Issue],
        scan_root: str = "",
        full_scan: bool = True,
    ) -> Optional[Alarm]:
        """Raise an alarm for CRITICAL/HIGH findings not alarmed before.

        A confident CRITICAL goes to every channel.  HIGH, and CRITICAL
        with LOW confidence, go only to channels that accept the HIGH
        level (the toast), so they never play a sound.  Anything lower is
        ignored.  Returns the alarm, or ``None`` when nothing new deserved
        one.  Thread-safe.

        With *full_scan* the findings are the complete picture of
        *scan_root*: alarmed findings that are no longer present are
        forgotten, so they alarm again if they come back.  A monitor that
        reports only part of a project must pass ``full_scan=False``.
        """
        root_key = self._root_key(scan_root)
        candidates = {
            self.finding_id(issue, scan_root): issue
            for issue in findings
            if issue.severity in self._ALARM_SEVERITIES
        }

        with self._lock:
            if full_scan:
                self._store.forget_missing(root_key, list(candidates))
            if not candidates:
                return None
            new_ids = self._store.unseen(list(candidates))
            if not new_ids:
                return None
            self._store.mark_seen(sorted(new_ids), root_key)

        new_issues = [issue for fid, issue in candidates.items() if fid in new_ids]
        alarm = self._build_alarm(new_issues, tuple(sorted(new_ids)))
        for channel in self._channels:
            if alarm.level in channel.levels:
                try:
                    channel.deliver(alarm)
                except Exception:
                    continue
        return alarm

    @staticmethod
    def open_critical_banner(findings: Iterable[Issue]) -> str:
        """Text for the persistent banner, or ``""`` when no critical is open.

        Unlike ``notify`` this never goes quiet: it reflects every CRITICAL
        finding of the current scan, seen before or not.
        """
        count = sum(1 for issue in findings if issue.severity is Severity.CRITICAL)
        if count == 0:
            return ""
        return LanguageManager().t("critical_open_banner", count=count)

    @staticmethod
    def _root_key(scan_root: str) -> str:
        return os.path.normcase(os.path.abspath(scan_root)) if scan_root else ""

    @staticmethod
    def finding_id(issue: Issue, scan_root: str = "") -> str:
        """Stable ID: sha1 of rule category, path relative to the scan root, line.

        The scan root is mixed in so the same relative path in two different
        projects never shares an ID.
        """
        relative = AlarmCenter._relative_path(issue.file_path, scan_root)
        root_key = AlarmCenter._root_key(scan_root)
        raw = f"{root_key}|{issue.category.value}|{relative}|{issue.line_number}"
        return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()

    @staticmethod
    def _relative_path(file_path: str, scan_root: str) -> str:
        if scan_root and os.path.isdir(scan_root):
            try:
                return Path(os.path.relpath(file_path, scan_root)).as_posix()
            except ValueError:
                pass
        return os.path.basename(file_path)

    @staticmethod
    def _build_alarm(new_issues: List[Issue], finding_ids: Tuple[str, ...]) -> Alarm:
        lm = LanguageManager()
        worst = max(
            new_issues, key=lambda issue: (not issue.needs_review, issue.severity.weight)
        )
        is_critical = worst.severity is Severity.CRITICAL and not worst.needs_review
        level = AlarmLevel.CRITICAL if is_critical else AlarmLevel.HIGH
        counts = dict(Counter(issue.language.value for issue in new_issues))
        counts_text = ", ".join(f"{name} {count}" for name, count in counts.items())

        if is_critical:
            title = lm.t("alarm_critical_title")
        elif worst.needs_review:
            title = lm.t("alarm_review_title")
        else:
            title = lm.t("alarm_high_title")
        location = lm.t(
            "alarm_location",
            language=worst.language.value,
            file=worst.filename,
            line=worst.line_number,
            issue=lm.rule_title((worst.rule_id, *worst.also_detected_by), worst.title),
        )
        message = f"{title}\n{location}\n{lm.t('alarm_counts', counts=counts_text)}"
        return Alarm(
            level=level,
            title=title,
            message=message,
            worst_issue=worst,
            counts_by_language=counts,
            finding_ids=finding_ids,
            needs_review=worst.needs_review,
        )
