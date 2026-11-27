"""
Export of security events: CSV, and the data of the PDF report section.

Requests come from attackers, so a CSV cell that a spreadsheet would read
as a formula is written as text. Addresses are exported as stored: the
store already truncated them unless the user kept full addresses.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.scanner_engine.base import Severity

from .events import SecurityEvent
from .store import Attacker, EventFilter, SecurityEventStore

Translate = Callable[..., str]


class CsvCell:
    """A value that cannot turn into a formula in Excel or LibreOffice."""

    FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

    @classmethod
    def safe(cls, value: object) -> str:
        text = str(value)
        return "'" + text if text.startswith(cls.FORMULA_START) else text


class EventExporter:
    HEADER_KEYS = (
        "ls_col_time", "ls_col_severity", "ls_col_rule", "ls_col_title", "ls_col_ip", "ls_col_request",
        "ls_col_status", "ls_col_reason", "ls_col_hits", "ls_col_state", "ls_col_source",
    )

    @classmethod
    def rows(cls, events: Sequence[SecurityEvent], translate: Optional[Translate] = None) -> List[List[str]]:
        t = translate or LanguageManager().t
        rows = [[t(key) for key in cls.HEADER_KEYS]]
        for event in events:
            rows.append([
                event.time.strftime("%Y-%m-%d %H:%M:%S UTC"), event.severity.value, event.rule_id,
                t(event.title_key), event.ip, event.request, str(event.status or "-"),
                event.reason_text(t), str(event.hits), t(f"ls_state_{event.state.value}"), event.source,
            ])
        return rows

    @classmethod
    def to_csv(cls, events: Sequence[SecurityEvent], path: str, translate: Optional[Translate] = None) -> int:
        rows = cls.rows(events, translate)
        # utf-8-sig: Excel on Windows reads umlauts and Arabic correctly.
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle, delimiter=";", quoting=csv.QUOTE_MINIMAL)
            for row in rows:
                writer.writerow([CsvCell.safe(cell) for cell in row])
        return len(rows) - 1


@dataclass(frozen=True)
class AttackReport:
    """What the PDF report shows in "Attacks seen in web logs"."""

    per_severity: Dict[str, int] = field(default_factory=dict)
    attackers: Tuple[Attacker, ...] = ()
    events: Tuple[SecurityEvent, ...] = ()
    total: int = 0

    MAX_EVENTS = 40

    @property
    def empty(self) -> bool:
        return self.total == 0

    @classmethod
    def from_default_store(cls) -> Optional["AttackReport"]:
        """The report of the app's event store; ``None`` when Log Sentinel was never used."""
        if not SecurityEventStore.default_path().exists():
            return None
        try:
            report = cls.from_store(SecurityEventStore())
        except Exception:
            return None         # the scan report must not fail because of this section
        return None if report.empty else report

    @classmethod
    def from_store(cls, store: SecurityEventStore) -> "AttackReport":
        per_severity = {
            severity.value: store.count(EventFilter(severities=(severity,)))
            for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        }
        # The worst first, then the newest: what a reader of the report must see.
        events: List[SecurityEvent] = []
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            if len(events) >= cls.MAX_EVENTS:
                break
            events.extend(store.events(EventFilter(severities=(severity,)), limit=cls.MAX_EVENTS - len(events)))
        return cls(per_severity, tuple(store.top_attackers(10)), tuple(events), sum(per_severity.values()))
