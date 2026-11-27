"""Security events: what is stored and shown, after the privacy rules were applied."""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, List, Optional, Sequence, Tuple

from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory

from .privacy import IpAnonymizer, RequestRedactor
from .rules import AttackCategory, Detection, Reason


class EventState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"


@dataclass(frozen=True)
class SecurityEvent:
    time: datetime
    rule_id: str
    category: AttackCategory
    severity: Severity
    ip: str                     # truncated, or full when the user chose it
    ip_hash: str
    request: str                # method and normalised target, secrets hidden, at most 300 characters
    status: int
    reasons: Tuple[Reason, ...]
    source: str = ""            # the log file
    evidence: str = ""
    state: EventState = EventState.OPEN
    id: int = 0                 # set by the store
    hits: int = 1               # requests folded into this event (same rule, address, window, severity)
    last_time: Optional[datetime] = None

    @property
    def title_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}"

    @property
    def explanation_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}_explain"

    @property
    def is_open(self) -> bool:
        return self.state is EventState.OPEN

    def reason_text(self, translate: Optional[Callable[..., str]] = None) -> str:
        t = translate or LanguageManager().t
        return "; ".join(t(reason.key, **reason.kwargs()) for reason in self.reasons)

    def dedup_key(self, window_minutes: int = 10) -> str:
        """One event and one alarm per rule, address, ten minute window and severity.

        The severity is part of it, so an attack that later gets a real
        answer still alarms at the higher level.
        """
        slot = int(self.time.timestamp() // (window_minutes * 60))
        return f"{self.rule_id}|{self.ip_hash}|{slot}|{self.severity.value}"

    def to_issue(self, window_minutes: int = 10) -> Issue:
        lm = LanguageManager()
        return Issue(
            rule_id=self.rule_id,
            title=f"{lm.t(self.title_key)} ({self.ip})",
            description=f"{self.request}  ·  {self.reason_text(lm.t)}",
            severity=self.severity,
            file_path=self.source or "access.log",
            line_number=0,
            recommendation=lm.t(self.explanation_key),
            confidence="HIGH",
            category=IssueCategory.ATTACK,
            finding_key=self.dedup_key(window_minutes),
        )


class EventFactory:
    """Turns detections into events. The raw address and query never leave this class."""

    def __init__(self, anonymizer: IpAnonymizer) -> None:
        self._anonymizer = anonymizer

    @property
    def anonymizer(self) -> IpAnonymizer:
        return self._anonymizer

    def build(self, detection: Detection, source: str = "", now: Optional[datetime] = None) -> SecurityEvent:
        entry = detection.entry
        method = entry.method or "-"
        normalized = detection.normalized or entry.target
        path, _, query = normalized.partition("?")
        evidence = RequestRedactor.text(detection.evidence)
        reasons = tuple(
            Reason(reason.key, tuple(
                (name, RequestRedactor.text(value) if name == "evidence" else value) for name, value in reason.args
            ))
            for reason in detection.reasons
        )
        return SecurityEvent(
            time=entry.time or now or datetime.now(timezone.utc),
            rule_id=detection.rule_id,
            category=detection.category,
            severity=detection.severity,
            ip=self._anonymizer.display(entry.client_ip),
            ip_hash=self._anonymizer.hash(entry.client_ip),
            request=RequestRedactor.text(f"{method} {RequestRedactor.target(path, query)}"),
            status=entry.status,
            reasons=reasons,
            source=source,
            evidence=evidence,
        )


class EventSink(ABC):
    """Where the monitor puts events: the store, or a list in tests."""

    @abstractmethod
    def add(self, events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        """Store *events*; return them with their ids."""


@dataclass
class MemorySink(EventSink):
    events: List[SecurityEvent] = field(default_factory=list)

    def add(self, events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        stored = []
        for event in events:
            stored.append(_with_id(event, len(self.events) + 1))
            self.events.append(stored[-1])
        return stored


def _with_id(event: SecurityEvent, event_id: int) -> SecurityEvent:
    from dataclasses import replace
    return replace(event, id=event_id)


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
