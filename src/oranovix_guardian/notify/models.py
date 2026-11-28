"""What is sent, and what came back."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass(frozen=True)
class OutboundMessage:
    """One message in its three forms. It never holds a token or a password."""

    id: str                 # dedup key in the outbox
    kind: str               # "daily", "alarm", "fold" or "test"
    subject: str
    text: str
    telegram_html: str
    email_html: str
    created_at: datetime

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "OutboundMessage":
        values = dict(data)
        values["created_at"] = datetime.fromisoformat(str(values["created_at"]))
        return cls(**values)


@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    error: str = ""         # already redacted
    permanent: bool = False  # retrying cannot help (wrong settings, refused token)


class Notifier(ABC):
    """One way out: email or Telegram. ``send`` never raises."""

    channel: str = ""
    host: str = ""

    @abstractmethod
    def send(self, message: OutboundMessage) -> DeliveryResult:
        """Deliver *message*; every error is in the result, redacted."""
