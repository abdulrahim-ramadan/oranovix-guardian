"""
The ``notifications`` entry of ``settings.json``.

Everything is off by default. A channel sends only when the master
switch, the channel switch and the channel's consent are all on. The
SMTP password and the bot token are never here: they are in the
credential store (``SecretStore``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Optional, Tuple

from oranovix_guardian.core.settings_file import SettingsFile

from .mail import EmailSettings

CHANNELS = ("email", "telegram")
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


@dataclass(frozen=True)
class TelegramSettings:
    enabled: bool = False
    consented: bool = False
    chat_id: str = ""
    chat_name: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "consented": self.consented, "chat_id": self.chat_id,
                "chat_name": self.chat_name}

    @classmethod
    def from_json(cls, data: object) -> "TelegramSettings":
        if not isinstance(data, dict):
            return cls()
        chat = str(data.get("chat_id") or "").strip()
        return cls(enabled=data.get("enabled") is True, consented=data.get("consented") is True,
                   chat_id=chat if re.fullmatch(r"-?\d{1,20}", chat) else "",
                   chat_name=str(data.get("chat_name") or "")[:64])


@dataclass(frozen=True)
class NotifyConfig:
    enabled: bool = False
    daily_time: str = "08:00"
    instant_critical: bool = False
    hide_projects: bool = False
    include_network: bool = False
    email: EmailSettings = field(default_factory=EmailSettings)
    telegram: TelegramSettings = field(default_factory=TelegramSettings)
    aliases: Tuple[Tuple[str, str], ...] = ()       # hidden project names, kept locally

    def channel(self, name: str) -> Any:
        return self.email if name == "email" else self.telegram

    def active_channels(self) -> Tuple[str, ...]:
        """Channels that may send now: master switch, channel switch and consent."""
        if not self.enabled:
            return ()
        return tuple(name for name in CHANNELS if self.channel(name).enabled and self.channel(name).consented)

    @staticmethod
    def valid_time(value: object) -> str:
        text = str(value or "").strip()
        return text if _TIME.match(text) else "08:00"


class NotifySettings:
    KEY = "notifications"

    def __init__(self, path: Optional[str] = None) -> None:
        self._file = SettingsFile(path)

    def load(self) -> NotifyConfig:
        saved = self._file.section(self.KEY)
        aliases = saved.get("aliases")
        return NotifyConfig(
            enabled=saved.get("enabled") is True,
            daily_time=NotifyConfig.valid_time(saved.get("daily_time")),
            instant_critical=saved.get("instant_critical") is True,
            hide_projects=saved.get("hide_projects") is True,
            include_network=saved.get("include_network") is True,
            email=EmailSettings.from_json(saved.get("email")),
            telegram=TelegramSettings.from_json(saved.get("telegram")),
            aliases=tuple((str(k), str(v)) for k, v in aliases.items()) if isinstance(aliases, dict) else (),
        )

    def save(self, config: NotifyConfig) -> bool:
        return self._file.set(self.KEY, {
            "enabled": config.enabled,
            "daily_time": NotifyConfig.valid_time(config.daily_time),
            "instant_critical": config.instant_critical,
            "hide_projects": config.hide_projects,
            "include_network": config.include_network,
            "email": config.email.to_json(),
            "telegram": config.telegram.to_json(),
            "aliases": dict(config.aliases),
        })

    def update(self, **changes: Any) -> NotifyConfig:
        config = replace(self.load(), **changes)
        self.save(config)
        return config
