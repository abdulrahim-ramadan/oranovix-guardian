"""
The ``threat_feed`` entry of ``settings.json``.

The feed is off until the user switches it on. ``asked`` records that the
first-run dialog was answered, so it is not shown again.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional, Tuple

from oranovix_guardian.live_defense.controller import LiveDefenseSettings

from .sources import SourceCatalog, SourceConfig


@dataclass(frozen=True)
class ThreatFeedConfig:
    enabled: bool = False
    asked: bool = False
    interval_minutes: int = 60
    sources: Tuple[SourceConfig, ...] = SourceCatalog.DEFAULTS

    MIN_INTERVAL = 15
    MAX_INTERVAL = 24 * 60

    @property
    def enabled_sources(self) -> Tuple[SourceConfig, ...]:
        return tuple(source for source in self.sources if source.enabled)

    @classmethod
    def valid_interval(cls, value: object) -> int:
        try:
            minutes = int(str(value))
        except (TypeError, ValueError):
            return 60
        return min(max(minutes, cls.MIN_INTERVAL), cls.MAX_INTERVAL)


class _Entry(LiveDefenseSettings):
    """Same file and same safe writing as the Live Defense entry, other key."""

    KEY = "threat_feed"


class ThreatFeedSettings:
    """Loads and saves ``ThreatFeedConfig``."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._entry = _Entry(path)

    def load(self) -> ThreatFeedConfig:
        saved = self._entry.load()
        return ThreatFeedConfig(
            enabled=saved.get("enabled") is True,
            asked=saved.get("asked") is True,
            interval_minutes=ThreatFeedConfig.valid_interval(saved.get("interval_minutes", 60)),
            sources=SourceCatalog.from_json(saved.get("sources")),
        )

    def save(self, config: ThreatFeedConfig) -> None:
        self._entry.save(
            enabled=config.enabled,
            asked=config.asked,
            interval_minutes=ThreatFeedConfig.valid_interval(config.interval_minutes),
            sources=[source.to_json() for source in config.sources],
        )

    def update(self, **changes: object) -> ThreatFeedConfig:
        config = replace(self.load(), **changes)        # type: ignore[arg-type]
        self.save(config)
        return config
