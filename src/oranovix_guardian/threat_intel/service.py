"""
The Threat Feed as one service: download, store, match, alarm.

``refresh`` is the only method that reaches the network, and only when
the user has switched the feed on. It asks each enabled source for its
public feed; the projects are matched afterwards on this machine.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter

from .alarms import ThreatAlarmRaiser
from .fetcher import Fetcher, HttpFetcher
from .models import FeedError, FeedItem, Relevance, SourceHealth
from .projects import Inventory, InventoryBuilder, Project, ProjectRegistry
from .relevance import RelevanceMatcher
from .settings import ThreatFeedConfig, ThreatFeedSettings
from .sources import DownloadedFeedSource, SourceCatalog, SourceConfig, utc_now
from .store import ThreatStore

Clock = Callable[[], datetime]


@dataclass(frozen=True)
class RefreshReport:
    """What one refresh did."""

    finished_at: datetime
    disabled: bool = False                  # the feed is switched off: nothing was requested
    new_items: Tuple[FeedItem, ...] = ()    # without the background
    background_items: int = 0               # old catalog entries stored for matching only
    failures: Tuple[str, ...] = ()          # "source: reason"
    sources_ok: int = 0
    alarms: Tuple[Alarm, ...] = field(default_factory=tuple)

    @property
    def offline(self) -> bool:
        """Every source failed: the page keeps showing the cached items."""
        return not self.disabled and self.sources_ok == 0 and bool(self.failures)


class ThreatFeedService:
    """Owns the store and runs the refresh cycle."""

    # A catalog entry older than this is not news when it first arrives. The
    # first download of the CISA catalog brings well over a thousand of them.
    BACKGROUND_AFTER_DAYS = 30

    def __init__(
        self,
        store: ThreatStore,
        registry: ProjectRegistry,
        settings: ThreatFeedSettings,
        fetcher: Optional[Fetcher] = None,
        matcher: Optional[RelevanceMatcher] = None,
        alarm_center: Optional[AlarmCenter] = None,
        inventory_builder: Optional[InventoryBuilder] = None,
        clock: Clock = utc_now,
    ) -> None:
        self._store = store
        self._registry = registry
        self._settings = settings
        self._fetcher = fetcher
        self._matcher = matcher or RelevanceMatcher()
        self._alarms = ThreatAlarmRaiser(alarm_center, store)
        self._inventory = inventory_builder or InventoryBuilder()
        self._clock = clock
        self._lock = threading.Lock()

    @property
    def store(self) -> ThreatStore:
        return self._store

    @property
    def registry(self) -> ProjectRegistry:
        return self._registry

    @property
    def settings(self) -> ThreatFeedSettings:
        return self._settings

    @property
    def database_ready(self) -> bool:
        return self._matcher.database_ready

    def config(self) -> ThreatFeedConfig:
        return self._settings.load()

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> RefreshReport:
        """Download every enabled source, then match and alarm. May block."""
        with self._lock:
            config = self._settings.load()
            if not config.enabled:
                return RefreshReport(self._clock(), disabled=True)

            fetcher = self._fetcher or HttpFetcher(public_only=True)
            collected: List[FeedItem] = []
            failures: List[str] = []
            succeeded = 0
            for source in self._sources(config.enabled_sources):
                try:
                    collected.extend(source.fetch(fetcher))
                    succeeded += 1
                except FeedError as exc:
                    failures.append(str(exc))
                finally:
                    self._store.save_source(source.health, source.validators)

            background = self._background_ids(collected)
            added = self._store.add(collected, background)
            self._store.purge()
            alarms = self._match_and_alarm()
            # An old entry that turned out to affect a project is news after all.
            affecting = {s.id for s in self._store.items([Relevance.AFFECTS_YOU], limit=100000)}
            quiet = background - affecting
            return RefreshReport(
                finished_at=self._clock(),
                new_items=tuple(item for item in added if item.id not in quiet),
                background_items=sum(1 for item in added if item.id in quiet),
                failures=tuple(failures),
                sources_ok=succeeded,
                alarms=tuple(alarms),
            )

    def _background_ids(self, items: Sequence[FeedItem]) -> Set[str]:
        limit = self._clock() - timedelta(days=self.BACKGROUND_AFTER_DAYS)
        return {
            item.id for item in items
            if item.is_known_exploited and item.published is not None and item.published < limit
        }

    def rematch(self) -> List[Alarm]:
        """Match the cached items again, e.g. after a project was added. No network."""
        with self._lock:
            return self._match_and_alarm()

    def _match_and_alarm(self) -> List[Alarm]:
        stored = self._store.items(limit=100000)
        inventories = self._inventory.build_all(self._registry.list())
        verdicts = self._matcher.match([s.item for s in stored], inventories)
        self._store.set_relevance({
            item_id: (verdict.relevance, verdict.matches) for item_id, verdict in verdicts.items()
        })
        return self._alarms.raise_for(self._store.items([Relevance.AFFECTS_YOU], limit=100000))

    def inventory(self, project: Project) -> Inventory:
        return self._inventory.build(project)

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def _sources(self, configs: Sequence[SourceConfig]) -> List[DownloadedFeedSource]:
        states = self._store.source_states()
        sources = []
        for config in configs:
            source = SourceCatalog.build(config, self._clock)
            health, validators = states.get(config.name, (None, None))
            source.restore(health, validators)
            sources.append(source)
        return sources

    def source_health(self) -> List[Tuple[SourceConfig, SourceHealth]]:
        """Every configured source with what is known about it, for the Sources tab."""
        states: Dict[str, Tuple[SourceHealth, object]] = dict(self._store.source_states())
        return [
            (config, states[config.name][0] if config.name in states else SourceHealth(config.name))
            for config in self._settings.load().sources
        ]
