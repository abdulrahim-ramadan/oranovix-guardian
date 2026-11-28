"""
The daily report: what happened, reduced to what may leave the machine.

``DailyReport.build`` is pure: the same state, clock and options always
give the same report, nothing is read or sent. ``ReportState`` is what
the collector (``notify.collect``) read from the local stores; the
builder keeps only this (the data protection line):

* Threat Feed: counts (from ``DigestBuilder``); title, CVE ids and the
  affected project names of items that affect a project.
* Uptime: site down since / back up, with the host only.
* Log Sentinel: hits per severity and the top rules. No address at all;
  with ``include_network`` only the /24 (IPv4) or /48 (IPv6) network.
* Live Defense: counts, and relative paths of HIGH/CRITICAL events.
* Last scan: date, project and counts per severity.

Never: code, snippets or file contents, secret values or descriptions,
full addresses, request lines, user agents, keys, absolute paths.
"""
from __future__ import annotations

import ipaddress
import posixpath
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from oranovix_guardian.live_defense.base import IntegrityEvent
from oranovix_guardian.log_sentinel.events import SecurityEvent
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.threat_intel.digest import DigestBuilder
from oranovix_guardian.threat_intel.models import Relevance, StoredItem
from oranovix_guardian.threat_intel.projects import Project
from oranovix_guardian.threat_intel.sanitize import SafeUrl

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_LOUD = (Severity.CRITICAL, Severity.HIGH)


@dataclass(frozen=True)
class SiteChange:
    project: str
    host: str
    down_since: Optional[datetime] = None
    back_up_at: Optional[datetime] = None


@dataclass(frozen=True)
class ScanSummary:
    date: datetime
    project: str
    counts: Mapping[str, int]


@dataclass(frozen=True)
class FeedHit:
    title: str
    cve_ids: Tuple[str, ...]
    projects: Tuple[str, ...]
    url: str = ""
    exploited: bool = False


@dataclass(frozen=True)
class ReportState:
    """Everything the collector read. It may hold more than the report keeps."""

    feed_items: Sequence[StoredItem]
    projects: Sequence[Project]
    feed_checked: bool
    sites: Sequence[SiteChange]
    sentinel_events: Sequence[SecurityEvent]
    integrity_events: Sequence[IntegrityEvent]
    last_scan: Optional[ScanSummary]


@dataclass(frozen=True)
class ReportOptions:
    hide_projects: bool = False
    include_network: bool = False


class ProjectAliases:
    """"Project A, B, C..." in place of names, the same letter every day.

    The mapping is kept locally (``settings.json``); only the letters leave.
    """

    def __init__(self, mapping: Optional[Mapping[str, str]] = None,
                 on_change: Callable[[Dict[str, str]], None] = lambda mapping: None) -> None:
        self.mapping: Dict[str, str] = dict(mapping or {})
        self._on_change = on_change

    def alias(self, name: str) -> str:
        if name not in self.mapping:
            self.mapping[name] = f"Project {self._letters(len(self.mapping))}"
            self._on_change(dict(self.mapping))
        return self.mapping[name]

    @staticmethod
    def _letters(index: int) -> str:
        letters = ""
        index += 1
        while index:
            index, rest = divmod(index - 1, 26)
            letters = chr(ord("A") + rest) + letters
        return letters


@dataclass(frozen=True)
class DailyReport:
    now: datetime
    since: datetime
    feed_checked: bool
    feed_new: int
    feed_exposed: int
    feed_hits: Tuple[FeedHit, ...]
    sites: Tuple[SiteChange, ...]
    sentinel_by_severity: Mapping[str, int]
    sentinel_top_rules: Tuple[Tuple[str, int], ...]
    sentinel_networks: Tuple[Tuple[str, int], ...]
    integrity_by_severity: Mapping[str, int]
    integrity_paths: Tuple[Tuple[str, str], ...]
    last_scan: Optional[ScanSummary] = None

    MAX_FEED = 15
    MAX_RULES = 5
    MAX_NETWORKS = 5
    MAX_PATHS = 10

    @property
    def quiet(self) -> bool:
        return not (self.feed_hits or self.sites or self.sentinel_by_severity or self.integrity_paths)

    @classmethod
    def build(cls, state: ReportState, now: datetime, since: datetime, options: ReportOptions = ReportOptions(),
              aliases: Optional[ProjectAliases] = None) -> "DailyReport":
        names = aliases or ProjectAliases()
        name = names.alias if options.hide_projects else (lambda project: project)

        digest = DigestBuilder.build(state.feed_items, state.projects, since)
        hits = tuple(
            FeedHit(
                title=item.item.title,
                cve_ids=tuple(item.item.cve_ids),
                projects=tuple(dict.fromkeys(name(match.project) for match in item.matches)),
                url=SafeUrl.clean(item.item.url) or "",
                exploited=item.item.is_known_exploited,
            )
            for item in sorted(state.feed_items, key=_feed_order)
            if item.relevance is Relevance.AFFECTS_YOU and item.counts_as_new and item.first_seen > since
        )[: cls.MAX_FEED]

        events = [event for event in state.sentinel_events if _event_time(event) >= since]
        by_severity: Counter = Counter()
        by_rule: Counter = Counter()
        by_network: Counter = Counter()
        for event in events:
            by_severity[event.severity.value] += event.hits
            by_rule[event.rule_id] += event.hits
            if options.include_network:
                network = _network(event.ip)
                if network:
                    by_network[network] += event.hits

        integrity: Counter = Counter(event.severity.value for event in state.integrity_events)
        paths = tuple(
            (event.severity.value, _relative(event.relative_path))
            for event in sorted(state.integrity_events, key=lambda e: (-e.severity.weight, e.relative_path))
            if event.severity in _LOUD and event.relative_path
        )[: cls.MAX_PATHS]

        scan = state.last_scan
        if scan is not None:
            scan = ScanSummary(scan.date, name(_project_label(scan.project)),
                               {severity: int(scan.counts.get(severity, 0)) for severity in SEVERITIES})
        return cls(
            now=now, since=since, feed_checked=state.feed_checked,
            feed_new=digest.new_count, feed_exposed=digest.exposed_count, feed_hits=hits,
            # With hidden names the host would give the project away, so it is left out too.
            sites=tuple(SiteChange(name(site.project), "" if options.hide_projects else site.host,
                                   site.down_since, site.back_up_at)
                        for site in state.sites),
            sentinel_by_severity=_ordered(by_severity),
            sentinel_top_rules=tuple(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0])))[: cls.MAX_RULES],
            sentinel_networks=tuple(sorted(by_network.items(), key=lambda kv: (-kv[1], kv[0])))[: cls.MAX_NETWORKS],
            integrity_by_severity=_ordered(integrity),
            integrity_paths=paths,
            last_scan=scan,
        )

    def to_json(self) -> Dict[str, Any]:
        """The report as plain data (for tests and the preview), the same content as rendered."""
        def site(change: SiteChange) -> Dict[str, Any]:
            return {"project": change.project, "host": change.host,
                    "down_since": change.down_since.isoformat() if change.down_since else None,
                    "back_up_at": change.back_up_at.isoformat() if change.back_up_at else None}
        return {
            "since": self.since.isoformat(), "now": self.now.isoformat(),
            "feed": {"new": self.feed_new, "exposed": self.feed_exposed,
                     "hits": [{"title": h.title, "cve_ids": list(h.cve_ids), "projects": list(h.projects)}
                              for h in self.feed_hits]},
            "sites": [site(change) for change in self.sites],
            "sentinel": {"by_severity": dict(self.sentinel_by_severity), "top_rules": list(self.sentinel_top_rules),
                         "networks": list(self.sentinel_networks)},
            "live_defense": {"by_severity": dict(self.integrity_by_severity), "paths": list(self.integrity_paths)},
            "last_scan": None if self.last_scan is None else {
                "date": self.last_scan.date.isoformat(), "project": self.last_scan.project,
                "counts": dict(self.last_scan.counts)},
        }


def _feed_order(item: StoredItem) -> int:
    """Exploited first; otherwise the order of the store (sorted() is stable)."""
    return 0 if item.item.is_known_exploited else 1


def _event_time(event: SecurityEvent) -> datetime:
    return event.last_time or event.time


def _ordered(counts: Counter) -> Dict[str, int]:
    return {severity: counts[severity] for severity in SEVERITIES if counts.get(severity)}


def _network(address: str) -> str:
    """203.0.113.57 -> 203.0.113.0/24, 2001:db8:85a3:1::7 -> 2001:db8:85a3::/48."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return ""
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _relative(path: str) -> str:
    """A path inside the project; anything absolute or leaving it is reduced to its name."""
    posix = path.replace("\\", "/")
    parts = posix.split("/")
    if posix.startswith("/") or (len(parts[0]) == 2 and parts[0].endswith(":")) or ".." in parts:
        return posixpath.basename(posix)
    return posixpath.normpath(posix)


def _project_label(project: str) -> str:
    return posixpath.basename(project.replace("\\", "/").rstrip("/")) or project
