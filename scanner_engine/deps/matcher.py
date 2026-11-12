"""
Decides whether an installed version falls inside an advisory's ranges.

Follows the OSV evaluation rule: walk the events of a range in version
order; ``introduced`` switches "affected" on, ``fixed`` (and ``limit``)
switch it off from that version, ``last_affected`` switches it off after
that version.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from .osv_db import AffectedRange, Vulnerability
from .versions import Ecosystem, VersionScheme, scheme_for


@dataclass(frozen=True)
class VulnerabilityMatch:
    """An advisory that applies to the installed version."""

    vulnerability: Vulnerability
    fixed_version: str = ""     # lowest fixed version above the installed one
    last_affected: str = ""     # newest affected version, when no fix is listed


class VersionMatcher:
    """Matches versions of one ecosystem against OSV ranges."""

    # At the same version an "introduced" event is applied before the others.
    _ORDER = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}

    def __init__(self, ecosystem: Ecosystem) -> None:
        self._scheme: VersionScheme = scheme_for(ecosystem)

    def match(self, installed: str, vulnerability: Vulnerability) -> Optional[VulnerabilityMatch]:
        """Return a match when *installed* is affected, otherwise ``None``.

        A version that cannot be parsed is never reported: nothing is guessed.
        """
        version = self._scheme.parse(installed)
        if version is None:
            return None
        if not any(self._affects(version, r) for r in vulnerability.ranges):
            return None

        fixed: List[Tuple[Any, str]] = []
        last: List[Tuple[Any, str]] = []
        for affected_range in vulnerability.ranges:
            for event in affected_range.events:
                parsed = self._scheme.parse(event.version)
                if parsed is None:
                    continue
                if event.kind == "fixed" and parsed > version:
                    fixed.append((parsed, event.version))
                elif event.kind == "last_affected" and parsed >= version:
                    last.append((parsed, event.version))

        return VulnerabilityMatch(
            vulnerability=vulnerability,
            fixed_version=min(fixed)[1] if fixed else "",
            last_affected="" if fixed or not last else min(last)[1],
        )

    def _affects(self, version: Any, affected_range: AffectedRange) -> bool:
        events = []
        for event in affected_range.events:
            parsed = self._scheme.parse(event.version)
            if parsed is None:
                return False            # a range we cannot order is not evaluated
            events.append((parsed, self._ORDER.get(event.kind, 1), event.kind))
        events.sort(key=lambda item: (item[0], item[1]))

        affected = False
        for parsed, _, kind in events:
            if kind == "introduced":
                if version >= parsed:
                    affected = True
            elif kind in ("fixed", "limit"):
                if version >= parsed:
                    affected = False
            elif kind == "last_affected":
                if version > parsed:
                    affected = False
        return affected
