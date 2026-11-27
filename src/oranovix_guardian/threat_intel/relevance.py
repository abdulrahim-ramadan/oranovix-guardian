"""
Decides which feed items concern the user's own projects.

Runs entirely on this machine: the items come from the store, the
installed packages from the manifests, the vulnerable ranges from the
local OSV database of the dependency scanner.

* AFFECTS_YOU - a CVE id (or a package the item names) leads to a local
  advisory whose range contains a version some project has installed.
* POSSIBLE    - only a vendor or product name equals an installed package.
  This is a guess from names and must be verified by the user.
* GENERAL     - everything else.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from oranovix_guardian.scanner_engine.deps.manifests import Dependency
from oranovix_guardian.scanner_engine.deps.matcher import VersionMatcher
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase, Vulnerability
from oranovix_guardian.scanner_engine.deps.versions import Ecosystem, scheme_for

from .models import FeedItem, PackageRef, ProjectMatch, Relevance
from .projects import Inventory, Project


@dataclass(frozen=True)
class Verdict:
    relevance: Relevance
    matches: Tuple[ProjectMatch, ...] = ()


class NameMatcher:
    """Compares a vendor or product name with a package name. Approximate by nature."""

    MIN_LENGTH = 4
    # Words that say nothing about which product is meant.
    GENERIC: FrozenSet[str] = frozenset({
        "multiple", "products", "product", "server", "client", "core", "framework", "software",
        "system", "systems", "service", "services", "manager", "enterprise", "platform", "tool",
        "tools", "open", "source", "project", "web", "http", "api", "app", "apps", "base",
        "common", "utils", "util", "plugin", "plugins", "module", "library", "node", "data",
        "file", "files", "router", "gateway", "windows", "office", "mobile", "desktop",
    })

    _WORD = re.compile(r"[a-z0-9]+")

    @classmethod
    @lru_cache(maxsize=16384)       # the whole catalog is compared with every package
    def words(cls, name: str) -> Tuple[str, ...]:
        return tuple(cls._WORD.findall(name.lower()))

    @classmethod
    def same(cls, package: str, product: str) -> bool:
        """True when *product* is, or starts with, the name of *package*."""
        package_words = cls.words(package)
        product_words = cls.words(product)
        if not package_words or not product_words:
            return False
        if len("".join(package_words)) < cls.MIN_LENGTH:
            return False
        if all(word in cls.GENERIC for word in package_words):
            return False
        return product_words[: len(package_words)] == package_words


@dataclass
class _Exposure:
    """What the projects have installed, and which advisories cover it."""

    by_advisory: Dict[str, List[ProjectMatch]] = field(default_factory=dict)
    by_package: Dict[Tuple[str, str], List[ProjectMatch]] = field(default_factory=dict)
    installed: List[Tuple[Project, Dependency, FrozenSet[str]]] = field(default_factory=list)


class RelevanceMatcher:
    """Matches feed items against the inventories of the projects."""

    MAX_MATCHES = 20

    def __init__(self, database: Optional[OSVDatabase] = None) -> None:
        self._database = database or OSVDatabase()

    @property
    def database_ready(self) -> bool:
        """Without the OSV database nothing can be confirmed, only guessed."""
        return self._database.exists()

    def match(self, items: Iterable[FeedItem], inventories: Sequence[Inventory]) -> Dict[str, Verdict]:
        """A verdict for every item, by item id."""
        exposure = self._exposure(inventories)
        return {item.id: self._verdict(item, exposure) for item in items}

    # ------------------------------------------------------------------
    # One item
    # ------------------------------------------------------------------

    def _verdict(self, item: FeedItem, exposure: _Exposure) -> Verdict:
        confirmed = self._confirmed(item, exposure)
        if confirmed:
            return Verdict(Relevance.AFFECTS_YOU, self._unique(confirmed))
        possible = self._possible(item, exposure)
        if possible:
            return Verdict(Relevance.POSSIBLE, self._unique(possible))
        return Verdict(Relevance.GENERAL)

    @staticmethod
    def _confirmed(item: FeedItem, exposure: _Exposure) -> List[ProjectMatch]:
        matches = [
            match for cve in item.cve_ids for match in exposure.by_advisory.get(cve.upper(), [])
        ]
        if matches or item.cve_ids:
            return matches
        # No CVE id on the item: a package it names with its registry is enough,
        # as long as the installed version is inside some advisory's range.
        for ref in item.packages:
            ecosystem = RelevanceMatcher._ecosystem(ref)
            if ecosystem is not None:
                key = (ecosystem.value, RelevanceMatcher._normalized(ecosystem, ref.name))
                matches.extend(exposure.by_package.get(key, []))
        return matches

    @staticmethod
    def _possible(item: FeedItem, exposure: _Exposure) -> List[ProjectMatch]:
        names = [ref.name for ref in item.packages]
        if not names:
            return []
        cves = {cve.upper() for cve in item.cve_ids}
        matches: List[ProjectMatch] = []
        for project, dependency, advisory_ids in exposure.installed:
            if not any(NameMatcher.same(dependency.name, name) for name in names):
                continue
            if dependency.pinned and cves & advisory_ids:
                # The local database knows this CVE for this package, and the
                # installed version is outside its range: not affected.
                continue
            matches.append(ProjectMatch(
                project=project.name, project_path=project.path, package=dependency.name,
                ecosystem=dependency.ecosystem.value, version=dependency.version or "",
                file_path=dependency.file_path, line=dependency.line,
            ))
        return matches

    @classmethod
    def _unique(cls, matches: Sequence[ProjectMatch]) -> Tuple[ProjectMatch, ...]:
        """One match per project, package and version; the most severe advisory wins."""
        best: Dict[Tuple[str, str, str, str], ProjectMatch] = {}
        for match in matches:
            key = (match.project_path, match.ecosystem, match.package.lower(), match.version)
            current = best.get(key)
            if current is None or cls._weight(match) > cls._weight(current):
                best[key] = match
        return tuple(best.values())[: cls.MAX_MATCHES]

    @staticmethod
    def _weight(match: ProjectMatch) -> int:
        return match.severity.weight if match.severity else 0

    # ------------------------------------------------------------------
    # What is installed
    # ------------------------------------------------------------------

    def _exposure(self, inventories: Sequence[Inventory]) -> _Exposure:
        exposure = _Exposure()
        advisories: Dict[Tuple[Ecosystem, str], List[Vulnerability]] = {}
        for inventory in inventories:
            for dependency in inventory.dependencies:
                key = (dependency.ecosystem, dependency.normalized_name)
                if key not in advisories:
                    advisories[key] = self._database.vulnerabilities_for(*key)
                known = advisories[key]
                ids = frozenset(i.upper() for vulnerability in known for i in vulnerability.all_ids)
                exposure.installed.append((inventory.project, dependency, ids))
                if dependency.pinned:
                    self._add_hits(exposure, inventory.project, dependency, known)
        return exposure

    @staticmethod
    def _add_hits(
        exposure: _Exposure, project: Project, dependency: Dependency,
        advisories: Sequence[Vulnerability],
    ) -> None:
        version = dependency.version or ""
        matcher = VersionMatcher(dependency.ecosystem)
        for vulnerability in advisories:
            hit = matcher.match(version, vulnerability)
            if hit is None:
                continue
            match = ProjectMatch(
                project=project.name, project_path=project.path, package=dependency.name,
                ecosystem=dependency.ecosystem.value, version=version,
                advisory_id=vulnerability.cve or vulnerability.id,
                severity=vulnerability.severity, fixed_version=hit.fixed_version,
                file_path=dependency.file_path, line=dependency.line,
            )
            for advisory_id in vulnerability.all_ids:
                exposure.by_advisory.setdefault(advisory_id.upper(), []).append(match)
            package_key = (dependency.ecosystem.value, dependency.normalized_name)
            exposure.by_package.setdefault(package_key, []).append(match)

    @staticmethod
    def _ecosystem(ref: PackageRef) -> Optional[Ecosystem]:
        return next((e for e in Ecosystem if e.value.lower() == ref.ecosystem.lower()), None)

    @staticmethod
    def _normalized(ecosystem: Ecosystem, name: str) -> str:
        return scheme_for(ecosystem).normalize_name(name)
