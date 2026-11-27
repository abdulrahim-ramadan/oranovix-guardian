"""
What each project is exposed to right now.

Exposure is not the same as "unread". An item that affects a project
keeps counting, read or not, for as long as the matcher finds the
installed version inside the vulnerable range. It stops counting when
the dependency is upgraded, when the project is removed, or when the
user accepts the risk for that item and project with a written reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from typing import Dict, Mapping, Optional, Sequence, Tuple

from .models import AcceptedRisk, ProjectMatch, Relevance, RiskKey, StoredItem, project_key
from .projects import Project


@dataclass(frozen=True)
class OpenItem:
    """One confirmed item for one project."""

    stored: StoredItem
    match: ProjectMatch                 # the most severe match of the item in this project
    accepted: Optional[AcceptedRisk] = None

    @property
    def rank(self) -> Tuple[int, int, float, str]:
        """Sort key, worst first: exploited, then severity, then newest."""
        severity = self.match.severity.weight if self.match.severity else 0
        moment = self.stored.item.published or self.stored.first_seen
        return (
            0 if self.stored.item.is_known_exploited else 1,
            -severity,
            -moment.replace(tzinfo=moment.tzinfo or timezone.utc).timestamp(),
            self.stored.id,
        )


@dataclass(frozen=True)
class ProjectExposure:
    project: Project
    open: Tuple[OpenItem, ...] = ()         # worst first
    accepted: Tuple[OpenItem, ...] = ()

    @property
    def exposed(self) -> bool:
        return bool(self.open)

    @property
    def worst(self) -> Optional[OpenItem]:
        return self.open[0] if self.open else None

    @property
    def first_fix(self) -> str:
        """The first fixed version the open items name, the worst item first."""
        return next((item.match.fixed_version for item in self.open if item.match.fixed_version), "")


@dataclass(frozen=True)
class ExposureReport:
    """The exposure of every project, in the order of the project list."""

    projects: Tuple[ProjectExposure, ...] = ()

    @property
    def exposed(self) -> Tuple[ProjectExposure, ...]:
        return tuple(entry for entry in self.projects if entry.exposed)

    def of(self, project: Project) -> ProjectExposure:
        return next(
            (entry for entry in self.projects if entry.project.key == project.key),
            ProjectExposure(project),
        )

    @classmethod
    def build(
        cls,
        items: Sequence[StoredItem],
        projects: Sequence[Project],
        accepted: Optional[Mapping[RiskKey, AcceptedRisk]] = None,
    ) -> "ExposureReport":
        """From the stored matches. The read flag of an item plays no part."""
        risks = accepted or {}
        found: Dict[str, Dict[str, OpenItem]] = {project.key: {} for project in projects}
        for stored in items:
            if stored.relevance is not Relevance.AFFECTS_YOU:
                continue
            for match in stored.matches:
                key = project_key(match.project_path)
                if not match.confirmed or key not in found:
                    continue
                candidate = OpenItem(stored, match, risks.get((stored.id, key)))
                current = found[key].get(stored.id)
                if current is None or candidate.rank < current.rank:
                    found[key][stored.id] = candidate
        entries = []
        for project in projects:
            ordered = sorted(found[project.key].values(), key=lambda item: item.rank)
            entries.append(ProjectExposure(
                project,
                tuple(item for item in ordered if item.accepted is None),
                tuple(item for item in ordered if item.accepted is not None),
            ))
        return cls(tuple(entries))
