"""
The user's projects: where they are, what they depend on, how the last scan went.

Everything here is local. The inventory is read from the manifests with
the parsers of the dependency scanner; nothing is sent anywhere.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from oranovix_guardian.core.scan_history import ScanHistory
from oranovix_guardian.scanner_engine.deps.manifests import Dependency, ManifestError, ManifestFinder

from .sanitize import SafeUrl, TextCleaner
from .store import FeedDatabase


class ProjectError(ValueError):
    """A project could not be added or changed; the message is shown to the user."""


@dataclass(frozen=True)
class Project:
    name: str
    path: str
    site_url: Optional[str] = None

    @property
    def key(self) -> str:
        """The folder in a form that compares equal however it was typed."""
        return os.path.normcase(os.path.abspath(self.path))


class ProjectRegistry:
    """The list of projects, kept in ``feed.db``."""

    MAX_NAME = 60
    # Translation key of the notice shown whenever a site address is entered.
    SITE_NOTICE_KEY = "proj_site_notice"

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS projects (
            name TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            site_url TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL DEFAULT ''
        );
    """

    def __init__(self, database: Optional[FeedDatabase] = None) -> None:
        self._db = database or FeedDatabase()
        self._db.script(self._SCHEMA)

    def add(self, name: str, path: str, site_url: Optional[str] = None) -> Project:
        project = Project(self._name(name), self._folder(path), self._site(site_url))
        for existing in self.list():
            if existing.name.lower() == project.name.lower():
                raise ProjectError(f"A project named {project.name} already exists.")
            if existing.key == project.key:
                raise ProjectError(f"This folder is already the project {existing.name}.")
        self._db.write(
            "INSERT INTO projects (name, path, site_url, added_at) VALUES (?, ?, ?, ?)",
            (project.name, project.path, project.site_url or "", datetime.now().isoformat()),
        )
        return project

    def remove(self, name: str) -> bool:
        return self._db.write("DELETE FROM projects WHERE name = ?", (name,)) > 0

    def set_site_url(self, name: str, site_url: Optional[str]) -> Project:
        project = self.get(name)
        if project is None:
            raise ProjectError(f"There is no project named {name}.")
        url = self._site(site_url)
        self._db.write("UPDATE projects SET site_url = ? WHERE name = ?", (url or "", name))
        return Project(project.name, project.path, url)

    def list(self) -> List[Project]:
        rows = self._db.read("SELECT name, path, site_url FROM projects ORDER BY name COLLATE NOCASE")
        return [Project(name, path, site_url or None) for name, path, site_url in rows]

    def get(self, name: str) -> Optional[Project]:
        return next((project for project in self.list() if project.name == name), None)

    @classmethod
    def site_notice_key(cls, project: Project) -> str:
        """The notice to show for *project*, or ``""`` when it has no site address."""
        return cls.SITE_NOTICE_KEY if project.site_url else ""

    @classmethod
    def _name(cls, name: str) -> str:
        clean = TextCleaner.plain(name)[: cls.MAX_NAME]
        if not clean:
            raise ProjectError("Give the project a name.")
        return clean

    @staticmethod
    def _folder(path: str) -> str:
        folder = os.path.abspath(path) if path and path.strip() else ""
        if not folder or not os.path.isdir(folder):
            raise ProjectError("Choose the folder of the project.")
        return folder

    @staticmethod
    def _site(site_url: Optional[str]) -> Optional[str]:
        if site_url is None or not site_url.strip():
            return None
        url = SafeUrl.clean(site_url)
        if not url:
            raise ProjectError("The site address must start with http:// or https://.")
        return url


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Inventory:
    """Every dependency the manifests of one project declare."""

    project: Project
    dependencies: Tuple[Dependency, ...]
    warnings: Tuple[str, ...] = ()

    def packages(self) -> List[Tuple[str, str, Optional[str]]]:
        """``(ecosystem, name, version)``; the version is ``None`` when not pinned."""
        return [(d.ecosystem.value, d.name, d.version) for d in self.dependencies]


class InventoryBuilder:
    """Reads the manifests of a project with the dependency scanner's parsers."""

    def build(self, project: Project) -> Inventory:
        dependencies: List[Dependency] = []
        warnings: List[str] = []
        if not os.path.isdir(project.path):
            return Inventory(project, (), (f"The folder {project.path} is missing.",))
        for file_path, parser in ManifestFinder.find(project.path):
            try:
                dependencies.extend(parser.parse(file_path))
            except ManifestError as exc:
                warnings.append(str(exc))
        return Inventory(project, tuple(dependencies), tuple(warnings))

    def build_all(self, projects: List[Project]) -> List[Inventory]:
        return [self.build(project) for project in projects]


# ---------------------------------------------------------------------------
# Latest scan
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanSummary:
    scanned_at: Optional[datetime]
    critical: int
    high: int
    total_issues: int
    risk_score: int


class ScanSummaryLookup:
    """Finds the newest entry of the scan history for a project folder."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or ScanHistory._resolve_db_path()

    def latest_for(self, project: Project) -> Optional[ScanSummary]:
        if not os.path.isfile(self._db_path):
            return None
        try:
            with closing(sqlite3.connect(self._db_path)) as conn:
                rows = conn.execute(
                    "SELECT scan_date, target_path, critical_count, high_count, "
                    "total_issues, risk_score FROM scans ORDER BY id DESC"
                ).fetchall()
        except sqlite3.Error:
            return None
        for scan_date, target, critical, high, total, score in rows:
            if os.path.normcase(os.path.abspath(str(target))) == project.key:
                return ScanSummary(
                    self._date(scan_date), int(critical or 0), int(high or 0),
                    int(total or 0), int(score or 0),
                )
        return None

    @staticmethod
    def _date(text: object) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(str(text))
        except ValueError:
            return None
