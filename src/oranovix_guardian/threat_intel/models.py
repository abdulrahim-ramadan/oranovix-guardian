"""
Data model of the Threat Feed.

A ``FeedSource`` downloads one public feed and turns it into ``FeedItem``
objects. Nothing about the user's projects is ever part of a request:
matching against the projects happens later and only on this machine.
"""
from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple

from oranovix_guardian.scanner_engine.base import Severity

from .sanitize import SafeUrl, TextCleaner

if TYPE_CHECKING:
    from .fetcher import Fetcher


class Relevance(str, Enum):
    """How much a feed item has to do with the user's own projects."""

    AFFECTS_YOU = "affects_you"     # an installed version is inside a vulnerable range
    POSSIBLE = "possible"           # only a vendor or product name matched; verify
    GENERAL = "general"

    @property
    def rank(self) -> int:
        return {Relevance.AFFECTS_YOU: 0, Relevance.POSSIBLE: 1, Relevance.GENERAL: 2}[self]


@dataclass(frozen=True)
class PackageRef:
    """A package an item talks about.

    ``ecosystem`` is an OSV name ("PyPI", "npm") when the feed states it and
    ``""`` when the feed only gives a vendor or product name.
    """

    ecosystem: str
    name: str


@dataclass(frozen=True)
class FeedItem:
    """One entry of a feed: a headline and a link, never the article itself."""

    id: str
    source: str
    title: str
    url: str
    published: Optional[datetime]
    summary: str = ""
    cve_ids: Tuple[str, ...] = ()
    packages: Tuple[PackageRef, ...] = ()
    is_known_exploited: bool = False
    severity_hint: Optional[Severity] = None

    @staticmethod
    def make_id(source: str, key: str) -> str:
        """Stable id: hash of the source name and the entry's guid or url."""
        raw = f"{source}\n{key}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:32]

    @classmethod
    def build(
        cls,
        source: str,
        key: object,
        title: object,
        url: object,
        published: Optional[datetime] = None,
        summary: object = "",
        cve_ids: Sequence[str] = (),
        packages: Sequence[PackageRef] = (),
        is_known_exploited: bool = False,
        severity_hint: Optional[Severity] = None,
    ) -> Optional["FeedItem"]:
        """Create an item from raw feed values, or ``None`` when it is unusable.

        Every source goes through here, so every item is cleaned the same
        way. An entry without a title or without a web link is dropped.
        """
        clean_title = TextCleaner.title(title)
        clean_url = SafeUrl.clean(url)
        if not clean_title or not clean_url:
            return None
        ids = dict.fromkeys(
            (*TextCleaner.cve_ids(" ".join(str(c) for c in cve_ids)),
             *TextCleaner.cve_ids(title, summary))
        )
        refs = tuple(
            PackageRef(TextCleaner.plain(p.ecosystem)[:40], TextCleaner.plain(p.name)[:120])
            for p in packages
            if TextCleaner.plain(p.name)
        )
        return cls(
            id=cls.make_id(source, str(key or "").strip() or clean_url),
            source=source,
            title=clean_title,
            url=clean_url,
            published=cls._utc(published),
            summary=TextCleaner.summary(summary),
            cve_ids=tuple(ids),
            packages=refs,
            is_known_exploited=is_known_exploited,
            severity_hint=severity_hint,
        )

    @staticmethod
    def _utc(moment: Optional[datetime]) -> Optional[datetime]:
        if moment is None:
            return None
        if moment.tzinfo is None:
            return moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)


@dataclass(frozen=True)
class ProjectMatch:
    """Why an item concerns one project: which package matched, and how."""

    project: str
    project_path: str
    package: str
    ecosystem: str = ""
    version: str = ""               # installed version; "" when it is not pinned
    advisory_id: str = ""           # the local OSV advisory; "" for a name-only match
    severity: Optional[Severity] = None
    fixed_version: str = ""
    file_path: str = ""             # manifest that declares the package
    line: int = 0

    @property
    def confirmed(self) -> bool:
        """True when a local advisory covers the installed version."""
        return bool(self.advisory_id)


def project_key(path: str) -> str:
    """A project folder in a form that compares equal however it was typed."""
    return os.path.normcase(os.path.abspath(path))


RiskKey = Tuple[str, str]       # item id, project folder


@dataclass(frozen=True)
class AcceptedRisk:
    """The user decided to live with one item in one project, and wrote down why."""

    item_id: str
    project_path: str
    reason: str
    accepted_at: Optional[datetime] = None

    @property
    def key(self) -> RiskKey:
        return (self.item_id, project_key(self.project_path))


@dataclass(frozen=True)
class StoredItem:
    """A feed item as kept in the local store."""

    item: FeedItem
    first_seen: datetime
    read: bool = False
    relevance: Relevance = Relevance.GENERAL
    matches: Tuple[ProjectMatch, ...] = ()
    background: bool = False        # old catalog entry: kept for matching, not news

    @property
    def id(self) -> str:
        return self.item.id

    @property
    def counts_as_new(self) -> bool:
        """A background item is news only once it affects a project."""
        return not self.background or self.relevance is Relevance.AFFECTS_YOU


@dataclass(frozen=True)
class SourceHealth:
    """When a source last worked and what went wrong last."""

    name: str
    last_success: Optional[datetime] = None
    last_error: str = ""
    last_error_at: Optional[datetime] = None

    @property
    def ok(self) -> bool:
        """True when the newest attempt succeeded."""
        if self.last_success is None:
            return False
        return self.last_error_at is None or self.last_success >= self.last_error_at


@dataclass(frozen=True)
class CacheValidators:
    """What the server said about the last download, for conditional requests."""

    etag: str = ""
    last_modified: str = ""


class FeedError(RuntimeError):
    """A feed could not be downloaded or understood."""


class FeedSource(ABC):
    """One public feed."""

    def __init__(self, name: str, url: str, language: str = "en") -> None:
        self._name = name
        self._url = url
        self._language = language

    @property
    def name(self) -> str:
        return self._name

    @property
    def url(self) -> str:
        return self._url

    @property
    def language(self) -> str:
        return self._language

    @property
    def host(self) -> str:
        return SafeUrl.host(self._url)

    @property
    @abstractmethod
    def health(self) -> SourceHealth:
        """Outcome of the attempts so far."""

    @abstractmethod
    def fetch(self, fetcher: "Fetcher") -> List[FeedItem]:
        """Download the feed and return its items.

        Returns an empty list when the server says nothing changed. Raises
        ``FeedError`` on failure, after noting it in ``health``.
        """
