"""
Feed sources: the CISA list of exploited vulnerabilities and RSS / Atom news.

A source only downloads its own public URL. Each one keeps its own
health, so a broken feed shows up in the Sources tab and the others
carry on.
"""
from __future__ import annotations

import json
import re
from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from oranovix_guardian.scanner_engine.base import Severity

from .fetcher import FetchError, Fetcher
from .models import CacheValidators, FeedError, FeedItem, FeedSource, PackageRef, SourceHealth
from .sanitize import SafeUrl, TextCleaner

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DownloadedFeedSource(FeedSource):
    """A source that is one https download; subclasses only parse the body."""

    MAX_ITEMS = 200         # news: only the newest headlines matter

    def __init__(self, name: str, url: str, language: str = "en", clock: Clock = utc_now) -> None:
        super().__init__(name, url, language)
        self._clock = clock
        self._health = SourceHealth(name)
        self._validators = CacheValidators()

    @property
    def health(self) -> SourceHealth:
        return self._health

    @property
    def validators(self) -> CacheValidators:
        return self._validators

    def restore(self, health: Optional[SourceHealth], validators: Optional[CacheValidators]) -> None:
        """Continue from what an earlier session stored."""
        if health is not None:
            self._health = health
        if validators is not None:
            self._validators = validators

    def fetch(self, fetcher: Fetcher) -> List[FeedItem]:
        try:
            if not SafeUrl.is_https(self.url):
                raise FeedError("Only https feeds are downloaded.")
            response = fetcher.get(self.url, self._validators.etag, self._validators.last_modified)
            if response.unchanged:
                self._succeeded()
                return []
            if not response.ok:
                raise FeedError(f"The server answered with status {response.status}.")
            items = self.parse(response.body)[: self.MAX_ITEMS]
            self._validators = CacheValidators(response.etag, response.last_modified)
            self._succeeded()
            return items
        except (FeedError, FetchError) as exc:
            self._failed(str(exc))
            raise FeedError(f"{self.name}: {exc}") from exc
        except Exception as exc:        # a feed must never take the app down
            self._failed(type(exc).__name__)
            raise FeedError(f"{self.name}: {type(exc).__name__}") from exc

    @abstractmethod
    def parse(self, body: bytes) -> List[FeedItem]:
        """Turn the downloaded bytes into items. Raise ``FeedError`` when they make no sense."""

    def _succeeded(self) -> None:
        self._health = SourceHealth(
            self.name, self._clock(), self._health.last_error, self._health.last_error_at
        )

    def _failed(self, error: str) -> None:
        self._health = SourceHealth(
            self.name, self._health.last_success, error[:300], self._clock()
        )


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------

class CisaKevSource(DownloadedFeedSource):
    """The CISA catalog of vulnerabilities that are exploited in the wild."""

    NAME = "CISA KEV"
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
    # The whole catalog is kept: an entry from years ago can still hit a project.
    MAX_ITEMS = 5000

    _CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

    def __init__(
        self, name: str = NAME, url: str = URL, language: str = "en", clock: Clock = utc_now
    ) -> None:
        super().__init__(name, url, language, clock)

    def parse(self, body: bytes) -> List[FeedItem]:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise FeedError("The catalog is not valid JSON.") from exc
        entries = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise FeedError("The catalog has no list of vulnerabilities.")

        items = [item for entry in entries for item in [self._item(entry)] if item is not None]
        # Newest first, so the cap would drop the oldest entries.
        items.sort(key=lambda item: item.published or datetime.min.replace(tzinfo=timezone.utc),
                   reverse=True)
        return items

    def _item(self, entry: Any) -> Optional[FeedItem]:
        if not isinstance(entry, Mapping):
            return None
        cve = str(entry.get("cveID") or "").strip().upper()
        if not self._CVE.match(cve):
            return None
        vendor = str(entry.get("vendorProject") or "")
        product = str(entry.get("product") or "")
        name = str(entry.get("vulnerabilityName") or "") or f"{vendor} {product}".strip()
        ransomware = str(entry.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        return FeedItem.build(
            source=self.name,
            key=cve,
            title=f"{cve}: {name}",
            url=self.DETAIL_URL.format(cve=cve),
            published=self._date(entry.get("dateAdded")),
            summary=entry.get("shortDescription") or "",
            cve_ids=[cve],
            packages=[PackageRef("", product), PackageRef("", vendor)],
            is_known_exploited=True,
            severity_hint=Severity.CRITICAL if ransomware else Severity.HIGH,
        )

    @staticmethod
    def _date(value: Any) -> Optional[datetime]:
        try:
            return datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# RSS 2.0 and Atom
# ---------------------------------------------------------------------------

class RssSource(DownloadedFeedSource):
    """Generic news feed in RSS 2.0, RSS 1.0 or Atom."""

    _ENTRY_TAGS = frozenset({"item", "entry"})
    # CERT-Bund and others put the rating in the headline: "[hoch] Linux Kernel: ..."
    _RATING = re.compile(r"\[\s*(kritisch|critical|hoch|high|mittel|medium|niedrig|low)\s*\]", re.IGNORECASE)
    _RATINGS: Dict[str, Severity] = {
        "kritisch": Severity.CRITICAL, "critical": Severity.CRITICAL,
        "hoch": Severity.HIGH, "high": Severity.HIGH,
        "mittel": Severity.MEDIUM, "medium": Severity.MEDIUM,
        "niedrig": Severity.LOW, "low": Severity.LOW,
    }

    def parse(self, body: bytes) -> List[FeedItem]:
        try:
            # No DTD at all: that rules out entity expansion and external entities.
            root = SafeElementTree.fromstring(body, forbid_dtd=True)
        except DefusedXmlException as exc:
            raise FeedError(f"The feed uses forbidden XML ({type(exc).__name__}).") from exc
        except (ParseError, ValueError) as exc:
            raise FeedError("The feed is not valid XML.") from exc
        if self._local(root.tag) not in ("rss", "feed", "RDF"):
            raise FeedError("The document is not an RSS or Atom feed.")

        items: List[FeedItem] = []
        for element in root.iter():
            if self._local(element.tag) not in self._ENTRY_TAGS:
                continue
            item = self._item(element)
            if item is not None:
                items.append(item)
            if len(items) >= self.MAX_ITEMS:
                break
        return items

    def _item(self, element: Element) -> Optional[FeedItem]:
        fields: Dict[str, Element] = {}
        links: List[Element] = []
        for child in element:
            name = self._local(child.tag)
            if name == "link":
                links.append(child)
            fields.setdefault(name, child)

        title = self._text(fields.get("title"))
        # "is not None": an element without children is falsy.
        summary = next(
            (self._text(fields[name]) for name in ("description", "summary", "content")
             if fields.get(name) is not None),
            "",
        )
        link = self._link(links)
        guid = self._text(fields.get("guid")) or self._text(fields.get("id"))
        rating = self._RATING.search(title)
        return FeedItem.build(
            source=self.name,
            key=guid or link,
            title=title,
            url=link,
            published=self._date(fields),
            summary=summary,
            severity_hint=self._RATINGS[rating.group(1).lower()] if rating else None,
        )

    @staticmethod
    def _local(tag: Any) -> str:
        return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

    @staticmethod
    def _text(element: Optional[Element]) -> str:
        if element is None:
            return ""
        return "".join(element.itertext()).strip()

    @classmethod
    def _link(cls, links: Sequence[Element]) -> str:
        """RSS writes the link as text; Atom as ``href`` of the "alternate" link."""
        for link in links:
            href = (link.get("href") or "").strip()
            if href and link.get("rel", "alternate") == "alternate":
                return href
        for link in links:
            text = cls._text(link)
            if text:
                return text
        return ""

    @classmethod
    def _date(cls, fields: Mapping[str, Element]) -> Optional[datetime]:
        rfc822 = cls._text(fields.get("pubDate"))
        if rfc822:
            try:
                return parsedate_to_datetime(rfc822)
            except (TypeError, ValueError):
                return None
        for name in ("published", "updated", "date"):
            text = cls._text(fields.get(name))
            if text:
                try:
                    return datetime.fromisoformat(text.replace("Z", "+00:00"))
                except ValueError:
                    return None
        return None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class SourceKind(str, Enum):
    RSS = "rss"
    KEV = "kev"


@dataclass(frozen=True)
class SourceConfig:
    """One entry of the source list in ``settings.json``."""

    name: str
    url: str
    language: str = "en"
    enabled: bool = True
    kind: SourceKind = SourceKind.RSS

    @property
    def host(self) -> str:
        return SafeUrl.host(self.url)

    def to_json(self) -> Dict[str, object]:
        return {
            "name": self.name, "url": self.url, "language": self.language,
            "enabled": self.enabled, "kind": self.kind.value,
        }


class SourceCatalog:
    """The default source list, and reading a list back from settings."""

    MAX_SOURCES = 20

    # Addresses as published by the sites themselves (checked 2026-11-16).
    DEFAULTS: Tuple[SourceConfig, ...] = (
        SourceConfig(CisaKevSource.NAME, CisaKevSource.URL, "en", True, SourceKind.KEV),
        SourceConfig("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "en"),
        SourceConfig("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "en"),
        SourceConfig("BSI CERT-Bund", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "de"),
    )

    @classmethod
    def from_json(cls, raw: object) -> Tuple[SourceConfig, ...]:
        """Valid entries of a JSON list. Anything that is not an https source is left out."""
        if not isinstance(raw, list):
            return cls.DEFAULTS
        configs: Dict[str, SourceConfig] = {}
        for entry in raw:
            config = cls._config(entry)
            if config is not None and config.name not in configs:
                configs[config.name] = config
            if len(configs) >= cls.MAX_SOURCES:
                break
        return tuple(configs.values())

    @classmethod
    def parse_text(cls, text: str) -> Tuple[SourceConfig, ...]:
        """Read the list as the user edits it in Settings. Raises ``ValueError``."""
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise ValueError("The source list is not valid JSON.") from exc
        if not isinstance(raw, list):
            raise ValueError("The source list must be a JSON list.")
        configs = cls.from_json(raw)
        if len(configs) != len(raw):
            raise ValueError(
                "Every source needs a unique name and an https url "
                f"(at most {cls.MAX_SOURCES} sources)."
            )
        return configs

    @staticmethod
    def to_text(configs: Iterable[SourceConfig]) -> str:
        return json.dumps([config.to_json() for config in configs], indent=2, ensure_ascii=False)

    @staticmethod
    def _config(entry: object) -> Optional[SourceConfig]:
        if not isinstance(entry, Mapping):
            return None
        name = TextCleaner.plain(entry.get("name"))[:60]
        url = SafeUrl.clean(entry.get("url"))
        if not name or not SafeUrl.is_https(url):
            return None
        language = TextCleaner.plain(entry.get("language") or "en")[:5].lower() or "en"
        try:
            kind = SourceKind(str(entry.get("kind") or "rss").lower())
        except ValueError:
            return None
        return SourceConfig(name, url, language, entry.get("enabled", True) is not False, kind)

    @staticmethod
    def build(config: SourceConfig, clock: Clock = utc_now) -> DownloadedFeedSource:
        if config.kind is SourceKind.KEV:
            return CisaKevSource(config.name, config.url, config.language, clock)
        return RssSource(config.name, config.url, config.language, clock)

    @staticmethod
    def hosts(configs: Iterable[SourceConfig]) -> List[str]:
        """Hosts the enabled sources contact, for the consent dialog."""
        return sorted({config.host for config in configs if config.enabled and config.host})
