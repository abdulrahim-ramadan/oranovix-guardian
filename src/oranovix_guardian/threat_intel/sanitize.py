"""
Cleaning of feed content. Everything a feed delivers is untrusted.

Titles and summaries become plain text: tags and entities are removed and
the length is capped. Links are kept only when they are http or https.
"""
from __future__ import annotations

import html
import re
from typing import Dict, Tuple
from urllib.parse import urlsplit


class TextCleaner:
    """Turns feed markup into short plain text."""

    TITLE_LIMIT = 200
    SUMMARY_LIMIT = 400

    _BLOCKS = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
    _TAG = re.compile(r"<[^>]*>")
    _SPACE = re.compile(r"\s+")
    # Control characters and the marks that reorder text on screen.
    _CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
    _CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    @classmethod
    def plain(cls, text: object) -> str:
        """Plain text without tags, entities or control characters. Not capped."""
        value = str(text or "")
        # Feeds often carry escaped HTML inside the XML, so one pass is not enough.
        for _ in range(2):
            value = cls._BLOCKS.sub(" ", value)
            value = cls._TAG.sub(" ", value)
            value = html.unescape(value)
        value = cls._BLOCKS.sub(" ", value)
        value = cls._TAG.sub(" ", value)
        value = value.replace("<", " ").replace(">", " ")
        value = cls._SPACE.sub(" ", value)
        value = cls._CONTROL.sub("", value)
        return value.strip()

    @classmethod
    def title(cls, text: object) -> str:
        return cls._cap(cls.plain(text), cls.TITLE_LIMIT)

    @classmethod
    def summary(cls, text: object) -> str:
        return cls._cap(cls.plain(text), cls.SUMMARY_LIMIT)

    @classmethod
    def cve_ids(cls, *texts: object) -> Tuple[str, ...]:
        """Every CVE id named in *texts*, upper case, in order of appearance."""
        found: Dict[str, None] = {}
        for text in texts:
            for match in cls._CVE.finditer(str(text or "")):
                found.setdefault(match.group(0).upper(), None)
        return tuple(found)

    @staticmethod
    def _cap(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 1].rstrip() + "…"


class SafeUrl:
    """Accepts web links only."""

    MAX_LENGTH = 2000
    SCHEMES = frozenset({"http", "https"})

    @classmethod
    def clean(cls, url: object) -> str:
        """The link when it is a plain http/https URL with a host, otherwise ``""``.

        Links with user info (``user:pw@host``) are refused: they hide the real host.
        """
        value = str(url or "").strip()
        if not value or len(value) > cls.MAX_LENGTH:
            return ""
        if any(c.isspace() or ord(c) < 32 for c in value):
            return ""
        try:
            parts = urlsplit(value)
            host = parts.hostname
        except ValueError:
            return ""
        if parts.scheme.lower() not in cls.SCHEMES or not host or "@" in parts.netloc:
            return ""
        return value

    @classmethod
    def host(cls, url: str) -> str:
        """Host of *url*, as shown to the user before a link is opened."""
        try:
            return (urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    @classmethod
    def is_https(cls, url: str) -> bool:
        try:
            parts = urlsplit(url)
            return parts.scheme.lower() == "https" and bool(parts.hostname)
        except ValueError:
            return False
