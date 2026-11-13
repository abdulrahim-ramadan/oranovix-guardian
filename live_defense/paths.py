"""
Path facts shared by the ignore rules and the change classifier.

A "public" folder is one whose files the web server hands out or may run,
so a planted file there matters even inside folders that are normally
third-party noise (``static/node_modules``).
"""
from __future__ import annotations

from typing import FrozenSet, Iterable

PUBLIC_DIRS: FrozenSet[str] = frozenset({
    "upload", "uploads", "media", "static", "public", "tmp", "temp", "files", "images",
    "img", "assets", "attachments", "storage", "cache", "downloads", "public_html", "www",
    "wp-content",
})


def public_part(parts: Iterable[str]) -> str:
    """The first public folder name among *parts*, or ``""``."""
    return next((p for p in parts if p.lower() in PUBLIC_DIRS), "")
