"""
Path facts shared by the ignore rules and the change classifier.

A "public" folder is one whose files the web server hands out or may run,
so a planted file there matters even inside folders that are normally
third-party noise (``static/node_modules``).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import FrozenSet, Iterable

PUBLIC_DIRS: FrozenSet[str] = frozenset({
    "upload", "uploads", "media", "static", "public", "tmp", "temp", "files", "images",
    "img", "assets", "attachments", "storage", "cache", "downloads", "public_html", "www",
    "wp-content",
})


# Public folders that hold user files, where code never belongs. Web roots
# (static, public_html, wp-content...) legitimately hold the site's own code.
UPLOAD_DIRS: FrozenSet[str] = frozenset({
    "upload", "uploads", "media", "tmp", "temp", "files", "images", "img", "attachments", "downloads",
})


def public_part(parts: Iterable[str]) -> str:
    """The first public folder name among *parts*, or ``""``."""
    return next((p for p in parts if p.lower() in PUBLIC_DIRS), "")


def upload_part(parts: Iterable[str]) -> str:
    return next((p for p in parts if p.lower() in UPLOAD_DIRS), "")


@dataclass(frozen=True)
class LinkInfo:
    """Where a symlink or junction points."""

    target: str             # as written in the link
    resolved: str           # final path after following every link
    outside_root: bool      # also True when the target cannot be read


def strip_extended_prefix(path: str) -> str:
    """``\\\\?\\C:\\x`` and ``\\??\\C:\\x`` (how Windows stores junction targets) -> ``C:\\x``."""
    for prefix, keep in ((r"\\?\UNC" + "\\", "\\\\"), (r"\\?" + "\\", ""), (r"\??" + "\\", "")):
        if path.startswith(prefix):
            return keep + path[len(prefix):]
    return path


def is_inside(path: str, root: str) -> bool:
    path, root = os.path.normcase(path), os.path.normcase(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:      # different drives
        return False
