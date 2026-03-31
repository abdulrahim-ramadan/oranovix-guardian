"""
asset_helper — resolves paths to bundled assets and translations.

Works in both development (source) and frozen (--onefile/--onedir) modes:
  - Frozen:  sys._MEIPASS  → temp extraction dir where PyInstaller unpacks data
  - Dev:     project root  → resolved from this file's location (gui/../)
"""
from __future__ import annotations

import os
import sys


def _base() -> str:
    if getattr(sys, "frozen", False):
        return sys._MEIPASS          # type: ignore[attr-defined]
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_asset_path(filename: str) -> str:
    """Return absolute path to assets/<filename>."""
    return os.path.join(_base(), "assets", filename)


def get_translations_path() -> str:
    """Return absolute path to the translations/ directory."""
    return os.path.join(_base(), "translations")
