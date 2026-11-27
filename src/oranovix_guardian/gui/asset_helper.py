"""
asset_helper — resolves paths to bundled assets and translations.

Works in both development (source) and frozen (--onefile/--onedir) modes:
  - Frozen:  sys._MEIPASS  → temp extraction dir where PyInstaller unpacks data
  - Dev:     project root  → resolved from this file's location (gui/../)
"""
from __future__ import annotations

import os


def _base() -> str:
    from oranovix_guardian.core.app_paths import AppPaths
    return str(AppPaths.resource_dir())


def get_asset_path(filename: str) -> str:
    """Return absolute path to assets/<filename>."""
    return os.path.join(_base(), "assets", filename)


def get_translations_path() -> str:
    """Return absolute path to the translations/ directory."""
    return os.path.join(_base(), "translations")


def load_logo(size: int):
    """The app logo as a PIL image whose longer side is ``size`` px, or None.

    Uses ``icon_square.png`` (the tile without its background); at 20 px
    and below the shield-only ``icon_shield.png``, where the text would be
    noise. The aspect ratio of the source is always kept.
    """
    try:
        from PIL import Image
        name = "icon_shield.png" if size <= 20 else "icon_square.png"
        path = get_asset_path(name)
        if not os.path.exists(path):
            return None
        img = Image.open(path).convert("RGBA")
        img.thumbnail((size, size), Image.Resampling.LANCZOS)
        return img
    except Exception:
        return None
