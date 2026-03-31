"""
LanguageManager — Singleton service that drives all multilingual support.

Design:
  • Singleton via __new__ (only one instance for the process lifetime)
  • Observer pattern: UI components register callbacks; all are called when
    the active language changes so the entire interface refreshes instantly
  • Loads translations from translations/{lang}.json at startup
  • Exposes RTL/LTR helpers consumed by both the GUI and PDF generator
  • Provides Arabic text-shaping utility for correct PDF rendering
"""
from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Abstract observer (optional — callers may also pass plain callables)
# ---------------------------------------------------------------------------

class LanguageObserver(ABC):
    """Abstract base for objects that react to language changes."""

    @abstractmethod
    def on_language_changed(self, lang: str) -> None:
        """Called with the new ISO-639-1 language code."""


# ---------------------------------------------------------------------------
# Singleton LanguageManager
# ---------------------------------------------------------------------------

class LanguageManager:
    """
    Central translation and layout-direction manager.

    Usage (anywhere in the codebase):
        lm = LanguageManager()         # always the same instance
        lm.set_language("ar")
        label = lm.t("start_scan")
        sidebar_side = lm.pack_side    # "right" when Arabic
    """

    # ── Singleton bookkeeping ──────────────────────────────────────────────
    _instance:     Optional["LanguageManager"] = None
    _initialized:  bool = False

    # ── Supported languages ───────────────────────────────────────────────
    RTL_LANGUAGES: Set[str] = {"ar"}
    SUPPORTED:     Set[str] = {"en", "de", "ar"}
    DISPLAY_NAMES: Dict[str, str] = {
        "en": "English",
        "de": "Deutsch",
        "ar": "العربية",
    }

    # ── Singleton constructor ─────────────────────────────────────────────

    def __new__(cls) -> "LanguageManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        self._current_lang: str = "en"
        self._translations: Dict[str, Dict[str, str]] = {}
        self._observers: List[Callable[[], None]] = []
        self._translations_dir: Path = self._find_translations_dir()
        self._load_all()

    # ── Public factory ────────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "LanguageManager":
        """Convenience alias — identical to LanguageManager()."""
        return cls()

    # ── Language switching ────────────────────────────────────────────────

    def set_language(self, lang: str) -> None:
        """Switch to *lang* (ISO-639-1 code) and notify all observers."""
        if lang not in self._translations:
            return
        if lang == self._current_lang:
            return
        self._current_lang = lang
        self._notify()

    def set_language_by_display(self, display_name: str) -> None:
        """Switch by human-readable name (e.g. 'Deutsch', 'العربية')."""
        reverse = {v: k for k, v in self.DISPLAY_NAMES.items()}
        lang = reverse.get(display_name)
        if lang:
            self.set_language(lang)

    # ── Translation ───────────────────────────────────────────────────────

    def t(self, key: str, **kwargs: object) -> str:
        """
        Return the translated string for *key* in the active language.
        Falls back to English, then to the bare key.
        Supports named format placeholders: lm.t("key", count=5)
        """
        text = (
            self._translations.get(self._current_lang, {}).get(key)
            or self._translations.get("en", {}).get(key)
            or key
        )
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, IndexError):
                pass
        return text

    # ── Layout direction helpers ──────────────────────────────────────────

    @property
    def is_rtl(self) -> bool:
        """True when the active language reads right-to-left."""
        return self._current_lang in self.RTL_LANGUAGES

    @property
    def pack_side(self) -> str:
        """
        Primary pack side for the sidebar.
        'right' when RTL (Arabic), 'left' otherwise.
        """
        return "right" if self.is_rtl else "left"

    @property
    def text_anchor(self) -> str:
        """Tkinter anchor: 'e' for RTL, 'w' for LTR."""
        return "e" if self.is_rtl else "w"

    @property
    def text_justify(self) -> str:
        """Tkinter justify: 'right' for RTL, 'left' for LTR."""
        return "right" if self.is_rtl else "left"

    @property
    def opposite_side(self) -> str:
        """Opposite of pack_side — used for elements that sit on the far end."""
        return "left" if self.is_rtl else "right"

    # ── Language metadata ─────────────────────────────────────────────────

    @property
    def current_lang(self) -> str:
        return self._current_lang

    @property
    def current_display_name(self) -> str:
        return self.DISPLAY_NAMES.get(self._current_lang, "English")

    @property
    def display_names(self) -> List[str]:
        return list(self.DISPLAY_NAMES.values())

    def available_languages(self) -> List[str]:
        """ISO codes of languages that have translation files loaded."""
        return list(self._translations.keys())

    # ── Observer management ───────────────────────────────────────────────

    def add_observer(self, callback: Callable[[], None]) -> None:
        """Register a zero-argument callable to be called on lang change."""
        if callback not in self._observers:
            self._observers.append(callback)

    def remove_observer(self, callback: Callable[[], None]) -> None:
        self._observers = [o for o in self._observers if o is not callback]

    def clear_observers(self) -> None:
        """Remove all registered observers (call before rebuilding UI)."""
        self._observers.clear()

    # ── Arabic text utilities (PDF rendering) ─────────────────────────────

    @staticmethod
    def process_arabic_for_pdf(text: str) -> str:
        """
        Reshape Arabic glyphs and apply the Unicode BiDi algorithm so
        ReportLab renders Arabic text correctly.

        Requires: arabic-reshaper, python-bidi
        Falls back to the raw string when those libraries are absent.
        """
        try:
            import arabic_reshaper              # type: ignore
            from bidi.algorithm import get_display  # type: ignore
            reshaped = arabic_reshaper.reshape(text)
            return get_display(reshaped)
        except Exception:
            return text

    @staticmethod
    def arabic_libs_available() -> bool:
        """Return True if arabic-reshaper and python-bidi are importable."""
        try:
            import arabic_reshaper              # type: ignore
            from bidi.algorithm import get_display  # type: ignore
            return True
        except ImportError:
            return False

    # ── Private helpers ───────────────────────────────────────────────────

    def _load_all(self) -> None:
        """Load every supported language from its JSON file."""
        for lang in self.SUPPORTED:
            path = self._translations_dir / f"{lang}.json"
            if path.exists():
                try:
                    with open(path, encoding="utf-8") as fh:
                        self._translations[lang] = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    self._translations[lang] = {}
            else:
                self._translations[lang] = {}

        # Always guarantee an English fallback dict exists
        self._translations.setdefault("en", {})

    @staticmethod
    def _find_translations_dir() -> Path:
        """
        Walk up from this file to locate (or create) the translations/
        directory at the project root.
        """
        try:
            from gui.asset_helper import get_translations_path
            return Path(get_translations_path())
        except ImportError:
            pass
        if getattr(sys, "frozen", False):
            return Path(sys._MEIPASS) / "translations"  # type: ignore[attr-defined]
        candidates = [
            Path(__file__).parent.parent / "translations",
            Path.cwd() / "translations",
        ]
        for p in candidates:
            if p.exists():
                return p
        fallback = Path(__file__).parent.parent / "translations"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

    def _notify(self) -> None:
        for cb in list(self._observers):
            try:
                cb()
            except Exception:
                pass
