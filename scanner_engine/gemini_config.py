"""
Gemini model selection shared by the AI analyzer and the AI fix generator.

Model names are retired regularly, so the name is read from
``settings.json`` (key ``gemini_model``) and defaults to an alias that
Google keeps pointed at the current Flash model.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_GEMINI_MODEL = "gemini-flash-latest"
GEMINI_MODEL_SETTING = "gemini_model"


class GeminiModelNotFoundError(RuntimeError):
    """The configured Gemini model does not exist (HTTP 404)."""

    def __init__(self, model: str) -> None:
        self.model = model
        super().__init__(
            f"Gemini model '{model}' was not found (HTTP 404). It may have been "
            f"retired. Set \"{GEMINI_MODEL_SETTING}\" in settings.json to a "
            f"current model, for example \"{DEFAULT_GEMINI_MODEL}\"."
        )


class GeminiConfig:
    """Reads Gemini settings from the application's settings.json."""

    @staticmethod
    def settings_path() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).parent / "settings.json"
        return Path(__file__).parent.parent / "settings.json"

    @classmethod
    def _read(cls) -> dict:
        try:
            data = json.loads(cls.settings_path().read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @classmethod
    def model_name(cls) -> str:
        """Return the configured model, or the default when none is set."""
        configured = str(cls._read().get(GEMINI_MODEL_SETTING, "")).strip()
        return configured or DEFAULT_GEMINI_MODEL

    @classmethod
    def api_key(cls) -> str:
        return str(cls._read().get("api_key", "")).strip()
