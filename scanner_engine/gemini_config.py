"""
Gemini settings shared by the AI analyzer and the AI fix generator.

Model names are retired regularly, so the name is read from
``settings.json`` (key ``gemini_model``) and defaults to an alias that
Google keeps pointed at the current Flash model.

The API key is never read from ``settings.json``. It comes from the
``GEMINI_API_KEY`` environment variable or from the OS credential store
(``core.secret_store.SecretStore``).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from core.secret_store import SecretStore, SecretStoreError

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_MODEL = "gemini-flash-latest"
GEMINI_MODEL_SETTING = "gemini_model"
GEMINI_API_KEY_ENV = "GEMINI_API_KEY"
LEGACY_API_KEY_SETTING = "api_key"


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
    """Reads Gemini settings: the model from settings.json, the key from
    the environment or the credential store."""

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
        """Return the Gemini API key: environment variable first, then the
        credential store. Empty string when neither has one."""
        cls.migrate_legacy_api_key()
        from_env = os.getenv(GEMINI_API_KEY_ENV, "").strip()
        return from_env or SecretStore().get()

    @classmethod
    def migrate_legacy_api_key(cls) -> bool:
        """Move a plain-text ``api_key`` from settings.json into the
        credential store and delete it from the file.

        Returns ``True`` when a key was moved. When the credential store
        cannot take the key, the file is left untouched so that nothing is
        lost and the move is tried again later.
        """
        data = cls._read()
        if LEGACY_API_KEY_SETTING not in data:
            return False

        legacy = str(data.get(LEGACY_API_KEY_SETTING) or "").strip()
        moved = False
        if legacy:
            store = SecretStore()
            try:
                # A key saved through the settings page is newer than the
                # one left in the file, so it is not overwritten.
                if not store.get():
                    store.set(legacy)
                    if store.get() != legacy:
                        raise SecretStoreError("the key could not be read back")
                    moved = True
            except SecretStoreError as exc:
                logger.warning(
                    "The API key in settings.json could not be moved to the "
                    "credential store (%s). It stays in the file for now.", exc
                )
                return False

        del data[LEGACY_API_KEY_SETTING]
        try:
            cls._write(data)
        except OSError as exc:
            logger.warning("settings.json could not be rewritten: %s", exc)
        return moved

    @classmethod
    def _write(cls, data: dict) -> None:
        path = cls.settings_path()
        temp = path.with_name(path.name + ".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(temp, path)
