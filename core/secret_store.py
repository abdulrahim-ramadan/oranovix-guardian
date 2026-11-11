"""
Secure storage for the Gemini API key.

The key is kept in the operating system's credential store through the
``keyring`` package (Windows Credential Manager on Windows). It is never
written to ``settings.json`` or any other plain-text file.

When no usable credential store exists, the store reports itself as
unavailable: ``get()`` returns an empty string, ``set()`` and ``delete()``
raise ``SecretStoreError``. The application then works with the
``GEMINI_API_KEY`` environment variable only.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)

SERVICE_NAME = "OranovixGuardian"
GEMINI_KEY_NAME = "gemini_api_key"


class SecretStoreError(RuntimeError):
    """The credential store is missing or refused the operation."""


class SecretStore:
    """Reads and writes one secret in the OS credential store."""

    def __init__(self, service: str = SERVICE_NAME, name: str = GEMINI_KEY_NAME) -> None:
        self._service = service
        self._name = name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self) -> str:
        """Return the stored secret, or ``""`` when none is stored or the
        credential store cannot be used."""
        try:
            value = self._keyring().get_password(self._service, self._name)
        except Exception as exc:
            logger.warning("Credential store could not be read: %s", self._describe(exc))
            return ""
        return (value or "").strip()

    def set(self, value: str) -> None:
        """Store *value*. Raises ``SecretStoreError`` when it cannot be stored."""
        value = value.strip()
        if not value:
            raise SecretStoreError("An empty key cannot be saved.")
        try:
            self._keyring().set_password(self._service, self._name, value)
        except Exception as exc:
            raise SecretStoreError(self._describe(exc)) from exc

    def delete(self) -> None:
        """Remove the stored secret. Removing a secret that does not exist
        is not an error."""
        try:
            keyring = self._keyring()
            if keyring.get_password(self._service, self._name) is None:
                return
            keyring.delete_password(self._service, self._name)
        except Exception as exc:
            raise SecretStoreError(self._describe(exc)) from exc

    def is_available(self) -> bool:
        """Report whether a real credential store is present."""
        try:
            backend = self._keyring().get_keyring()
        except Exception:
            return False
        # keyring installs a "fail" backend (priority 0) when nothing usable
        # was found; every call on it raises.
        return float(getattr(backend, "priority", 0) or 0) > 0

    @staticmethod
    def mask(value: str) -> str:
        """Return *value* with everything but the last four characters hidden."""
        value = value.strip()
        if not value:
            return ""
        if len(value) < 8:
            return "••••"
        return "••••" + value[-4:]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _keyring() -> Any:
        import keyring

        if sys.platform == "win32":
            # Imported by name so the frozen exe always bundles the backend.
            import keyring.backends.Windows  # noqa: F401
        return keyring

    @staticmethod
    def _describe(exc: Exception) -> str:
        return f"{type(exc).__name__}: {exc}"
