"""SecretStore and the Gemini API key lookup, against a fake keyring backend."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.backends.fail import Keyring as FailKeyring
from keyring.errors import PasswordDeleteError

from core.secret_store import GEMINI_KEY_NAME, SERVICE_NAME, SecretStore, SecretStoreError
from scanner_engine.ai_analyzer import GeminiAnalyzer
from scanner_engine.ai_fix_generator import AIFixGenerator
from scanner_engine.gemini_config import GEMINI_API_KEY_ENV, GeminiConfig


class FakeKeyring(KeyringBackend):
    """In-memory backend; nothing reaches the real credential store."""

    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.passwords: Dict[Tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> Optional[str]:
        return self.passwords.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.passwords[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.passwords:
            raise PasswordDeleteError("not found")
        del self.passwords[(service, username)]


@pytest.fixture
def backend() -> Iterator[FakeKeyring]:
    previous = keyring.get_keyring()
    fake = FakeKeyring()
    keyring.set_keyring(fake)
    yield fake
    keyring.set_keyring(previous)


@pytest.fixture
def no_backend() -> Iterator[None]:
    previous = keyring.get_keyring()
    keyring.set_keyring(FailKeyring())
    yield
    keyring.set_keyring(previous)


@pytest.fixture
def settings_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated settings.json and no GEMINI_API_KEY in the environment."""
    path = tmp_path / "settings.json"
    monkeypatch.setattr(GeminiConfig, "settings_path", staticmethod(lambda: path))
    monkeypatch.delenv(GEMINI_API_KEY_ENV, raising=False)
    return path


def read_settings(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# SecretStore
# ---------------------------------------------------------------------------

def test_save_then_read(backend: FakeKeyring) -> None:
    SecretStore().set("AIzaSy-test-key-1234")

    assert SecretStore().get() == "AIzaSy-test-key-1234"
    assert backend.passwords == {(SERVICE_NAME, GEMINI_KEY_NAME): "AIzaSy-test-key-1234"}


def test_service_name_is_fixed() -> None:
    assert SERVICE_NAME == "OranovixGuardian"


def test_read_without_a_saved_key_is_empty(backend: FakeKeyring) -> None:
    assert SecretStore().get() == ""


def test_saved_key_is_stripped(backend: FakeKeyring) -> None:
    SecretStore().set("  AIzaSy-test-key-1234\n")

    assert SecretStore().get() == "AIzaSy-test-key-1234"


def test_empty_key_is_rejected(backend: FakeKeyring) -> None:
    with pytest.raises(SecretStoreError):
        SecretStore().set("   ")
    assert backend.passwords == {}


def test_remove(backend: FakeKeyring) -> None:
    store = SecretStore()
    store.set("AIzaSy-test-key-1234")

    store.delete()

    assert store.get() == ""
    assert backend.passwords == {}


def test_remove_without_a_saved_key_is_not_an_error(backend: FakeKeyring) -> None:
    SecretStore().delete()


def test_available_with_a_working_backend(backend: FakeKeyring) -> None:
    assert SecretStore().is_available() is True


def test_broken_keyring_reads_empty_and_refuses_writes(no_backend: None) -> None:
    store = SecretStore()

    assert store.is_available() is False
    assert store.get() == ""
    with pytest.raises(SecretStoreError):
        store.set("AIzaSy-test-key-1234")
    with pytest.raises(SecretStoreError):
        store.delete()


@pytest.mark.parametrize(
    "value, masked",
    [
        ("AIzaSy-test-key-1234", "••••1234"),
        ("12345678", "••••5678"),
        ("short", "••••"),
        ("", ""),
    ],
)
def test_mask_shows_only_the_last_four_characters(value: str, masked: str) -> None:
    assert SecretStore.mask(value) == masked


# ---------------------------------------------------------------------------
# GeminiConfig.api_key
# ---------------------------------------------------------------------------

def test_api_key_comes_from_the_store(backend: FakeKeyring, settings_file: Path) -> None:
    SecretStore().set("stored-key-0001")

    assert GeminiConfig.api_key() == "stored-key-0001"


def test_env_var_wins_over_the_store(
    backend: FakeKeyring, settings_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    SecretStore().set("stored-key-0001")
    monkeypatch.setenv(GEMINI_API_KEY_ENV, "env-key-0002")

    assert GeminiConfig.api_key() == "env-key-0002"


def test_api_key_is_empty_when_nothing_is_configured(
    backend: FakeKeyring, settings_file: Path
) -> None:
    assert GeminiConfig.api_key() == ""


def test_broken_keyring_falls_back_to_the_env_var(
    no_backend: None, settings_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert GeminiConfig.api_key() == ""

    monkeypatch.setenv(GEMINI_API_KEY_ENV, "env-key-0002")
    assert GeminiConfig.api_key() == "env-key-0002"


def test_both_ai_engines_use_the_same_key(backend: FakeKeyring, settings_file: Path) -> None:
    SecretStore().set("stored-key-0001")

    assert AIFixGenerator().api_key == "stored-key-0001"
    assert GeminiAnalyzer()._api_key == "stored-key-0001"


# ---------------------------------------------------------------------------
# Migration from settings.json
# ---------------------------------------------------------------------------

def test_legacy_key_moves_into_the_store(backend: FakeKeyring, settings_file: Path) -> None:
    settings_file.write_text(
        json.dumps({"theme": "dark", "api_key": "legacy-key-0003", "sound_volume": 0.5}),
        encoding="utf-8",
    )

    assert GeminiConfig.migrate_legacy_api_key() is True

    assert SecretStore().get() == "legacy-key-0003"
    assert read_settings(settings_file) == {"theme": "dark", "sound_volume": 0.5}
    assert "legacy-key-0003" not in settings_file.read_text(encoding="utf-8")


def test_migration_runs_only_once(backend: FakeKeyring, settings_file: Path) -> None:
    settings_file.write_text(json.dumps({"api_key": "legacy-key-0003"}), encoding="utf-8")

    assert GeminiConfig.migrate_legacy_api_key() is True
    assert GeminiConfig.migrate_legacy_api_key() is False
    assert SecretStore().get() == "legacy-key-0003"


def test_api_key_lookup_migrates_the_legacy_key(
    backend: FakeKeyring, settings_file: Path
) -> None:
    settings_file.write_text(json.dumps({"api_key": "legacy-key-0003"}), encoding="utf-8")

    assert GeminiConfig.api_key() == "legacy-key-0003"
    assert read_settings(settings_file) == {}


def test_legacy_key_does_not_overwrite_a_saved_key(
    backend: FakeKeyring, settings_file: Path
) -> None:
    SecretStore().set("stored-key-0001")
    settings_file.write_text(json.dumps({"api_key": "legacy-key-0003"}), encoding="utf-8")

    assert GeminiConfig.migrate_legacy_api_key() is False

    assert SecretStore().get() == "stored-key-0001"
    assert read_settings(settings_file) == {}


def test_empty_legacy_entry_is_just_removed(backend: FakeKeyring, settings_file: Path) -> None:
    settings_file.write_text(json.dumps({"theme": "dark", "api_key": ""}), encoding="utf-8")

    assert GeminiConfig.migrate_legacy_api_key() is False

    assert backend.passwords == {}
    assert read_settings(settings_file) == {"theme": "dark"}


def test_legacy_key_stays_in_the_file_when_the_store_is_broken(
    no_backend: None, settings_file: Path
) -> None:
    settings_file.write_text(json.dumps({"api_key": "legacy-key-0003"}), encoding="utf-8")

    assert GeminiConfig.migrate_legacy_api_key() is False

    assert read_settings(settings_file) == {"api_key": "legacy-key-0003"}
    # The file is no longer a key source: only the env var and the store are.
    assert GeminiConfig.api_key() == ""


def test_migration_without_a_settings_file(backend: FakeKeyring, settings_file: Path) -> None:
    assert GeminiConfig.migrate_legacy_api_key() is False
    assert not settings_file.exists()
