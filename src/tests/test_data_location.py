"""Where the app writes its data.

The installer puts the exe in Program Files, which a normal user cannot
write to. These tests start the code "frozen" with the exe in a folder
that is really read-only (chmod 555, and an ACL deny entry on Windows
where chmod has no effect on folders) and check that every store still
works and writes into the data folder instead.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_DIR_NAME = "Oranovix Guardian"


# ---------------------------------------------------------------------------
# A read-only install folder
# ---------------------------------------------------------------------------

def _writable(folder: Path) -> bool:
    probe = folder / f".probe-{uuid.uuid4().hex}"
    try:
        probe.write_text("x", encoding="utf-8")
    except OSError:
        return False
    probe.unlink()
    return True


def _windows_user() -> str:
    return subprocess.run(["whoami"], capture_output=True, text=True, check=False).stdout.strip()


class ReadOnlyFolder:
    """chmod 555; on Windows, where that does not stop new files, an ACL deny entry."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self._denied_user = ""

    def __enter__(self) -> "ReadOnlyFolder":
        os.chmod(self.folder, 0o555)
        if _writable(self.folder) and sys.platform == "win32":
            user = _windows_user()
            done = subprocess.run(
                ["icacls", str(self.folder), "/deny", f"{user}:(OI)(CI)(WD,AD)"],
                capture_output=True, check=False,
            )
            if done.returncode == 0:
                self._denied_user = user
        return self

    @property
    def read_only(self) -> bool:
        return not _writable(self.folder)

    def __exit__(self, *exc: object) -> None:
        if self._denied_user:
            subprocess.run(
                ["icacls", str(self.folder), "/remove:d", self._denied_user],
                capture_output=True, check=False,
            )
        os.chmod(self.folder, 0o755)


def _reset_singletons(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.scan_history import ScanHistory
    from oranovix_guardian.core.sound_manager import SoundManager
    from oranovix_guardian.gui.theme_manager import ThemeManager
    for cls in (ScanHistory, SoundManager, ThemeManager):
        monkeypatch.setattr(cls, "_instance", None)


@pytest.fixture
def frozen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Dict[str, Path]]:
    """The app runs as an installed exe in a read-only folder."""
    install = tmp_path / "Program Files" / APP_DIR_NAME
    install.mkdir(parents=True)
    exe = install / "Oranovix Guardian.exe"
    exe.write_bytes(b"MZ")
    local = tmp_path / "LocalAppData"
    roaming = tmp_path / "RoamingAppData"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setattr(sys, "_MEIPASS", str(PROJECT_ROOT / "src" / "oranovix_guardian"), raising=False)
    monkeypatch.delenv("ORANOVIX_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("XDG_DATA_HOME", str(local))
    _reset_singletons(monkeypatch)
    with ReadOnlyFolder(install):
        yield {"install": install, "data": local / APP_DIR_NAME}


def _install_untouched(paths: Dict[str, Path]) -> None:
    assert sorted(p.name for p in paths["install"].iterdir()) == ["Oranovix Guardian.exe"]


# ---------------------------------------------------------------------------
# Every store works with a read-only install folder
# ---------------------------------------------------------------------------

def _critical_issue(path: str) -> Any:
    from oranovix_guardian.scanner_engine.base import Issue, Severity
    from oranovix_guardian.scanner_engine.categories import IssueCategory
    return Issue(
        "SEC001", "Hardcoded Secret", "description", Severity.CRITICAL, path, 3,
        category=IssueCategory.SECRET,
    )


class _FakeRoot:
    def __init__(self) -> None:
        self.scheduled: List[Any] = []

    def after(self, delay: int, *call: Any) -> None:
        self.scheduled.append(call)


def test_alarm_center_works_and_writes_into_the_data_folder(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.gui.alarm_channels import build_alarm_center
    center = build_alarm_center(_FakeRoot())

    alarm = center.notify([_critical_issue("/site/app.py")], "/site")

    assert alarm is not None
    assert (frozen["data"] / "scan_history.db").is_file()
    _install_untouched(frozen)


def test_scan_history_is_saved_into_the_data_folder(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.core.scan_history import ScanHistory
    from oranovix_guardian.scanner_engine.base import ScanResult
    history = ScanHistory()

    history.save_scan(ScanResult(target_path="/site", scan_id="1", files_scanned=3))

    assert history.get_stats()["total_scans"] == 1
    assert (frozen["data"] / "scan_history.db").is_file()
    _install_untouched(frozen)


def test_threat_store_works(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.threat_intel.store import ThreatStore
    store = ThreatStore()

    assert store.count() == 0
    assert (frozen["data"] / "feed.db").is_file()
    _install_untouched(frozen)


def test_security_event_store_works(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.log_sentinel.store import SecurityEventStore
    from oranovix_guardian.log_sentinel.tail import TailStateStore
    store = SecurityEventStore()
    TailStateStore()

    assert store.path == frozen["data"] / "security_events.db"
    assert (frozen["data"] / "log_sentinel_state.db").is_file()
    _install_untouched(frozen)


def test_osv_update_target_is_writable(frozen: Dict[str, Path], osv_records: Any) -> None:
    from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
    database = OSVDatabase()

    assert database.import_records(osv_records) > 0
    assert database.path == frozen["data"] / "osv.db"
    assert database.exists()
    _install_untouched(frozen)


def test_online_consent_is_stored(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig

    GeminiConfig.set_online_consent(True)

    assert GeminiConfig.online_consent() is True
    saved = json.loads((frozen["data"] / "settings.json").read_text(encoding="utf-8"))
    assert saved["ai_online_consent"] == "allow"
    _install_untouched(frozen)


def test_integrity_baseline_and_settings_go_to_the_data_folder(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.live_defense.baseline import Baseline
    from oranovix_guardian.live_defense.controller import LiveDefenseSettings
    from oranovix_guardian.log_sentinel.controller import SentinelSettings
    from oranovix_guardian.threat_intel.settings import ThreatFeedSettings

    LiveDefenseSettings().save(interval=45)
    SentinelSettings().save(interval=20)
    ThreatFeedSettings().update(enabled=True)

    assert Baseline(str(frozen["install"])).db_path == frozen["data"] / "integrity.db"
    saved = json.loads((frozen["data"] / "settings.json").read_text(encoding="utf-8"))
    assert saved["live_defense"]["interval"] == 45
    assert saved["log_sentinel"]["interval"] == 20
    assert saved["threat_feed"]["enabled"] is True
    _install_untouched(frozen)


def test_theme_and_sound_are_saved(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.core.sound_manager import SoundManager
    from oranovix_guardian.gui.theme_manager import ThemeManager

    ThemeManager().set_mode("light" if ThemeManager().is_dark else "dark")
    expected = ThemeManager().mode
    SoundManager().volume = 0.25

    saved = json.loads((frozen["data"] / "settings.json").read_text(encoding="utf-8"))
    assert saved["theme"] == expected
    assert saved["sound_volume"] == 0.25
    _install_untouched(frozen)


def test_custom_rules_are_saved_and_default_rules_come_from_the_bundle(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.scanner_engine.rule_engine import Rule, RuleEngine
    engine = RuleEngine()
    assert any(rule.is_builtin for rule in engine.rules), "default_rules.json not found in the bundle"

    engine.add_rule(Rule(
        id="CUSTOM-1", name="no foo", description="d", pattern=r"foo\(",
        severity="LOW", language="ALL",
    ))

    assert (frozen["data"] / "rules" / "custom_rules.json").is_file()
    assert any(rule.id == "CUSTOM-1" for rule in RuleEngine().rules)
    _install_untouched(frozen)


def test_pdf_reports_go_to_the_data_folder(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.reports.pdf_generator import PDFReportGenerator
    from oranovix_guardian.scanner_engine.base import ScanResult

    target = PDFReportGenerator()._default_path(ScanResult(target_path="/site", scan_id="1"))

    assert Path(target).parent == frozen["data"] / "reports" / "output"
    _install_untouched(frozen)


def test_the_install_folder_was_really_read_only(frozen: Dict[str, Path]) -> None:
    """Guards the guard: on this machine the folder must refuse new files."""
    if _writable(frozen["install"]):
        pytest.skip("this account can still write into a chmod 555 folder")


# ---------------------------------------------------------------------------
# Data folder location
# ---------------------------------------------------------------------------

def test_from_source_data_stays_in_the_project_root(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    monkeypatch.delenv("ORANOVIX_DATA_DIR", raising=False)
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert AppPaths.data_dir() == PROJECT_ROOT


def test_environment_variable_overrides_the_data_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(tmp_path / "custom"))

    assert AppPaths.data_dir() == tmp_path / "custom"
    assert (tmp_path / "custom").is_dir()


def test_frozen_without_localappdata_falls_back_to_appdata(frozen: Dict[str, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    monkeypatch.delenv("LOCALAPPDATA")
    if sys.platform != "win32":
        pytest.skip("LOCALAPPDATA / APPDATA are Windows folders")

    assert AppPaths.data_dir() == tmp_path / "RoamingAppData" / APP_DIR_NAME


def test_resources_come_from_the_bundle(frozen: Dict[str, Path]) -> None:
    from oranovix_guardian.core.app_paths import AppPaths

    assert AppPaths.resource("translations", "en.json").is_file()
    assert AppPaths.resource("rules", "default_rules.json").is_file()


# ---------------------------------------------------------------------------
# Migration from the folder next to the exe
# ---------------------------------------------------------------------------

@pytest.fixture
def old_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    install = tmp_path / "Program Files" / APP_DIR_NAME
    install.mkdir(parents=True)
    (install / "Oranovix Guardian.exe").write_bytes(b"MZ")
    local = tmp_path / "LocalAppData"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(install / "Oranovix Guardian.exe"))
    monkeypatch.setattr(sys, "_MEIPASS", str(PROJECT_ROOT / "src" / "oranovix_guardian"), raising=False)
    monkeypatch.delenv("ORANOVIX_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("XDG_DATA_HOME", str(local))
    return {"install": install, "data": local / APP_DIR_NAME}


def test_migration_copies_old_settings_once_and_keeps_the_original(old_install: Dict[str, Path]) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    old = old_install["install"] / "settings.json"
    old.write_text(json.dumps({"theme": "light"}), encoding="utf-8")
    (old_install["install"] / "scan_history.db").write_bytes(b"db")
    (old_install["install"] / "rules").mkdir()
    (old_install["install"] / "rules" / "custom_rules.json").write_text('{"rules": []}', encoding="utf-8")

    copied = AppPaths.migrate_legacy()

    new = old_install["data"] / "settings.json"
    assert json.loads(new.read_text(encoding="utf-8")) == {"theme": "light"}
    assert (old_install["data"] / "scan_history.db").read_bytes() == b"db"
    assert (old_install["data"] / "rules" / "custom_rules.json").is_file()
    assert "settings.json" in copied
    assert old.is_file(), "the original must never be deleted"

    # A second start does not copy again, even when the old file changed.
    old.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
    new.unlink()
    assert AppPaths.migrate_legacy() == []
    assert not new.exists()


def test_migration_never_overwrites_newer_data(old_install: Dict[str, Path]) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    (old_install["install"] / "settings.json").write_text('{"theme": "light"}', encoding="utf-8")
    old_install["data"].mkdir(parents=True)
    (old_install["data"] / "settings.json").write_text('{"theme": "dark"}', encoding="utf-8")

    AppPaths.migrate_legacy()

    assert json.loads((old_install["data"] / "settings.json").read_text(encoding="utf-8")) == {"theme": "dark"}


def test_no_migration_when_running_from_source(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.app_paths import AppPaths
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert AppPaths.migrate_legacy() == []


# ---------------------------------------------------------------------------
# settings.json: one owner, atomic writes, corrupt files kept
# ---------------------------------------------------------------------------

@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    folder = tmp_path / "data"
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(folder))
    monkeypatch.delattr(sys, "frozen", raising=False)
    _reset_singletons(monkeypatch)
    return folder


def test_two_writers_in_a_row_keep_both_keys(data_dir: Path) -> None:
    from oranovix_guardian.gui.theme_manager import ThemeManager
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig

    ThemeManager().set_mode("light")
    GeminiConfig.set_online_consent(True)

    saved = json.loads((data_dir / "settings.json").read_text(encoding="utf-8"))
    assert saved["theme"] == "light"
    assert saved["ai_online_consent"] == "allow"


def test_every_settings_writer_keeps_the_other_keys(data_dir: Path) -> None:
    from oranovix_guardian.core.sound_manager import SoundManager
    from oranovix_guardian.gui.theme_manager import ThemeManager
    from oranovix_guardian.live_defense.controller import LiveDefenseSettings
    from oranovix_guardian.log_sentinel.controller import SentinelSettings
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig
    from oranovix_guardian.threat_intel.settings import ThreatFeedSettings

    ThemeManager().set_mode("light")
    SoundManager().enabled = False
    GeminiConfig.set_online_consent(False)
    LiveDefenseSettings().save(root="/site")
    SentinelSettings().save(interval=15)
    ThreatFeedSettings().update(asked=True)

    saved = json.loads((data_dir / "settings.json").read_text(encoding="utf-8"))
    assert saved["theme"] == "light"
    assert saved["sound_enabled"] is False
    assert saved["ai_online_consent"] == "offline"
    assert saved["live_defense"]["root"] == "/site"
    assert saved["log_sentinel"]["interval"] == 15
    assert saved["threat_feed"]["asked"] is True


def test_parallel_writers_lose_nothing(data_dir: Path) -> None:
    from oranovix_guardian.core.settings_file import SettingsFile

    def write(index: int) -> None:
        SettingsFile().set(f"key_{index}", index)

    threads = [threading.Thread(target=write, args=(i,)) for i in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    saved = SettingsFile().read()
    assert all(saved[f"key_{i}"] == i for i in range(24))


def test_a_corrupt_settings_file_is_kept_as_corrupt_copy(data_dir: Path) -> None:
    from oranovix_guardian.live_defense.controller import LiveDefenseSettings
    data_dir.mkdir(parents=True)
    broken = '{"theme": "light", "live_defense": {"root": "/site"'      # cut off
    (data_dir / "settings.json").write_text(broken, encoding="utf-8")

    LiveDefenseSettings().save(interval=60)

    kept = list(data_dir.glob("settings.json.corrupt-*"))
    assert len(kept) == 1
    assert kept[0].read_text(encoding="utf-8") == broken
    assert re.fullmatch(r"settings\.json\.corrupt-\d{8}-\d{6}(-\d+)?", kept[0].name)
    assert json.loads((data_dir / "settings.json").read_text(encoding="utf-8")) == {"live_defense": {"interval": 60}}


def test_a_settings_file_that_is_not_an_object_is_kept_too(data_dir: Path) -> None:
    from oranovix_guardian.core.settings_file import SettingsFile
    data_dir.mkdir(parents=True)
    (data_dir / "settings.json").write_text("[1, 2]", encoding="utf-8")

    SettingsFile().set("theme", "dark")

    assert len(list(data_dir.glob("settings.json.corrupt-*"))) == 1


def test_no_temp_file_is_left_behind(data_dir: Path) -> None:
    from oranovix_guardian.core.settings_file import SettingsFile
    SettingsFile().set("theme", "dark")

    assert sorted(p.name for p in data_dir.iterdir()) == ["settings.json"]


# ---------------------------------------------------------------------------
# A failed write is shown once
# ---------------------------------------------------------------------------

def test_a_failed_settings_write_is_reported_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.settings_file import SettingsFile
    from oranovix_guardian.core.storage_problems import StorageProblems
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    settings = SettingsFile(blocker / "settings.json")     # parent is a file: cannot write
    monkeypatch.setattr(StorageProblems, "_reported", set())
    monkeypatch.setattr(StorageProblems, "_pending", [])
    seen: List[Any] = []
    StorageProblems.set_listener(seen.append)
    try:
        assert settings.set("theme", "dark") is False
        assert settings.set("theme", "light") is False
    finally:
        StorageProblems.set_listener(None)

    assert len(seen) == 1
    assert "settings.json" in seen[0].path


def test_problems_before_the_window_exists_are_delivered_later(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.storage_problems import StorageProblems
    monkeypatch.setattr(StorageProblems, "_reported", set())
    monkeypatch.setattr(StorageProblems, "_pending", [])
    StorageProblems.set_listener(None)

    StorageProblems.report("scan history", "/x/scan_history.db", OSError("denied"))
    seen: List[Any] = []
    StorageProblems.set_listener(seen.append)
    StorageProblems.set_listener(None)

    assert [problem.what for problem in seen] == ["scan history"]


def test_a_failed_scan_history_write_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.scan_history import ScanHistory
    from oranovix_guardian.core.storage_problems import StorageProblems
    from oranovix_guardian.scanner_engine.base import ScanResult
    monkeypatch.setattr(StorageProblems, "_reported", set())
    monkeypatch.setattr(StorageProblems, "_pending", [])
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ScanHistory, "_instance", None)
    history = ScanHistory()
    (tmp_path / "scan_history.db").unlink()
    (tmp_path / "scan_history.db").mkdir()             # a folder where the file should be
    seen: List[Any] = []
    StorageProblems.set_listener(seen.append)
    try:
        history.save_scan(ScanResult(target_path="/site", scan_id="1"))
    finally:
        StorageProblems.set_listener(None)

    assert [problem.what for problem in seen] == ["scan history"]


# ---------------------------------------------------------------------------
# Single instance
# ---------------------------------------------------------------------------

def test_a_second_instance_is_refused(tmp_path: Path) -> None:
    from oranovix_guardian.core.single_instance import SingleInstance
    name = f"oranovix-test-{uuid.uuid4().hex}"
    first = SingleInstance(name, lock_dir=tmp_path)
    second = SingleInstance(name, lock_dir=tmp_path)

    assert first.acquire() is True
    try:
        assert second.acquire() is False
    finally:
        first.release()
    assert second.acquire() is True
    second.release()


def test_a_second_process_is_refused(tmp_path: Path) -> None:
    from oranovix_guardian.core.single_instance import SingleInstance
    name = f"oranovix-test-{uuid.uuid4().hex}"
    first = SingleInstance(name, lock_dir=tmp_path)
    assert first.acquire()
    try:
        code = (
            "import sys; from pathlib import Path; from oranovix_guardian.core.single_instance import SingleInstance; "
            f"sys.exit(0 if SingleInstance({name!r}, lock_dir=Path({str(tmp_path)!r})).acquire() else 3)"
        )
        done = subprocess.run(
            [sys.executable, "-c", code], cwd=PROJECT_ROOT, check=False,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        )
        assert done.returncode == 3
    finally:
        first.release()


def test_the_instance_name_depends_on_the_data_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.single_instance import SingleInstance
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(tmp_path / "a"))
    first = SingleInstance.for_data_dir().name
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(tmp_path / "b"))

    assert SingleInstance.for_data_dir().name != first


# ---------------------------------------------------------------------------
# Installer and version
# ---------------------------------------------------------------------------

INSTALLER = PROJECT_ROOT / "src" / "build_tools" / "installer.iss"


def test_installer_writes_nothing_into_the_app_folder_at_runtime() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    files_section = text.split("[Files]", 1)[1].split("\n[", 1)[0]

    assert "settings.json" not in files_section
    assert "{autopf}" in text


def test_versions_agree() -> None:
    from oranovix_guardian.core.version import APP_VERSION
    text = INSTALLER.read_text(encoding="utf-8")
    installer_version = re.search(r"^AppVersion=(.+)$", text, re.MULTILINE)
    main_text = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")

    assert installer_version is not None and installer_version.group(1).strip() == APP_VERSION
    assert f"Version: {APP_VERSION}" in main_text
    assert APP_VERSION == "1.2.0"
