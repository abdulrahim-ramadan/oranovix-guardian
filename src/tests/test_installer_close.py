"""Clean installer updates: one-folder build, running-app mutex, polite shutdown.

Setup closed the app badly because the one-file exe runs as a windowless
bootloader plus the app. The installer now ships a one-folder build,
finds a running copy by a fixed mutex, and the app closes cleanly when
Windows or Restart Manager asks it to.
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any, List

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD_TOOLS = ROOT / "src" / "build_tools"


def _iss() -> str:
    return (BUILD_TOOLS / "installer.iss").read_text(encoding="utf-8")


def _build_script() -> str:
    return (BUILD_TOOLS / "build.ps1").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Build: one folder for the installer, one file only on request
# ---------------------------------------------------------------------------

def test_build_script_makes_a_one_folder_build_by_default() -> None:
    script = _build_script()
    assert '"--onedir"' in script
    assert re.search(r"param\(.*\[switch\]\$OneFile", script, re.S)
    # --onefile only appears on the -OneFile branch
    assert script.count('"--onefile"') == 1
    assert re.search(r"if \(\$OneFile\)[^\n]*\n?[^\n]*--onefile|\$OneFile\s*\)\s*\{[^}]*--onefile", script)


@pytest.mark.parametrize("flag", [
    '"--noconfirm"', '"--clean"', '"--windowed"', '"--paths"', '"--name", "Oranovix Guardian"',
    '"--icon"', "'assets');assets", "'translations');translations", "default_rules.json');rules",
    '"--collect-all", "bandit"', '"--collect-all", "stevedore"', '"--copy-metadata", "bandit"',
    '"--hidden-import", "keyring.backends.Windows"', '"--hidden-import", "truststore"',
    '"--hidden-import", "regex"', '"--hidden-import", "PIL._tkinter_finder"',
    '"--collect-data", "certifi"', '"--collect-data", "customtkinter"',
    '"--collect-submodules", "arabic_reshaper"', '"--distpath"', '"--workpath"', '"--specpath"',
])
def test_build_script_keeps_every_flag(flag: str) -> None:
    assert flag in _build_script()


def test_installer_ships_the_whole_one_folder_build() -> None:
    iss = _iss()
    assert re.search(
        r'^Source: "dist\\Oranovix Guardian\\\*"; DestDir: "\{app\}"; Flags: [^\n]*recursesubdirs',
        iss, re.M,
    )
    assert 'Source: "dist\\Oranovix Guardian.exe"' not in iss


def test_installer_removes_the_old_bundle_before_copying() -> None:
    """A stale _internal folder (or the loose 1.1.0 assets) must not mix with the new build."""
    iss = _iss()
    section = iss.split("[InstallDelete]", 1)[1].split("\n[", 1)[0]
    for folder in ("_internal", "assets", "translations"):
        assert f'Name: "{{app}}\\{folder}"' in section


# ---------------------------------------------------------------------------
# 2. Running-app mutex
# ---------------------------------------------------------------------------

def test_running_mutex_names() -> None:
    from oranovix_guardian.core.single_instance import RUNNING_MUTEX, RunningMarker

    assert RUNNING_MUTEX == "OranovixGuardianRunning"
    assert RunningMarker.NAMES == ("OranovixGuardianRunning", "Global\\OranovixGuardianRunning")


def test_installer_checks_the_same_mutexes() -> None:
    from oranovix_guardian.core.single_instance import RunningMarker

    iss = _iss()
    assert f"AppMutex={','.join(RunningMarker.NAMES)}\n" in iss
    assert re.search(r"^CloseApplications=yes$", iss, re.M)
    assert re.search(r"^RestartApplications=no$", iss, re.M)


def test_setup_and_uninstall_ask_to_close_the_running_app() -> None:
    iss = _iss()
    messages = iss.split("[Messages]", 1)[1].split("\n[", 1)[0]
    for key in ("SetupAppRunningError", "UninstallAppRunningError"):
        line = next(line for line in messages.splitlines() if line.startswith(key + "="))
        assert "Oranovix Guardian is running, please close it" in line


def _mutex_exists(name: str) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenMutexW.restype = wintypes.HANDLE
    handle = kernel32.OpenMutexW(0x00100000, False, name)       # SYNCHRONIZE, as Setup opens it
    if not handle:
        return False
    kernel32.CloseHandle(handle)
    return True


@pytest.mark.skipif(sys.platform != "win32", reason="named mutexes are Windows only")
def test_running_marker_holds_the_mutexes_until_released() -> None:
    from oranovix_guardian.core.single_instance import RunningMarker

    marker = RunningMarker()
    marker.acquire()
    try:
        assert _mutex_exists("OranovixGuardianRunning")
        assert marker.held[0] == "OranovixGuardianRunning"
        if "Global\\OranovixGuardianRunning" in marker.held:
            assert _mutex_exists("Global\\OranovixGuardianRunning")
    finally:
        marker.release()
    assert marker.held == ()
    assert not _mutex_exists("OranovixGuardianRunning")
    assert not _mutex_exists("Global\\OranovixGuardianRunning")


@pytest.mark.skipif(sys.platform != "win32", reason="named mutexes are Windows only")
def test_running_marker_never_blocks_a_start() -> None:
    """The per-data-folder lock decides about a second copy; the marker only tells Setup."""
    from oranovix_guardian.core.single_instance import RunningMarker

    first, second = RunningMarker(), RunningMarker()
    first.acquire()
    second.acquire()
    try:
        assert second.held
    finally:
        first.release()
        assert _mutex_exists("OranovixGuardianRunning")      # the second copy still holds it
        second.release()
    assert not _mutex_exists("OranovixGuardianRunning")


def test_running_marker_off_windows_does_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.single_instance import RunningMarker

    monkeypatch.setattr(sys, "platform", "linux")
    marker = RunningMarker()
    marker.acquire()
    assert marker.held == ()
    marker.release()


class _Lock:
    def __init__(self, log: List[str], name: str, ok: bool = True) -> None:
        self.log, self.name, self.ok = log, name, ok

    def acquire(self) -> bool:
        self.log.append(f"acquire {self.name}")
        return self.ok

    def release(self) -> None:
        self.log.append(f"release {self.name}")


def test_app_locks_release_both_once() -> None:
    from oranovix_guardian.core.single_instance import AppLocks

    log: List[str] = []
    locks = AppLocks(_Lock(log, "folder"), _Lock(log, "running"))
    assert locks.acquire()
    locks.release()
    locks.release()
    assert log == ["acquire folder", "acquire running", "release running", "release folder"]


def test_app_locks_take_no_marker_when_another_copy_runs() -> None:
    from oranovix_guardian.core.single_instance import AppLocks

    log: List[str] = []
    locks = AppLocks(_Lock(log, "folder", ok=False), _Lock(log, "running"))
    assert not locks.acquire()
    locks.release()
    assert log == ["acquire folder"]


def test_main_holds_both_locks_while_the_app_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    import main as entry
    from oranovix_guardian.core import single_instance

    log: List[str] = []
    monkeypatch.setattr(single_instance.SingleInstance, "for_data_dir", classmethod(lambda cls: _Lock(log, "folder")))
    monkeypatch.setattr(single_instance, "RunningMarker", lambda: _Lock(log, "running"))
    monkeypatch.setattr(entry.AppPaths, "migrate_legacy", classmethod(lambda cls: None))

    class _App:
        def __init__(self, instance: Any) -> None:
            log.append("app")
            self.instance = instance

        def mainloop(self) -> None:
            log.append("mainloop")
            self.instance.release()          # what _finish_close does

    monkeypatch.setattr(entry, "CodeGuardianApp", _App)
    entry.main()
    assert log == ["acquire folder", "acquire running", "app", "mainloop", "release running", "release folder"]


# ---------------------------------------------------------------------------
# 3. Polite shutdown
# ---------------------------------------------------------------------------

def test_close_request_calls_on_close_once_even_when_asked_twice() -> None:
    from oranovix_guardian.gui.session_end import CloseRequest

    calls: List[str] = []
    request = CloseRequest(lambda: calls.append("close"))
    request()
    request()
    assert calls == ["close"]
    assert request.asked


@pytest.mark.parametrize("message", ["WM_CLOSE", "WM_QUERYENDSESSION", "WM_ENDSESSION"])
def test_every_close_message_reaches_on_close_once(message: str) -> None:
    from oranovix_guardian.gui import session_end

    calls: List[str] = []
    waits: List[float] = []
    handler = session_end.CloseMessages(
        session_end.CloseRequest(lambda: calls.append("close")), wait=waits.append,
    )
    code = getattr(session_end, message)
    first = handler.handle(code, 1, session_end.ENDSESSION_CLOSEAPP)
    second = handler.handle(code, 1, session_end.ENDSESSION_CLOSEAPP)
    assert calls == ["close"]
    if message == "WM_QUERYENDSESSION":
        assert first == second == 1              # never block a logoff or an update
    if message == "WM_CLOSE":
        assert first is None                     # passed on to Tk, which runs WM_DELETE_WINDOW


def test_a_real_logoff_waits_for_the_shutdown_before_windows_ends_the_process() -> None:
    from oranovix_guardian.gui import session_end

    waits: List[float] = []
    handler = session_end.CloseMessages(session_end.CloseRequest(lambda: None), wait=waits.append)
    handler.handle(session_end.WM_ENDSESSION, 1, 0)                   # logoff: the process ends after this
    assert waits == [session_end.CloseMessages.ENDSESSION_WAIT_SECONDS]


def test_restart_manager_close_does_not_block_the_message_loop() -> None:
    """CLOSEAPP: Restart Manager waits for the process; Tk must keep running the close."""
    from oranovix_guardian.gui import session_end

    waits: List[float] = []
    handler = session_end.CloseMessages(session_end.CloseRequest(lambda: None), wait=waits.append)
    handler.handle(session_end.WM_ENDSESSION, 1, session_end.ENDSESSION_CLOSEAPP)
    assert waits == []


def test_a_cancelled_session_end_does_not_close() -> None:
    from oranovix_guardian.gui import session_end

    calls: List[str] = []
    handler = session_end.CloseMessages(session_end.CloseRequest(lambda: calls.append("close")), wait=lambda s: None)
    handler.handle(session_end.WM_ENDSESSION, 0, 0)       # another app refused: the session goes on
    assert calls == []


def test_other_messages_are_passed_on() -> None:
    from oranovix_guardian.gui import session_end

    calls: List[str] = []
    handler = session_end.CloseMessages(session_end.CloseRequest(lambda: calls.append("close")), wait=lambda s: None)
    assert handler.handle(0x0005, 0, 0) is None           # WM_SIZE
    assert calls == []


def test_a_failing_close_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    from oranovix_guardian.gui.session_end import CloseRequest

    def broken() -> None:
        raise RuntimeError("store busy")

    with caplog.at_level(logging.ERROR):
        CloseRequest(broken)()
    assert "store busy" in caplog.text


class _Monitor:
    def __init__(self) -> None:
        self.calls = 0

    def shutdown(self, timeout=None) -> None:
        self.calls += 1


class _Released:
    def __init__(self) -> None:
        self.released = 0

    def release(self) -> None:
        self.released += 1


def _bare_app(monkeypatch: pytest.MonkeyPatch, closed: List[bool], callbacks: List[Any]) -> Any:
    import customtkinter as ctk
    from oranovix_guardian.gui.app import CodeGuardianApp

    monkeypatch.setattr(ctk.CTk, "destroy", lambda self: closed.append(True))
    app = CodeGuardianApp.__new__(CodeGuardianApp)
    app._live_defense, app._threat_hub, app._log_sentinel = _Monitor(), _Monitor(), _Monitor()
    app._instance = _Released()
    app._closing = False
    app._pages = {}
    monkeypatch.setattr(type(app), "withdraw", lambda self: None)
    monkeypatch.setattr(type(app), "after", lambda self, delay, callback: callbacks.append(callback))
    return app


def test_session_end_runs_the_same_clean_close(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    closed: List[bool] = []
    callbacks: List[Any] = []
    app = _bare_app(monkeypatch, closed, callbacks)

    app._on_session_end()               # WM_SAVE_YOURSELF (Tk's WM_QUERYENDSESSION)
    app._on_session_end()
    app._on_close()                     # and WM_DELETE_WINDOW afterwards
    deadline = time.monotonic() + 3
    while callbacks and time.monotonic() < deadline:
        callbacks.pop(0)()
        time.sleep(0.005)

    assert closed == [True]
    assert app._instance is None
    monitors = (app._live_defense, app._threat_hub, app._log_sentinel)
    assert all(monitor.calls == 1 for monitor in monitors)


def test_waiting_for_the_shutdown_releases_the_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    """At a logoff Windows may end the process right after WM_ENDSESSION: stop everything now."""
    closed: List[bool] = []
    callbacks: List[Any] = []
    app = _bare_app(monkeypatch, closed, callbacks)
    lock = app._instance

    app._on_session_end()
    app._wait_for_shutdown(3)

    assert lock.released == 1
    assert all(m.calls == 1 for m in (app._live_defense, app._threat_hub, app._log_sentinel))


def test_the_window_asks_tk_for_the_session_end_protocol() -> None:
    source = (ROOT / "src" / "oranovix_guardian" / "gui" / "app.py").read_text(encoding="utf-8")
    assert 'self.protocol("WM_SAVE_YOURSELF", self._on_session_end)' in source
    assert 'self.protocol("WM_DELETE_WINDOW", self._on_close)' in source


# ---------------------------------------------------------------------------
# 4. Version
# ---------------------------------------------------------------------------

def test_version_is_1_2_0_everywhere() -> None:
    from oranovix_guardian.core.version import APP_VERSION

    assert APP_VERSION == "1.2.0"
    iss = _iss()
    assert re.search(r"^AppVersion=1\.2\.0$", iss, re.M)
    assert re.search(r"^OutputBaseFilename=Oranovix_Guardian_Setup_v1\.2\.0$", iss, re.M)
    assert "1.1.0" not in iss


# ---------------------------------------------------------------------------
# 5. Slow marker
# ---------------------------------------------------------------------------

def test_slow_marker_is_registered() -> None:
    ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert re.search(r"^markers\s*=\s*\n\s+slow:", ini, re.M)


def test_throughput_tests_are_marked_slow() -> None:
    tests = ROOT / "src" / "tests"
    monitor = (tests / "test_sentinel_monitor.py").read_text(encoding="utf-8")
    adversarial = (tests / "test_sentinel_adversarial.py").read_text(encoding="utf-8")
    assert "@pytest.mark.slow\ndef test_hundred_thousand_lines_in_under_fifteen_seconds" in monitor
    assert "test_hundred_thousand_lines_in_under_five_seconds" not in monitor
    assert "elapsed < 15.0" in monitor
    assert "@pytest.mark.slow\ndef test_fifty_thousand_addresses_through_the_monitor" in adversarial
