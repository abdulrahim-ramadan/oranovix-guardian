"""Controller: start/stop, saved state for resuming, listeners on the dispatch thread."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable, List

import pytest

from live_defense.baseline import BaselineError
from live_defense.controller import LiveDefenseController, LiveDefenseSettings, LiveDefenseState


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


class QueueDispatch:
    """Collects callbacks like ``widget.after`` would; ``run()`` plays them."""

    def __init__(self) -> None:
        self.pending: List[Callable[[], None]] = []
        self.lock = threading.Lock()
        self.arrived = threading.Event()

    def __call__(self, fn: Callable[[], None]) -> None:
        with self.lock:
            self.pending.append(fn)
        self.arrived.set()

    def run(self) -> None:
        with self.lock:
            pending, self.pending = self.pending, []
        for fn in pending:
            fn()


@pytest.fixture
def site(tmp_path: Path) -> Path:
    root = tmp_path / "site"
    (root / "shop").mkdir(parents=True)
    (root / "shop" / "settings.py").write_text("DEBUG = False\n", encoding="utf-8")
    return root


@pytest.fixture
def settings_path(tmp_path: Path) -> Path:
    return tmp_path / "settings.json"


@pytest.fixture
def keys() -> MemoryKeyStore:
    return MemoryKeyStore()


def make(tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, dispatch=None) -> LiveDefenseController:
    return LiveDefenseController(
        dispatch=dispatch or (lambda fn: fn()),
        settings=LiveDefenseSettings(str(settings_path)),
        db_path=str(tmp_path / "integrity.db"),
        key_store=keys,
        file_scanner=lambda path: [],
    )


def saved(settings_path: Path) -> dict:
    return json.loads(settings_path.read_text(encoding="utf-8"))["live_defense"]


def test_start_needs_a_folder_and_a_baseline(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    with pytest.raises(BaselineError, match="Choose a folder"):
        controller.start()

    controller.set_root(str(site))
    with pytest.raises(BaselineError, match="Create a baseline"):
        controller.start()


def test_start_stop_and_saved_state(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    controller.set_interval(45)
    assert controller.create_baseline(["*.tmp"]) == 1

    controller.start()
    assert controller.is_running
    assert saved(settings_path) == {"root": str(site), "running": True, "interval": 45}

    controller.stop()
    assert not controller.is_running
    assert saved(settings_path)["running"] is False


def test_shutdown_keeps_running_flag_for_resume(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    controller.create_baseline()
    controller.start()

    controller.shutdown()

    assert not controller.is_running
    reopened = make(tmp_path, settings_path, keys)
    assert reopened.root == str(site)
    assert reopened.resume_candidate() == str(site)
    assert reopened.is_running is False                 # never resumes on its own


def test_no_resume_offer_after_a_normal_stop(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    controller.create_baseline()
    controller.start()
    controller.stop()

    assert make(tmp_path, settings_path, keys).resume_candidate() == ""


def test_no_resume_offer_when_the_folder_is_gone(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore
) -> None:
    settings_path.write_text(json.dumps(
        {"theme": "dark", "live_defense": {"root": str(tmp_path / "gone"), "running": True}}
    ), encoding="utf-8")

    assert make(tmp_path, settings_path, keys).resume_candidate() == ""


def test_other_settings_are_kept(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    settings_path.write_text(json.dumps({"theme": "dark", "sound_volume": 0.4}), encoding="utf-8")
    controller = make(tmp_path, settings_path, keys)

    controller.set_root(str(site))

    data = json.loads(settings_path.read_text(encoding="utf-8"))
    assert data["theme"] == "dark" and data["sound_volume"] == 0.4


def test_changing_the_folder_stops_monitoring(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    controller.create_baseline()
    controller.start()

    controller.set_root(str(tmp_path))

    assert not controller.is_running
    assert controller.root == str(tmp_path)


def test_reports_reach_listeners_through_dispatch(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    dispatch = QueueDispatch()
    controller = make(tmp_path, settings_path, keys, dispatch)
    controller.set_root(str(site))
    controller.create_baseline()
    (site / "planted.php").write_text("x\n", encoding="utf-8")
    states: List[LiveDefenseState] = []
    controller.add_listener(states.append)

    controller.start()
    assert dispatch.arrived.wait(10)                    # the first cycle finished
    controller.stop()
    assert states == []                                 # nothing ran outside dispatch

    dispatch.run()

    (state,) = states
    assert state.running is False
    assert [e.relative_path for e in state.new_events] == ["planted.php"]
    assert [e.relative_path for e in state.open_events] == ["planted.php"]
    assert state.last_check_at is not None


def test_broken_listener_is_dropped(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore
) -> None:
    controller = make(tmp_path, settings_path, keys)
    calls: List[LiveDefenseState] = []

    def broken(state: LiveDefenseState) -> None:
        raise RuntimeError("widget destroyed")

    controller.add_listener(broken)
    controller.add_listener(calls.append)
    controller.notify()
    controller.notify()

    assert len(calls) == 2
    assert broken not in controller._listeners


def test_state_shows_baseline_and_tampering(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    assert controller.state().baseline_exists is False

    controller.create_baseline(["cache/"])
    state = controller.state()
    assert state.baseline_exists and state.baseline_ok
    assert state.baseline_files == 1
    assert state.ignore_patterns == ("cache/",)
    assert state.baseline_created_at is not None

    keys.value = ""
    assert controller.state().baseline_ok is False
    assert "credential store" in controller.state().baseline_problem


def test_accept_through_the_controller(
    tmp_path: Path, settings_path: Path, keys: MemoryKeyStore, site: Path
) -> None:
    controller = make(tmp_path, settings_path, keys)
    controller.set_root(str(site))
    controller.create_baseline()
    controller.set_interval(3600)
    controller.start()
    controller.stop(remember=False)
    (site / "new.txt").write_text("x\n", encoding="utf-8")

    (event,) = controller.check_now()
    assert controller.accept([event.event_id]) == 1
    assert controller.state().open_events == ()
    assert controller.check_now() == []


def test_interval_is_validated(tmp_path: Path, settings_path: Path, keys: MemoryKeyStore) -> None:
    controller = make(tmp_path, settings_path, keys)

    controller.set_interval(1)
    assert controller.interval == 5
    assert make(tmp_path, settings_path, keys).interval == 5

    settings_path.write_text(json.dumps({"live_defense": {"interval": "abc"}}), encoding="utf-8")
    assert make(tmp_path, settings_path, keys).interval == 30
