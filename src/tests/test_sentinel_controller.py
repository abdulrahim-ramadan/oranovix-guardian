"""Log Sentinel controller and the page texts. No window is opened, no sleeping."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.alarm_center import AlarmCenter, SqliteSeenFindingStore
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.log_sentinel.controller import (
    LogSentinelController,
    SentinelError,
    SentinelOptions,
    SentinelSettings,
    SentinelState,
    sample_log_path,
)
from oranovix_guardian.log_sentinel.events import EventState
from oranovix_guardian.log_sentinel.parsers import LogFormat
from oranovix_guardian.log_sentinel.store import EventFilter, SecurityEventStore
from oranovix_guardian.log_sentinel.tail import TailStateStore
from oranovix_guardian.scanner_engine.base import Severity

ROOT = Path(__file__).resolve().parents[2]
TRANSLATIONS = AppPaths.resource("translations")


class Keys:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.states: List[SentinelState] = []
        self.settings = SentinelSettings(str(tmp_path / "settings.json"))
        self.store = SecurityEventStore(str(tmp_path / "events.db"))
        self.keys = Keys()
        self.log = tmp_path / "access.log"
        self.log.write_text("", encoding="utf-8")
        self.controller = self.build()

    def build(self) -> LogSentinelController:
        controller = LogSentinelController(
            dispatch=lambda fn: fn(),
            alarm_center=AlarmCenter(store=SqliteSeenFindingStore(str(self.tmp / "alarms.db")), channels=[]),
            settings=self.settings, store=self.store, tail_store=TailStateStore(str(self.tmp / "state.db")),
            key_store=self.keys, spawn=lambda work: work(),
        )
        controller.add_listener(self.states.append)
        return controller


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


@pytest.fixture(autouse=True)
def english() -> None:
    LanguageManager().set_language("en")


ATTACK = ('198.51.100.23 - - [16/Nov/2026:12:00:00 +0000] "GET /item?id=1%27%20UNION%20SELECT%201,2--'
          ' HTTP/1.1" 404 153 "-" "curl/8"\n')


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def test_defaults_are_private_and_off(rig: Rig) -> None:
    options = rig.controller.options()
    assert options.logs == () and options.running is False
    assert options.keep_full_ips is False and options.retention_days == 30 and options.interval == 10
    assert options.trusted_proxies == () and options.allowlist == ()


def test_logs_are_added_and_removed(rig: Rig) -> None:
    rig.controller.add_log(str(rig.log), LogFormat.JSON)
    rig.controller.add_log(str(rig.log))                       # again: replaces, no duplicate

    (log,) = rig.controller.options().logs
    assert log.path == str(rig.log) and log.log_format is LogFormat.AUTO
    with pytest.raises(SentinelError):
        rig.controller.add_log(str(rig.tmp / "missing.log"))
    rig.controller.remove_log(str(rig.log))
    assert rig.controller.options().logs == ()


def test_networks_are_checked_and_saved(rig: Rig) -> None:
    invalid = rig.controller.set_networks("10.0.0.0/8, 192.0.2.1, nonsense", "203.0.113.0/24;2001:db8::/32")

    options = rig.controller.options()
    assert invalid == ["nonsense"]
    assert options.trusted_proxies == ("10.0.0.0/8", "192.0.2.1/32")
    assert options.allowlist == ("203.0.113.0/24", "2001:db8::/32")


@pytest.mark.parametrize("value, expected", [("30", 30), ("1", 5), ("99999", 3600), ("x", 10)])
def test_interval_is_bounded(rig: Rig, value: str, expected: int) -> None:
    assert rig.controller.set_interval(value) == expected


def test_options_survive_broken_settings() -> None:
    options = SentinelOptions.load({"logs": "nope", "interval": None, "keep_full_ips": "yes", "allowlist": 5})
    assert options.logs == () and options.interval == 10 and options.keep_full_ips is False


def test_switching_full_addresses_off_truncates_stored_ones(rig: Rig) -> None:
    rig.controller.set_keep_full_ips(True)
    rig.controller.add_log(str(rig.log))
    rig.controller.check_now()
    rig.log.write_text(ATTACK, encoding="utf-8")
    rig.controller.check_now()
    assert [e.ip for e in rig.store.events()] == ["198.51.100.23"]

    rig.controller.set_keep_full_ips(False)

    assert [e.ip for e in rig.store.events()] == ["198.51.100.0"]


def test_hash_key_is_created_once_in_the_credential_store(rig: Rig) -> None:
    first = rig.keys.value
    assert len(first) == 64
    rig.build()
    assert rig.keys.value == first


def test_retention_is_applied_on_start(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.controller.add_log(str(rig.log))
    rig.controller.check_now()
    rig.log.write_text(ATTACK.replace("16/Nov/2026", "01/Sep/2026"), encoding="utf-8")
    rig.controller.check_now()
    assert rig.store.count() == 1

    restarted = rig.build()                     # the app starts again
    assert restarted.purged == 1 and rig.store.count() == 0


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def test_start_needs_a_log(rig: Rig) -> None:
    with pytest.raises(SentinelError):
        rig.controller.start()


def test_start_stop_and_resume(rig: Rig) -> None:
    rig.controller.add_log(str(rig.log))
    rig.controller.start()
    try:
        assert rig.controller.is_running and rig.controller.options().running
    finally:
        rig.controller.shutdown()               # app closes: "running" is kept
    assert rig.build().resume_candidate() == (str(rig.log),)

    rig.controller.stop()
    assert rig.build().resume_candidate() == ()


def test_running_monitor_reports_through_the_listener(rig: Rig) -> None:
    rig.controller.add_log(str(rig.log))
    reported = threading.Event()
    rig.controller.add_listener(lambda state: reported.set() if state.last_report else None)
    rig.controller.start()
    try:
        assert reported.wait(5)
    finally:
        rig.controller.stop()
    assert any(state.running for state in rig.states)


def test_check_finds_attacks_and_counts_open_ones(rig: Rig) -> None:
    rig.controller.add_log(str(rig.log))
    rig.controller.check_now()
    rig.log.write_text(ATTACK, encoding="utf-8")

    report = rig.controller.check_now()

    assert [e.rule_id for e in report.new_events] == ["LS101"]
    state = rig.controller.state()
    assert (state.open_critical, state.open_high, state.open_alarming) == (0, 1, 1)

    rig.controller.acknowledge([report.new_events[0].id])
    assert rig.controller.state().open_alarming == 0
    assert rig.states[-1].open_alarming == 0                  # listeners were told


def test_sample_log_shows_results_at_once(rig: Rig) -> None:
    assert sample_log_path().is_file()

    rig.controller.analyse_sample()

    state = rig.states[-1]
    assert not state.analysing and state.last_report is not None and state.last_report.error == ""
    found = {e.rule_id for e in rig.store.events()}
    assert {"LS101", "LS102", "LS103", "LS106", "LS108", "LS109", "LS110", "LS111",
            "LS201", "LS202", "LS203"} <= found
    assert state.open_critical >= 2
    assert all(e.ip.endswith(".0") for e in rig.store.events())      # shortened by default


def test_acknowledge_all_with_a_filter(rig: Rig) -> None:
    rig.controller.analyse_sample()
    critical = EventFilter(severities=(Severity.CRITICAL,))

    rig.controller.acknowledge_all(critical)

    assert rig.controller.state().open_critical == 0
    assert rig.store.count(EventFilter(state=EventState.OPEN)) > 0


def test_csv_export_of_the_sample(rig: Rig, tmp_path: Path) -> None:
    rig.controller.analyse_sample()
    count = rig.controller.export_csv(str(tmp_path / "out.csv"))
    assert count == rig.store.count() and (tmp_path / "out.csv").stat().st_size > 500


# ---------------------------------------------------------------------------
# Page texts
# ---------------------------------------------------------------------------

def state(**changes: Any) -> SentinelState:
    values: Dict[str, Any] = dict(running=False, options=SentinelOptions(), open_critical=0, open_high=0)
    values.update(changes)
    return SentinelState(**values)


def test_status_and_banner_texts() -> None:
    from oranovix_guardian.gui.pages.log_sentinel_page import LogSentinelPage
    from oranovix_guardian.log_sentinel.monitor import FileReport, SentinelReport, WatchedLog

    one = SentinelOptions(logs=(WatchedLog("/var/log/nginx/access.log"),))
    assert LogSentinelPage.status_text(state()) == "No log file chosen"
    assert LogSentinelPage.status_text(state(options=one)) == "Stopped"
    report = SentinelReport(files=(FileReport("/var/log/nginx/access.log", malformed=3),))
    assert LogSentinelPage.status_text(state(options=one, running=True, last_report=report)) == (
        "Watching 1 log file(s)  ·  3 lines could not be read"
    )
    assert LogSentinelPage.banner_text(state(open_high=4)) == ""          # red only for CRITICAL
    assert LogSentinelPage.banner_text(state(open_critical=2)) == "2 critical attack event(s) need your attention"


def test_event_row_texts(rig: Rig) -> None:
    from oranovix_guardian.gui.pages.log_sentinel_page import LogSentinelPage

    rig.controller.analyse_sample()
    brute = next(e for e in rig.store.events() if e.rule_id == "LS202")
    time_text, title, ip, request, status, reason = LogSentinelPage.row_texts(brute)
    assert title == "Possible successful brute force" and ip == "203.0.113.0" and status == "302"
    assert request.startswith("POST /admin/login/")
    assert reason == "after the failed logins the server answered 302 on /admin/login"

    scan = next(e for e in rig.store.events() if e.rule_id == "LS111")
    assert LogSentinelPage.row_texts(scan)[5].startswith("45 requests  ·  Matched: nikto")
    assert LogSentinelPage.attackers_text(rig.controller.top_attackers(2)).startswith("Top addresses:  ")


def page_keys() -> Set[str]:
    sources = [ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "log_sentinel_page.py", ROOT / "src" / "oranovix_guardian" / "gui" / "app.py",
               ROOT / "src" / "oranovix_guardian" / "log_sentinel" / "export.py", ROOT / "src" / "oranovix_guardian" / "reports" / "pdf_generator.py"]
    keys: Set[str] = {"nav_log_sentinel", "language_web_log"}
    pattern = re.compile(r"""['"]((?:ls|pdf_attacks)_[a-z_]+)['"]""")
    for source in sources:
        keys.update(pattern.findall(source.read_text(encoding="utf-8")))
    keys.update(f"ls_severity_{s.value.lower()}" for s in Severity)
    keys.update(f"ls_format_{f.value}" for f in LogFormat)
    keys.update(f"ls_state_{s.value}" for s in EventState)
    return {key for key in keys if not key.endswith("_")}


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_every_text_exists_in_every_language(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    assert sorted(key for key in page_keys() if not texts.get(key)) == []


@pytest.mark.parametrize("language", ["de", "ar"])
def test_translations_keep_the_placeholders(language: str) -> None:
    english_texts = json.loads((TRANSLATIONS / "en.json").read_text(encoding="utf-8"))
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))
    placeholder = re.compile(r"\{[a-z_]+\}")
    keys = page_keys() | {key for key in english_texts if key.startswith(("ls_rule_", "ls_reason_"))}
    for key in keys:
        assert set(placeholder.findall(texts[key])) == set(placeholder.findall(english_texts[key])), key


def test_dsgvo_note_says_what_is_stored() -> None:
    texts = json.loads((TRANSLATIONS / "de.json").read_text(encoding="utf-8"))
    assert "DSGVO" in texts["ls_dsgvo_note"] and "/24" in texts["ls_dsgvo_note"]


def test_sample_log_is_plain_text_with_documentation_addresses() -> None:
    lines = sample_log_path().read_text(encoding="utf-8").splitlines()
    assert len(lines) > 200
    addresses = {line.split(" ", 1)[0] for line in lines}
    assert all(a.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for a in addresses)
    assert all("/Nov/2026:" in line for line in lines)
