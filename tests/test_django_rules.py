"""Django rule tests: every rule has a vulnerable and a safe case in tests/corpus/django_app."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

import pytest

from core.alarm_center import AlarmCenter, AlarmChannel, AlarmLevel, Alarm, SqliteSeenFindingStore
from scanner_engine.base import Issue, ScanResult, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.django_settings_rules import DjangoSettingsAnalyzer
from scanner_engine.orchestrator import ScanOrchestrator
from scanner_engine.taint import TaintTracker
from scanner_engine.vulnerability_db import VulnerabilityDatabase

DJANGO_APP = Path(__file__).parent / "corpus" / "django_app"
VIEWS = DJANGO_APP / "views.py"
VULNERABLE_SETTINGS = DJANGO_APP / "settings.py"
HARDENED_SETTINGS = DJANGO_APP / "hardened" / "settings.py"
VULNERABLE_TEMPLATE = DJANGO_APP / "templates" / "profile_vulnerable.html"
SAFE_TEMPLATE = DJANGO_APP / "templates" / "profile_safe.html"

VIEW_RULES = [f"DJ{number:03d}" for number in range(1, 11)]
SETTINGS_RULES = [f"DS{number:03d}" for number in range(1, 7)]
TEMPLATE_RULES = ["DT001", "DT002"]


@dataclass(frozen=True)
class Case:
    """One top-level function or class of views.py named ``<rule>_<vulnerable|safe>...``."""

    name: str
    rule_id: str
    vulnerable: bool
    first_line: int
    last_line: int


def view_cases() -> List[Case]:
    cases: List[Case] = []
    for node in ast.parse(VIEWS.read_text(encoding="utf-8")).body:
        if not isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            continue
        marker = node.name.lower().replace("_", "")
        if not marker.startswith("dj0"):
            continue
        kind = marker[5:]
        assert kind.startswith(("vulnerable", "safe")), node.name
        first_line = min([node.lineno, *(d.lineno for d in node.decorator_list)])
        cases.append(Case(
            node.name, marker[:5].upper(), kind.startswith("vulnerable"),
            first_line, node.end_lineno or node.lineno,
        ))
    return cases


def rule_ids(issue: Issue) -> Set[str]:
    return {issue.rule_id, *issue.also_detected_by}


def rules_by_file(result: ScanResult) -> Dict[str, Set[str]]:
    found: Dict[str, Set[str]] = {}
    for issue in result.issues:
        found.setdefault(Path(issue.file_path).as_posix(), set()).update(rule_ids(issue))
    return found


@pytest.fixture(scope="module")
def result() -> ScanResult:
    return ScanOrchestrator().scan(str(DJANGO_APP))


@pytest.fixture(scope="module")
def by_file(result: ScanResult) -> Dict[str, Set[str]]:
    return rules_by_file(result)


# ---------------------------------------------------------------------------
# Views: DJ001 - DJ010
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", VIEW_RULES)
def test_every_view_rule_has_a_vulnerable_and_a_safe_case(rule_id: str) -> None:
    kinds = {case.vulnerable for case in view_cases() if case.rule_id == rule_id}
    assert kinds == {True, False}


@pytest.mark.parametrize("case", view_cases(), ids=lambda case: case.name)
def test_view_case(case: Case, result: ScanResult) -> None:
    reported = [
        issue for issue in result.issues
        if Path(issue.file_path) == VIEWS
        and case.first_line <= issue.line_number <= case.last_line
        and case.rule_id in rule_ids(issue)
    ]
    if case.vulnerable:
        assert reported, f"{case.rule_id} not reported in {case.name}"
    else:
        assert reported == [], f"{case.rule_id} wrongly reported in {case.name}"


def test_view_rules_report_nothing_outside_their_own_cases(result: ScanResult) -> None:
    cases = view_cases()
    for issue in result.issues:
        if Path(issue.file_path) != VIEWS:
            continue
        for rule_id in rule_ids(issue) & set(VIEW_RULES):
            owners = [c for c in cases if c.first_line <= issue.line_number <= c.last_line]
            assert owners and owners[0].rule_id == rule_id and owners[0].vulnerable, (
                f"{rule_id} at line {issue.line_number}"
            )


def test_idor_is_high_with_low_confidence(result: ScanResult) -> None:
    idor = [issue for issue in result.issues if issue.rule_id == "DJ010"]
    assert idor
    for issue in idor:
        assert issue.severity is Severity.HIGH
        assert issue.confidence == "LOW" and issue.needs_review


def test_taint_rule_merges_with_bandit_and_keeps_confidence_and_help(result: ScanResult) -> None:
    merged = [
        issue for issue in result.issues
        if issue.category is IssueCategory.SQL_INJECTION and len(rule_ids(issue)) > 1
        and "DJ006" in rule_ids(issue)
    ]
    assert merged
    for issue in merged:
        assert issue.severity is Severity.CRITICAL
        assert not issue.needs_review
        assert issue.what_is_it and issue.fix_suggestion


# ---------------------------------------------------------------------------
# Settings: DS001 - DS006
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", SETTINGS_RULES)
def test_settings_rule(rule_id: str, by_file: Dict[str, Set[str]]) -> None:
    assert rule_id in by_file[VULNERABLE_SETTINGS.as_posix()]
    assert rule_id not in by_file.get(HARDENED_SETTINGS.as_posix(), set())


def test_settings_rules_only_run_on_settings_files(by_file: Dict[str, Set[str]]) -> None:
    assert not by_file[VIEWS.as_posix()] & set(SETTINGS_RULES)
    assert DjangoSettingsAnalyzer.is_settings_file("project/settings/production.py")
    assert not DjangoSettingsAnalyzer.is_settings_file("project/views.py")


def test_partial_settings_file_is_not_blamed_for_missing_settings() -> None:
    code = "from .base import *\nDEBUG = False\nSESSION_COOKIE_SECURE = False\n"
    issues = DjangoSettingsAnalyzer.analyze(code, "project/settings/dev.py")
    assert [(issue.rule_id, issue.line_number) for issue in issues] == [("DS002", 3)]


# ---------------------------------------------------------------------------
# Templates: DT001, DT002
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", TEMPLATE_RULES)
def test_template_rule(rule_id: str, by_file: Dict[str, Set[str]]) -> None:
    assert rule_id in by_file[VULNERABLE_TEMPLATE.as_posix()]
    assert rule_id not in by_file.get(SAFE_TEMPLATE.as_posix(), set())


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", VIEW_RULES + SETTINGS_RULES + TEMPLATE_RULES)
def test_every_rule_has_category_severity_and_database_entry(rule_id: str, result: ScanResult) -> None:
    info = VulnerabilityDatabase.get(rule_id.lower())
    assert info is not None
    assert info.what_is_it and info.why_dangerous and info.how_exploited and info.fix_suggestion

    own = [issue for issue in result.issues if issue.rule_id == rule_id]
    assert own, f"{rule_id} never leads a finding in the corpus"
    for issue in own:
        assert issue.category is not IssueCategory.OTHER
        assert issue.severity is info.severity
        assert issue.what_is_it == info.what_is_it


def test_expected_severities(result: ScanResult) -> None:
    expected = {
        "DJ001": "HIGH", "DJ002": "CRITICAL", "DJ003": "HIGH", "DJ004": "CRITICAL",
        "DJ005": "HIGH", "DJ007": "CRITICAL", "DJ008": "HIGH", "DJ009": "MEDIUM",
        "DJ010": "HIGH", "DS001": "HIGH", "DS002": "MEDIUM", "DS003": "HIGH",
        "DS004": "MEDIUM", "DS005": "HIGH", "DS006": "LOW", "DT001": "MEDIUM",
        "DT002": "HIGH",
    }
    for issue in result.issues:
        if issue.rule_id in expected:
            assert issue.severity.value == expected[issue.rule_id], issue.rule_id


def test_django_scan_is_deterministic(result: ScanResult) -> None:
    def fingerprint(scan: ScanResult) -> List[tuple]:
        return sorted((i.file_path, i.line_number, i.rule_id) for i in scan.issues)

    assert fingerprint(ScanOrchestrator().scan(str(DJANGO_APP))) == fingerprint(result)


# ---------------------------------------------------------------------------
# Taint tracker
# ---------------------------------------------------------------------------

def tainted_sinks(source: str) -> Dict[int, bool]:
    """Line -> taint of the argument, for every ``sink(...)`` call in *source*."""
    scope = ast.parse(source).body[0]
    assert isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
    tracker = TaintTracker(scope)
    return {
        call.lineno: tracker.is_tainted(call.args[0])
        for call in tracker.calls()
        if isinstance(call.func, ast.Name) and call.func.id == "sink"
    }


def test_taint_flows_through_string_building() -> None:
    source = (
        "def view(request):\n"
        "    a = request.GET['a']\n"
        "    sink(a)\n"
        "    sink(request.POST.get('b'))\n"
        "    sink('x' + a)\n"
        "    sink(f'{a}!')\n"
        "    sink('%s' % a)\n"
        "    sink('{}'.format(a))\n"
        "    sink(request.user.username)\n"
        "    sink('constant')\n"
    )
    assert tainted_sinks(source) == {
        3: True, 4: True, 5: True, 6: True, 7: True, 8: True, 9: False, 10: False,
    }


def test_sanitizers_clear_taint() -> None:
    source = (
        "def view(request):\n"
        "    a = request.GET['a']\n"
        "    sink(int(a))\n"
        "    sink(float(a))\n"
        "    sink(uuid.UUID(a))\n"
        "    sink(os.path.basename(a))\n"
        "    sink(get_valid_filename(a))\n"
        "    sink(escape(a))\n"
        "    sink(a)\n"
        "    a = int(a)\n"
        "    sink(a)\n"
    )
    assert tainted_sinks(source) == {
        3: False, 4: False, 5: False, 6: False, 7: False, 8: False, 9: True, 11: False,
    }


def test_url_check_clears_taint_only_where_it_holds() -> None:
    source = (
        "def view(request):\n"
        "    url = request.GET['next']\n"
        "    if url_has_allowed_host_and_scheme(url, allowed_hosts=None):\n"
        "        sink(url)\n"
        "    sink(url)\n"
        "    if not url_has_allowed_host_and_scheme(url, allowed_hosts=None):\n"
        "        return None\n"
        "    sink(url)\n"
    )
    assert tainted_sinks(source) == {4: False, 5: True, 8: False}


# ---------------------------------------------------------------------------
# Alarm: sound only for confident criticals
# ---------------------------------------------------------------------------

class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


class SoundLikeChannel(RecordingChannel):
    levels = frozenset({AlarmLevel.CRITICAL})


def finding(severity: Severity, confidence: str, line: int = 3) -> Issue:
    return Issue(
        "DJ006", "SQL injection", "description", severity, "/project/views.py", line,
        confidence=confidence, category=IssueCategory.SQL_INJECTION,
    )


@pytest.mark.parametrize("confidence, sounds", [("HIGH", 1), ("MEDIUM", 1), ("LOW", 0)])
def test_sound_only_for_critical_with_confidence_not_low(
    tmp_path: Path, confidence: str, sounds: int
) -> None:
    toast, sound = RecordingChannel(), SoundLikeChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [toast, sound])

    alarm = center.notify([finding(Severity.CRITICAL, confidence)], "/project")

    assert alarm is not None and len(toast.alarms) == 1
    assert len(sound.alarms) == sounds
    assert alarm.needs_review is (confidence == "LOW")


def test_low_confidence_high_finding_is_shown_but_silent(tmp_path: Path) -> None:
    toast, sound = RecordingChannel(), SoundLikeChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [toast, sound])

    alarm = center.notify([finding(Severity.HIGH, "LOW")], "/project")

    assert alarm is not None and alarm.needs_review
    assert len(toast.alarms) == 1 and sound.alarms == []


def test_confident_critical_still_sounds_next_to_a_low_confidence_one(tmp_path: Path) -> None:
    sound = SoundLikeChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [sound])

    alarm = center.notify(
        [finding(Severity.CRITICAL, "LOW"), finding(Severity.CRITICAL, "HIGH", line=9)],
        "/project",
    )

    assert alarm is not None and not alarm.needs_review
    assert alarm.worst_issue.line_number == 9
    assert len(sound.alarms) == 1
