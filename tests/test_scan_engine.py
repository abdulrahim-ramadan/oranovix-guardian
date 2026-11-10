"""Engine tests: run the orchestrator against tests/corpus (no GUI)."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from scanner_engine.bandit_runner import BanditRunner, BanditUnavailableError
from scanner_engine.base import BaseScanner, FileMatcher, Issue, Language, ScanResult, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.factory import ScannerFactory
from scanner_engine.orchestrator import ScanOrchestrator

CORPUS = Path(__file__).parent / "corpus"
MIXED_PROJECT = CORPUS / "mixed_project"
SINGLE = CORPUS / "single"


def scan(target: Path) -> ScanResult:
    return ScanOrchestrator().scan(str(target))


def result_with(critical: int) -> ScanResult:
    result = ScanResult(target_path="x", scan_id="x")
    result.issues = [
        Issue("R", "title", "description", Severity.CRITICAL, "f.py", line)
        for line in range(critical)
    ]
    return result


@pytest.fixture(scope="module")
def mixed_result() -> ScanResult:
    return scan(MIXED_PROJECT)


def test_mixed_folder_reports_python_and_javascript(mixed_result: ScanResult) -> None:
    languages = {issue.language for issue in mixed_result.issues}
    assert Language.PYTHON in languages
    assert Language.JAVASCRIPT in languages


def test_factory_returns_one_scanner_per_language_present() -> None:
    scanners = ScannerFactory.scanners_for_target(str(MIXED_PROJECT))
    assert {s.language for s in scanners} == {Language.PYTHON, Language.JAVASCRIPT}


def test_file_under_venv_produces_no_issues(mixed_result: ScanResult) -> None:
    assert (MIXED_PROJECT / "venv" / "lib" / "vendored.py").exists()
    in_venv = [i for i in mixed_result.issues if "venv" in Path(i.file_path).parts]
    assert in_venv == []
    assert mixed_result.files_scanned == 2


def test_hardcoded_password_yields_exactly_one_issue() -> None:
    issues = scan(SINGLE / "hardcoded_password.py").issues
    assert len(issues) == 1
    issue = issues[0]
    assert issue.category is IssueCategory.SECRET
    assert issue.severity is Severity.CRITICAL
    assert set(issue.also_detected_by) == {"B105", "AST-SEC1", "SEC-PWD01"}
    assert "Hardcoded Hardcoded" not in issue.title


def test_os_system_is_reported_by_bandit() -> None:
    result = scan(SINGLE / "os_system.py")
    assert result.engine_warnings == []
    assert "B605" in {issue.rule_id for issue in result.issues}


def test_forced_bandit_failure_adds_engine_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(self: BanditRunner, files: List[str]):
        raise BanditUnavailableError("forced failure")

    monkeypatch.setattr(BanditRunner, "run", fail)
    result = scan(SINGLE / "os_system.py")
    assert result.engine_warnings
    assert "Bandit" in result.engine_warnings[0]


def test_open_with_path_object_yields_no_issue() -> None:
    assert scan(SINGLE / "safe_open.py").issues == []


def test_version_string_yields_no_issue() -> None:
    assert scan(SINGLE / "version_string.py").issues == []


def test_three_criticals_score_lower_than_ten() -> None:
    assert result_with(critical=3).risk_score < result_with(critical=10).risk_score


def test_score_stays_within_bounds() -> None:
    assert result_with(critical=0).risk_score == 0
    assert result_with(critical=300).risk_score == 100


@pytest.mark.parametrize("dotenv_name", [".env", ".env.production"])
def test_dotenv_file_yields_two_critical_secrets(dotenv_name: str) -> None:
    result = scan(CORPUS / dotenv_name)
    assert result.files_scanned == 1
    assert len(result.issues) == 2
    assert all(issue.severity is Severity.CRITICAL for issue in result.issues)
    assert {issue.rule_id for issue in result.issues} == {"SEC-CONN1", "SEC-AWS01"}


def test_dotenv_files_are_found_when_scanning_a_folder() -> None:
    by_file = scan(CORPUS).issues_by_file()
    for dotenv_name in (".env", ".env.production"):
        issues = by_file.get(str(CORPUS / dotenv_name), [])
        assert len(issues) == 2, dotenv_name
        assert all(issue.severity is Severity.CRITICAL for issue in issues)


def test_extensionless_config_files_are_scanned_for_secrets() -> None:
    by_name = {
        Path(path).name: issues
        for path, issues in scan(CORPUS / "config_files").issues_by_file().items()
    }
    assert {"Dockerfile", ".npmrc"} <= set(by_name)


def test_file_matcher_handles_dotfiles_and_plain_names() -> None:
    matcher = FileMatcher([".env", ".py"], ["Dockerfile", ".npmrc"])
    for name in (".env", ".env.local", ".env.production", "app.py", "settings.ENV",
                 "Dockerfile", "dockerfile.dev", ".npmrc"):
        assert matcher.matches(name), name
    for name in (".environment", "env", "notes.md", "Dockerfiles", ".pyrc"):
        assert not matcher.matches(name), name


def test_collect_files_accepts_a_single_dotfile() -> None:
    dotenv = CORPUS / ".env"
    assert BaseScanner.collect_files(str(dotenv), [".env"]) == [str(dotenv)]


def test_issue_titles_are_never_generic_bandit_names() -> None:
    issues = scan(SINGLE / "bandit_generic_titles.py").issues
    titles = {issue.rule_id: issue.title for issue in issues}

    assert {"B307", "B324", "B301", "B506"} <= set(titles)
    for generic in ("Blacklist", "Hashlib", "Yaml Load"):
        assert generic not in titles.values()
    assert "eval()" in titles["B307"]
    assert titles["B301"] == "Unsafe pickle deserialization"
    assert titles["B506"] == "Unsafe yaml.load()"
