"""Config files are shown as "Config", never as "Unknown"."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from core.alarm_center import Alarm, AlarmCenter, AlarmChannel, SqliteSeenFindingStore
from core.language_manager import LanguageManager
from gui.pages.scanner_page import ScannerPage
from scanner_engine.base import Issue, Language, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.orchestrator import ScanOrchestrator
from scanner_engine.secrets_detector import SecretsDetector

AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def english() -> None:
    LanguageManager().set_language("en")


@pytest.mark.parametrize(
    "name",
    [
        ".env", ".env.production", "Dockerfile", "Dockerfile.dev", "docker-compose.yml",
        ".npmrc", ".pypirc", ".htpasswd", "settings.ini", "app.yaml", "config.json",
        "pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile.lock",
        "poetry.lock", "package.json", "package-lock.json", "pom.xml", "app.properties",
    ],
)
def test_config_files_are_config(name: str) -> None:
    assert Language.from_path(f"/project/{name}") is Language.CONFIG
    assert Language.from_path(f"C:\\project\\{name}") is Language.CONFIG


@pytest.mark.parametrize(
    "name, language",
    [
        ("app.py", Language.PYTHON),
        ("web.ts", Language.JAVASCRIPT),
        ("index.php", Language.PHP),
        ("App.java", Language.JAVA),
        ("Program.cs", Language.CSHARP),
        ("page.html", Language.HTML),
        ("tool.go", Language.UNKNOWN),
    ],
)
def test_source_files_keep_their_language(name: str, language: Language) -> None:
    assert Language.from_path(f"/project/{name}") is language


def make_issue(file_path: str) -> Issue:
    return Issue(
        rule_id="SEC-AWS01", title="Hardcoded AWS Access Key ID", description="",
        severity=Severity.CRITICAL, file_path=file_path, line_number=2,
        category=IssueCategory.SECRET, confidence="HIGH",
    )


def test_issue_in_a_config_file_has_the_config_language() -> None:
    assert make_issue("/project/.env").language is Language.CONFIG
    assert make_issue("/project/Dockerfile").language is Language.CONFIG
    assert make_issue("/project/app.py").language is Language.PYTHON


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


def test_toast_for_a_secret_in_dotenv_says_config(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"DEBUG=1\nAWS_KEY={AWS_EXAMPLE}\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(f"FROM python\nENV K={AWS_EXAMPLE}\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text(f"registry=x\n_auth={AWS_EXAMPLE}\n", encoding="utf-8")
    issues = SecretsDetector().scan(str(tmp_path)).issues
    channel = RecordingChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])

    alarm = center.notify(issues, str(tmp_path))

    assert alarm is not None
    assert alarm.counts_by_language == {"Config": 3}
    assert "Config" in alarm.message
    assert "Unknown" not in alarm.message


def test_dependency_findings_say_config(osv_db, tmp_path: Path) -> None:
    from scanner_engine.deps.dependency_scanner import DependencyScanner

    (tmp_path / "requirements.txt").write_text("Django==2.2.0\n", encoding="utf-8")

    result = DependencyScanner(osv_db).scan(str(tmp_path))

    assert {issue.language for issue in result.issues} == {Language.CONFIG}
    assert DependencyScanner(osv_db).language is Language.CONFIG


def test_detected_languages_text() -> None:
    text = ScannerPage.detected_languages_text

    assert text([Language.PYTHON], ["/p/app.py"]) == "Python"
    assert text([Language.PYTHON], ["/p/app.py", "/p/.env"]) == "Python, Config"
    assert text([], ["/p/.env", "/p/Dockerfile"]) == "Config"
    assert text([], []) == "Unknown"


def test_a_folder_of_only_config_files_is_detected_as_config(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python\n", encoding="utf-8")

    files = ScanOrchestrator.scannable_files(str(tmp_path))

    assert ScannerPage.detected_languages_text([], files) == "Config"


def test_config_label_is_translated() -> None:
    lm = LanguageManager()
    issue = make_issue("/project/.env")

    lm.set_language("de")
    try:
        assert AlarmCenter.language_label(issue) == "Konfiguration"
    finally:
        lm.set_language("en")
    assert AlarmCenter.language_label(issue) == "Config"
    assert AlarmCenter.language_label(make_issue("/project/app.py")) == "Python"
