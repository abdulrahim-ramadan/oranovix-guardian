"""Dependency scan end to end: manifests in, DEP findings out, no network."""
from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from scanner_engine.base import Issue, ScanResult, ScanStatus, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.deps.dependency_scanner import DependencyScanner
from scanner_engine.deps.osv_db import OSVDatabase
from scanner_engine.orchestrator import ScanOrchestrator, ScanProgress, ScanStage


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to open a connection fails the test."""
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access during a dependency scan")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def package_lock(**versions: str) -> str:
    packages: Dict[str, Any] = {"": {"name": "shop", "version": "1.0.0"}}
    for name, version in versions.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return json.dumps({"name": "shop", "lockfileVersion": 3, "packages": packages}, indent=2)


def scan(osv_db: OSVDatabase, target: Path) -> ScanResult:
    return DependencyScanner(osv_db).scan(str(target))


def vulnerable(result: ScanResult) -> List[Issue]:
    return [i for i in result.issues if i.rule_id == "DEP001"]


def unpinned(result: ScanResult) -> List[Issue]:
    return [i for i in result.issues if i.rule_id == "DEP002"]


# ---------------------------------------------------------------------------
# Vulnerable dependencies
# ---------------------------------------------------------------------------

def test_old_django_is_reported_with_a_fixed_version(osv_db: OSVDatabase, tmp_path: Path) -> None:
    manifest = write(tmp_path / "requirements.txt", "# web\nDjango==2.2.0\n")

    result = scan(osv_db, tmp_path)

    assert result.status is ScanStatus.COMPLETED
    assert result.engine_warnings == []
    findings = vulnerable(result)
    assert len(findings) >= 1
    sql_injection = next(i for i in findings if "CVE-2019-14234" in i.title)
    assert sql_injection.title == "Django 2.2.0: CVE-2019-14234 (SQL injection)"
    assert sql_injection.rule_id == "DEP001"
    assert sql_injection.category is IssueCategory.DEPENDENCY
    assert sql_injection.severity is Severity.CRITICAL
    assert sql_injection.file_path == str(manifest)
    assert sql_injection.line_number == 2
    assert sql_injection.code_snippet == "Django==2.2.0"
    assert sql_injection.recommendation == "Upgrade to 2.2.4 or later."
    assert sql_injection.dependency is not None
    assert sql_injection.dependency.fixed_version == "2.2.4"
    assert sql_injection.dependency.package == "Django"
    assert sql_injection.dependency.version == "2.2.0"


def test_one_finding_per_package_and_vulnerability(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "Django==2.2.0\n")

    findings = vulnerable(scan(osv_db, tmp_path))

    # Two advisories apply to 2.2.0. The GHSA and the PYSEC record of
    # CVE-2019-14234 are the same vulnerability and give one finding.
    assert sorted(i.title for i in findings) == [
        "Django 2.2.0: CVE-2019-14234 (SQL injection)",
        "Django 2.2.0: CVE-2024-27351 (Regular expression denial of service)",
    ]
    grouped = next(i for i in findings if "CVE-2019-14234" in i.title)
    assert grouped.dependency is not None
    assert grouped.dependency.vulnerability_ids == (
        "CVE-2019-14234", "GHSA-fixt-ure1-0001", "PYSEC-2019-13",
    )
    other = next(i for i in findings if "CVE-2024-27351" in i.title)
    assert other.severity is Severity.MEDIUM
    assert other.recommendation == "Upgrade to 3.2.25 or later."
    assert len({i.finding_key for i in findings}) == 2


def test_new_django_fixed_before_it_has_no_finding(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "Django==5.1.0\n")

    result = scan(osv_db, tmp_path)

    assert result.issues == []
    assert result.engine_warnings == []


def test_lodash_in_package_lock_is_reported(osv_db: OSVDatabase, tmp_path: Path) -> None:
    lock = write(tmp_path / "package-lock.json", package_lock(lodash="4.17.15", express="4.18.2"))

    (finding,) = vulnerable(scan(osv_db, tmp_path))

    assert finding.title == "lodash 4.17.15: CVE-2020-8203 (Prototype pollution)"
    assert finding.severity is Severity.HIGH
    assert finding.recommendation == "Upgrade to 4.17.19 or later."
    assert finding.file_path == str(lock)
    assert finding.code_snippet == '"node_modules/lodash": {'
    assert finding.dependency is not None and finding.dependency.ecosystem == "npm"


def test_patched_lodash_is_not_reported(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "package-lock.json", package_lock(lodash="4.17.21"))

    assert scan(osv_db, tmp_path).issues == []


@pytest.mark.parametrize("version, reported", [("1.4.2", True), ("1.4.3", False), ("0.9", False)])
def test_range_with_only_last_affected(
    osv_db: OSVDatabase, tmp_path: Path, version: str, reported: bool
) -> None:
    write(tmp_path / "requirements.txt", f"example-archive-tool=={version}\n")

    findings = vulnerable(scan(osv_db, tmp_path))

    assert bool(findings) is reported
    if reported:
        assert findings[0].recommendation == (
            "No fixed version is listed. Upgrade to a version later than 1.4.2."
        )
        assert findings[0].dependency is not None
        assert findings[0].dependency.fixed_version == ""


def test_package_name_is_normalised(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "DJANGO==2.2.0\nExample.Archive_Tool==1.0.0\n")

    titles = [i.title for i in vulnerable(scan(osv_db, tmp_path))]

    assert any(t.startswith("DJANGO 2.2.0: CVE-2019-14234") for t in titles)
    assert any(t.startswith("Example.Archive_Tool 1.0.0: CVE-2099-0003") for t in titles)


def test_fix_stays_on_the_installed_release_line(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "example-rce-lib==3.0.2\n")

    (finding,) = vulnerable(scan(osv_db, tmp_path))

    assert finding.severity is Severity.CRITICAL
    assert finding.recommendation == "Upgrade to 3.1.0 or later."


# ---------------------------------------------------------------------------
# Unpinned dependencies
# ---------------------------------------------------------------------------

def test_unpinned_dependency_gives_exactly_one_low_finding(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    write(tmp_path / "requirements.txt", "Django>=2.0\n")

    result = scan(osv_db, tmp_path)

    (finding,) = result.issues
    assert finding.rule_id == "DEP002"
    assert finding.severity is Severity.LOW
    assert finding.title == "Unpinned dependency: Django (>=2.0)"
    assert finding.category is IssueCategory.DEPENDENCY
    assert finding.line_number == 1


def test_dependency_without_any_version_is_unpinned(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "django\n")

    (finding,) = scan(osv_db, tmp_path).issues

    assert finding.title == "Unpinned dependency: django (no version)"
    assert finding.severity is Severity.LOW


def test_lock_file_replaces_the_ranges_of_the_manifest(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
    write(tmp_path / "package-lock.json", package_lock(lodash="4.17.15"))

    result = scan(osv_db, tmp_path)

    assert unpinned(result) == []
    assert [i.title for i in vulnerable(result)] == [
        "lodash 4.17.15: CVE-2020-8203 (Prototype pollution)"
    ]


def test_manifest_without_lock_file_reports_ranges_as_unpinned(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    write(tmp_path / "package.json", json.dumps(
        {"dependencies": {"lodash": "4.17.15", "express": "^4.18.0"}}, indent=2
    ))

    result = scan(osv_db, tmp_path)

    assert [i.title for i in unpinned(result)] == ["Unpinned dependency: express (^4.18.0)"]
    assert len(vulnerable(result)) == 1


# ---------------------------------------------------------------------------
# Database state
# ---------------------------------------------------------------------------

def test_missing_database_gives_a_warning_and_the_scan_completes(tmp_path: Path) -> None:
    write(tmp_path / "project" / "requirements.txt", "Django==2.2.0\nrequests>=2.0\n")
    missing = OSVDatabase(str(tmp_path / "no-such.db"))

    result = DependencyScanner(missing).scan(str(tmp_path / "project"))

    assert result.status is ScanStatus.COMPLETED
    assert len(result.engine_warnings) == 1
    assert "vulnerability database is missing" in result.engine_warnings[0]
    assert vulnerable(result) == []
    assert len(unpinned(result)) == 1          # needs no database


def test_stale_database_warns_but_still_reports(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    from datetime import datetime, timedelta

    write(tmp_path / "project" / "requirements.txt", "Django==2.2.0\n")
    stale = OSVDatabase(str(osv_db.path), clock=lambda: datetime.now() + timedelta(days=30))

    result = DependencyScanner(stale).scan(str(tmp_path / "project"))

    assert len(result.engine_warnings) == 1
    assert "days old" in result.engine_warnings[0]
    assert len(vulnerable(result)) == 2


def test_broken_manifest_is_a_warning_not_a_failure(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "package.json", "{not json")
    write(tmp_path / "requirements.txt", "Django==2.2.0\n")

    result = scan(osv_db, tmp_path)

    assert result.status is ScanStatus.COMPLETED
    assert result.engine_warnings == ["Dependency scan: package.json is not valid JSON."]
    assert len(vulnerable(result)) == 2


def test_project_without_manifests_is_silent(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "print(1)\n")
    missing = OSVDatabase(str(tmp_path / "no-such.db"))

    result = DependencyScanner(missing).scan(str(tmp_path))

    assert result.issues == []
    assert result.engine_warnings == []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def orchestrate(osv_db: OSVDatabase, target: Path, progress: List[ScanProgress]) -> ScanResult:
    return ScanOrchestrator(
        dependency_scanner=DependencyScanner(osv_db), on_progress=progress.append
    ).scan(str(target))


def test_orchestrator_runs_the_stage_when_a_manifest_exists(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    write(tmp_path / "app.py", "print(1)\n")
    write(tmp_path / "requirements.txt", "Django==2.2.0\n")
    progress: List[ScanProgress] = []

    result = orchestrate(osv_db, tmp_path, progress)

    assert ScanStage.DEPENDENCIES in {p.stage for p in progress}
    # Both vulnerabilities sit on the same line and must stay separate findings.
    assert len(vulnerable(result)) == 2
    assert result.files_scanned == 2
    assert result.engine_warnings == []


def test_orchestrator_skips_the_stage_without_a_manifest(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    write(tmp_path / "app.py", "print(1)\n")
    progress: List[ScanProgress] = []

    result = orchestrate(osv_db, tmp_path, progress)

    assert ScanStage.DEPENDENCIES not in {p.stage for p in progress}
    assert result.issues == []


def test_orchestrator_reports_a_missing_database_and_completes(tmp_path: Path) -> None:
    write(tmp_path / "project" / "requirements.txt", "Django==2.2.0\n")
    progress: List[ScanProgress] = []
    missing = OSVDatabase(str(tmp_path / "no-such.db"))

    result = orchestrate(missing, tmp_path / "project", progress)

    assert result.status is ScanStatus.COMPLETED
    assert any("vulnerability database is missing" in w for w in result.engine_warnings)
    assert any(p.level == "error" and "missing" in p.message for p in progress)


def test_manifests_in_third_party_folders_are_ignored(osv_db: OSVDatabase, tmp_path: Path) -> None:
    write(tmp_path / "node_modules" / "x" / "package-lock.json", package_lock(lodash="4.17.15"))
    write(tmp_path / "venv" / "requirements.txt", "Django==2.2.0\n")
    write(tmp_path / "app.py", "print(1)\n")

    assert orchestrate(osv_db, tmp_path, []).issues == []


# ---------------------------------------------------------------------------
# Alarm
# ---------------------------------------------------------------------------

class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


def test_critical_dependency_goes_through_the_alarm_center(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    write(project / "requirements.txt", "Django==2.2.0\nexample-rce-lib==1.0.0\n")
    result = scan(osv_db, project)
    channel = RecordingChannel()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])

    alarm = center.notify(result.issues, str(project))

    assert alarm is not None and alarm.level is AlarmLevel.CRITICAL
    assert alarm.worst_issue.rule_id == "DEP001"
    # Two criticals on different lines, and the medium one is not alarmed.
    assert len(alarm.finding_ids) == 2
    assert center.notify(result.issues, str(project)) is None      # only once


def test_vulnerabilities_on_one_line_have_different_alarm_ids(
    osv_db: OSVDatabase, tmp_path: Path
) -> None:
    write(tmp_path / "requirements.txt", "Django==2.2.0\n")
    first, second = vulnerable(scan(osv_db, tmp_path))

    assert first.line_number == second.line_number
    assert AlarmCenter.finding_id(first, str(tmp_path)) != AlarmCenter.finding_id(second, str(tmp_path))
