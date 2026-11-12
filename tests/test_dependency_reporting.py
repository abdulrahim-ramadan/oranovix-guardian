"""Dependency findings in the results filter and the PDF report."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from gui.pages.results_page import ResultsPage
from reports.pdf_generator import PDFReportGenerator
from scanner_engine.base import Issue, ScanResult, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.deps.dependency_scanner import DependencyScanner
from scanner_engine.deps.osv_db import OSVDatabase

TRANSLATIONS = Path(__file__).parent.parent / "translations"


@pytest.fixture
def result(osv_db: OSVDatabase, tmp_path: Path) -> ScanResult:
    """Three vulnerable packages, one unpinned one, and one ordinary finding."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "Django==2.2.0\nexample-archive-tool==1.2.0\nrequests>=2.0\n", encoding="utf-8"
    )
    (project / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"name": "shop"}, "node_modules/lodash": {"version": "4.17.15"}},
    }, indent=2), encoding="utf-8")

    scanned = DependencyScanner(osv_db).scan(str(project))
    scanned.issues.append(Issue(
        rule_id="B307", title="Use of eval()", description="eval",
        severity=Severity.CRITICAL, file_path=str(project / "app.py"), line_number=3,
        category=IssueCategory.CODE_EXEC,
    ))
    return scanned


# ---------------------------------------------------------------------------
# Results filter
# ---------------------------------------------------------------------------

def test_dependencies_filter_shows_only_dependency_findings(result: ScanResult) -> None:
    shown = ResultsPage.filter_issues(result.issues, ResultsPage.FILTER_DEPENDENCIES)

    assert len(shown) == 5
    assert {i.rule_id for i in shown} == {"DEP001", "DEP002"}
    assert all(i.category is IssueCategory.DEPENDENCY for i in shown)


def test_severity_filters_still_work(result: ScanResult) -> None:
    critical = ResultsPage.filter_issues(result.issues, "CRITICAL")
    low = ResultsPage.filter_issues(result.issues, "LOW")

    assert sorted(i.rule_id for i in critical) == ["B307", "DEP001"]
    assert [i.rule_id for i in low] == ["DEP002"]
    assert ResultsPage.filter_issues(result.issues, "ALL") == result.issues


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def test_pdf_rows_list_package_version_ids_and_fix(result: ScanResult) -> None:
    rows = PDFReportGenerator.dependency_rows(result)

    assert rows == [
        ("Django", "2.2.0", "CVE-2019-14234, GHSA-fixt-ure1-0001, PYSEC-2019-13",
         "Upgrade to 2.2.4 or later."),
        ("lodash", "4.17.15", "CVE-2020-8203, GHSA-fixt-ure2-0001",
         "Upgrade to 4.17.19 or later."),
        ("Django", "2.2.0", "CVE-2024-27351, GHSA-fixt-ure1-0002",
         "Upgrade to 3.2.25 or later."),
        ("example-archive-tool", "1.2.0", "CVE-2099-0003, GHSA-fixt-ure1-0003",
         "No fixed version is listed. Upgrade to a version later than 1.4.2."),
    ]


def test_pdf_rows_are_empty_without_vulnerable_dependencies() -> None:
    empty = ScanResult(target_path="x", scan_id="1")

    assert PDFReportGenerator.dependency_rows(empty) == []


def section_titles(result: ScanResult) -> List[str]:
    """Text of the section headers the dependency section adds to the story."""
    story: list = []
    PDFReportGenerator()._add_vulnerable_dependencies(
        story, result, _styles(), lambda key, **kwargs: key
    )
    return [flowable.getPlainText() for flowable in story if hasattr(flowable, "getPlainText")]


def _styles() -> dict:
    from reports.pdf_generator import StyleBuilder

    return StyleBuilder(False).build()


def test_pdf_section_is_added_only_when_there_is_something_to_list(result: ScanResult) -> None:
    assert section_titles(result) == ["pdf_vulnerable_dependencies"]
    assert section_titles(ScanResult(target_path="x", scan_id="1")) == []


def test_pdf_with_dependency_section_is_written(result: ScanResult, tmp_path: Path) -> None:
    output = tmp_path / "report.pdf"

    path = PDFReportGenerator().generate(result, str(output))

    assert Path(path) == output
    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 2000


# ---------------------------------------------------------------------------
# Translations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_dependency_texts_exist_in_every_language(language: str) -> None:
    texts = json.loads((TRANSLATIONS / f"{language}.json").read_text(encoding="utf-8"))

    for key in (
        "filter_dependencies", "language_config", "deps_db_title", "deps_db_update",
        "deps_db_date", "deps_db_missing", "deps_db_stale", "deps_db_updating",
        "deps_db_failed", "deps_db_hint", "pdf_vulnerable_dependencies",
        "pdf_dep_package", "pdf_dep_version", "pdf_dep_ids", "pdf_dep_fix",
    ):
        assert texts.get(key), f"{language}: {key}"
