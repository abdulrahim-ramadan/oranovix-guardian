"""PDF report: markup characters in findings, and secret values.

A ``<`` in any text (OSV summaries such as "XSS via <svg>" or
"versions < 2.0") used to stop the whole report with
``ValueError: paraparser: syntax error``. And the report printed full
secret values although it is meant to be shared.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest

pypdf = pytest.importorskip("pypdf")

from oranovix_guardian.reports.pdf_generator import PDFReportConfig, PDFReportGenerator  # noqa: E402
from oranovix_guardian.scanner_engine.base import Issue, ScanResult, ScanStatus, Severity  # noqa: E402
from oranovix_guardian.scanner_engine.categories import IssueCategory  # noqa: E402
from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator  # noqa: E402

CORPUS = Path(__file__).parent / "corpus"
CORPUS_SECRETS = ["AKIAIOSFODNN7EXAMPLE", "Pa55wordForNpm", "Pa55word", "SuperSecret123"]


def pdf_text(path: str) -> str:
    reader = pypdf.PdfReader(path)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return re.sub(r"\s+", " ", text)


def result_with(issues: List[Issue], **fields) -> ScanResult:
    result = ScanResult(target_path=fields.pop("target_path", "C:/site"), scan_id="1",
                        status=ScanStatus.COMPLETED, files_scanned=1, **fields)
    result.issues = issues
    return result


# ---------------------------------------------------------------------------
# Markup characters
# ---------------------------------------------------------------------------

def markup_issue() -> Issue:
    return Issue(
        rule_id="OSV<1>&2",
        title="XSS via <svg onload=alert(1)> & friends",
        description="Affects versions < 2.0 & >= 1.0; see <b>not bold</b>",
        severity=Severity.HIGH,
        file_path="C:/site/a<b>&c.py",
        line_number=3,
        code_snippet="if a < b and c > d & e: pass",
        recommendation="Upgrade to >= 2.0 & check <script> handling",
        cwe="CWE-79 <XSS> & co",
        confidence="HIGH<&>",
        category=IssueCategory.XSS,
        also_detected_by=["R<2>", "R&3"],
    )


def test_markup_in_every_field_does_not_break_the_report(tmp_path: Path) -> None:
    result = result_with([markup_issue()], scanner_name="Engine <A> & B",
                         engine_warnings=["x.py: not analysed (a < b & c > d)"])
    result.target_path = "C:/site/<project> & co"

    path = PDFReportGenerator().generate(result, str(tmp_path / "report.pdf"))

    text = pdf_text(path)
    assert "XSS via <svg onload=alert(1)> & friends" in text
    assert "versions < 2.0 & >= 1.0" in text
    assert "<b>not bold</b>" in text
    assert "Upgrade to >= 2.0 & check <script> handling" in text
    assert "a<b>&c.py:3" in text
    assert "CWE-79 <XSS> & co" in text


def test_the_snippet_is_cut_before_it_is_escaped(tmp_path: Path) -> None:
    issue = markup_issue()
    issue.code_snippet = "x" * 298 + "<<<<&&&&"          # the cut lands inside the special characters

    path = PDFReportGenerator().generate(result_with([issue]), str(tmp_path / "report.pdf"))

    assert "x" * 50 in pdf_text(path)


def test_markup_in_the_most_common_list_and_file_table(tmp_path: Path) -> None:
    issues = [markup_issue(), markup_issue()]

    path = PDFReportGenerator().generate(result_with(issues), str(tmp_path / "report.pdf"))

    assert "OSV<1>&2" in pdf_text(path)


# ---------------------------------------------------------------------------
# Secret values
# ---------------------------------------------------------------------------

def test_a_report_of_the_vulnerable_corpus_shows_no_full_secret(tmp_path: Path) -> None:
    result = ScanOrchestrator().scan(str(CORPUS))
    assert any(i.category is IssueCategory.SECRET for i in result.issues)

    text = pdf_text(PDFReportGenerator(PDFReportConfig(show_secret_values=False)).generate(
        result, str(tmp_path / "corpus.pdf")))

    leaked = [value for value in CORPUS_SECRETS if value in text]
    assert leaked == []
    assert re.search(r"AKIA.{1,3}MPLE", text), "the masked AWS key should still be recognisable"


DJANGO_KEY = "django-insecure-q8#w3n!x7z@p2k5m9v4b6c1d0f"
BANDIT_PASSWORD = "Tr0ub4dor-and-3-horses"


@pytest.fixture
def secret_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "settings.py").write_text(f"SECRET_KEY = '{DJANGO_KEY}'\nDEBUG = False\n", encoding="utf-8")
    (root / "db.py").write_text(f'def connect():\n    password = "{BANDIT_PASSWORD}"\n    return password\n',
                                encoding="utf-8")
    (root / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    return root


def test_django_key_aws_key_and_bandit_password_are_masked(secret_project: Path, tmp_path: Path) -> None:
    result = ScanOrchestrator().scan(str(secret_project))
    assert any("B105" in (i.rule_id, *i.also_detected_by) for i in result.issues)

    text = pdf_text(PDFReportGenerator(PDFReportConfig(show_secret_values=False)).generate(
        result, str(tmp_path / "secrets.pdf")))

    for value in (DJANGO_KEY, BANDIT_PASSWORD, "AKIAIOSFODNN7EXAMPLE"):
        assert value not in text
    assert re.search(r"djan.{1,3}0f", text) or re.search(r"\*{4}", text)


def test_secret_values_are_shown_when_the_setting_is_on(secret_project: Path, tmp_path: Path) -> None:
    result = ScanOrchestrator().scan(str(secret_project))

    text = pdf_text(PDFReportGenerator(PDFReportConfig(show_secret_values=True)).generate(
        result, str(tmp_path / "secrets.pdf")))

    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_the_setting_is_off_by_default_and_read_from_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.core.settings_file import SettingsFile
    from oranovix_guardian.reports.pdf_generator import SHOW_SECRETS_SETTING
    monkeypatch.setenv("ORANOVIX_DATA_DIR", str(tmp_path / "data"))

    assert PDFReportGenerator().show_secret_values is False
    SettingsFile().set(SHOW_SECRETS_SETTING, True)
    assert PDFReportGenerator().show_secret_values is True


@pytest.mark.parametrize("text, hidden", [
    ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("Possible hardcoded password: 'Tr0ub4dor-and-3-horses'", "Tr0ub4dor-and-3-horses"),
    ('password = "Pa55word"', "Pa55word"),
    ("DATABASE_URL=postgresql://admin:Pa55word@db.internal:5432/prod", "Pa55word"),
    ('//registry.example.com/:_password="Pa55wordForNpm"', "Pa55wordForNpm"),
    ("api_token: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("SECRET_KEY = 'django-insecure-q8#w3n!x7z@p2k5m9v4b6c1d0f'", "django-insecure-q8#w3n!x7z@p2k5m9v4b6c1d0f"),
])
def test_the_masker_hides_the_value(text: str, hidden: str) -> None:
    from oranovix_guardian.reports.secret_masking import SecretMasker

    masked = SecretMasker.mask(text)

    assert hidden not in masked
    if len(hidden) >= 12:
        assert hidden[:4] + "…" + hidden[-4:] in masked


def test_the_masker_keeps_names() -> None:
    from oranovix_guardian.reports.secret_masking import SecretMasker

    assert SecretMasker.mask('password = "Pa55word"').startswith("password = ")


def test_non_secret_findings_are_not_masked(tmp_path: Path) -> None:
    issue = Issue(
        rule_id="B608", title="SQL built from strings", description="query = 'SELECT name FROM users'",
        severity=Severity.HIGH, file_path="C:/site/db.py", line_number=4,
        code_snippet="cursor.execute('SELECT name FROM users WHERE id=' + uid)",
        category=IssueCategory.SQL_INJECTION,
    )

    text = pdf_text(PDFReportGenerator(PDFReportConfig(show_secret_values=False)).generate(
        result_with([issue]), str(tmp_path / "r.pdf")))

    assert "SELECT name FROM users WHERE id=" in text
