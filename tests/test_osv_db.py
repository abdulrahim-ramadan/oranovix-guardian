"""The local OSV database: import, lookup, age, and that only ``update`` uses the network."""
from __future__ import annotations

import json
import urllib.request
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

from scanner_engine.base import Severity
from scanner_engine.deps import osv_db as osv_db_module
from scanner_engine.deps.osv_db import OSVDatabase, OSVUpdateError
from scanner_engine.deps.severity import CvssV3, OSVSeverity
from scanner_engine.deps.versions import Ecosystem

Records = Dict[Ecosystem, List[Dict[str, Any]]]


def write_archive(path: Path, records: List[Dict[str, Any]]) -> Path:
    """An ``all.zip`` as OSV publishes it: one JSON file per advisory."""
    with zipfile.ZipFile(path, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
        archive.writestr("README.txt", "not an advisory")
        archive.writestr("broken.json", "{not json")
    return path


# ---------------------------------------------------------------------------
# Import and lookup
# ---------------------------------------------------------------------------

def test_lookup_returns_advisories_with_aliases_and_ranges(osv_db: OSVDatabase) -> None:
    found = {v.id: v for v in osv_db.vulnerabilities_for(Ecosystem.PYPI, "Django")}

    assert set(found) == {"GHSA-fixt-ure1-0001", "GHSA-fixt-ure1-0002", "PYSEC-2019-13"}
    sql_injection = found["GHSA-fixt-ure1-0001"]
    assert sql_injection.cve == "CVE-2019-14234"
    assert sql_injection.summary == "SQL injection in Django"
    assert sql_injection.severity is Severity.CRITICAL
    assert [(e.kind, e.version) for e in sql_injection.ranges[2].events] == [
        ("introduced", "2.2"), ("fixed", "2.2.4"),
    ]


@pytest.mark.parametrize("name", ["django", "Django", "DJANGO"])
def test_pypi_lookup_ignores_case(osv_db: OSVDatabase, name: str) -> None:
    assert len(osv_db.vulnerabilities_for(Ecosystem.PYPI, name)) == 3


@pytest.mark.parametrize(
    "name", ["example-archive-tool", "Example_Archive.Tool", "example.archive_tool"]
)
def test_pypi_names_are_normalised_as_pep_503(osv_db: OSVDatabase, name: str) -> None:
    (found,) = osv_db.vulnerabilities_for(Ecosystem.PYPI, name)

    assert found.id == "GHSA-fixt-ure1-0003"


def test_ecosystems_are_kept_apart(osv_db: OSVDatabase) -> None:
    assert osv_db.vulnerabilities_for(Ecosystem.NPM, "django") == []
    assert osv_db.vulnerabilities_for(Ecosystem.PYPI, "lodash") == []
    assert osv_db.vulnerabilities_for(Ecosystem.PYPI, "not-an-npm-package") == []
    assert [v.id for v in osv_db.vulnerabilities_for(Ecosystem.NPM, "lodash")] == [
        "GHSA-fixt-ure2-0001"
    ]


def test_git_ranges_are_skipped(osv_db: OSVDatabase) -> None:
    assert osv_db.vulnerabilities_for(Ecosystem.PYPI, "git-only-package") == []
    pysec = next(
        v for v in osv_db.vulnerabilities_for(Ecosystem.PYPI, "django") if v.id == "PYSEC-2019-13"
    )
    assert [r.type for r in pysec.ranges] == ["ECOSYSTEM"]


def test_withdrawn_advisories_are_not_imported(osv_db: OSVDatabase) -> None:
    ids = {v.id for v in osv_db.vulnerabilities_for(Ecosystem.PYPI, "django")}

    assert "GHSA-fixt-ure1-0005" not in ids


def test_summary_falls_back_to_the_first_line_of_the_details(osv_db: OSVDatabase) -> None:
    pysec = next(
        v for v in osv_db.vulnerabilities_for(Ecosystem.PYPI, "django") if v.id == "PYSEC-2019-13"
    )

    assert pysec.summary.startswith("An issue was discovered in Django")


def test_import_from_zip_archives(tmp_path: Path, osv_records: Records) -> None:
    database = OSVDatabase(str(tmp_path / "osv.db"))
    archives = {
        ecosystem: write_archive(tmp_path / f"{ecosystem.value}.zip", records)
        for ecosystem, records in osv_records.items()
    }

    count = database.import_archives(archives)

    assert count == database.advisory_count() == 7
    assert len(database.vulnerabilities_for(Ecosystem.PYPI, "django")) == 3
    assert len(database.vulnerabilities_for(Ecosystem.NPM, "lodash")) == 1


def test_rebuild_replaces_the_old_content(osv_db: OSVDatabase, osv_records: Records) -> None:
    osv_db.import_records({Ecosystem.NPM: osv_records[Ecosystem.NPM]})

    assert osv_db.vulnerabilities_for(Ecosystem.PYPI, "django") == []
    assert len(osv_db.vulnerabilities_for(Ecosystem.NPM, "lodash")) == 1
    assert not osv_db.path.with_name("osv.db.new").exists()


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "vector, score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_v3_base_score(vector: str, score: float) -> None:
    assert CvssV3.base_score(vector) == score


@pytest.mark.parametrize(
    "vector", ["", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N"]
)
def test_other_vectors_have_no_v3_score(vector: str) -> None:
    assert CvssV3.base_score(vector) is None


@pytest.mark.parametrize(
    "record, severity",
    [
        ({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}, Severity.CRITICAL),
        ({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}], "database_specific": {"severity": "LOW"}}, Severity.HIGH),
        ({"database_specific": {"severity": "MODERATE"}}, Severity.MEDIUM),
        ({"database_specific": {"severity": "LOW"}}, Severity.LOW),
        ({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}], "database_specific": {"severity": "HIGH"}}, Severity.HIGH),
        ({}, Severity.MEDIUM),
    ],
    ids=["cvss-critical", "cvss-wins-over-label", "label-moderate", "label-low", "v4-falls-back-to-label", "default"],
)
def test_severity_of_a_record(record: Dict[str, Any], severity: Severity) -> None:
    assert OSVSeverity.of(record) is severity


def test_severity_is_stored_per_advisory(osv_db: OSVDatabase) -> None:
    by_id = {v.id: v.severity for v in osv_db.vulnerabilities_for(Ecosystem.PYPI, "django")}

    assert by_id["GHSA-fixt-ure1-0001"] is Severity.CRITICAL   # CVSS 9.8
    assert by_id["GHSA-fixt-ure1-0002"] is Severity.MEDIUM     # label MODERATE
    assert by_id["PYSEC-2019-13"] is Severity.MEDIUM           # nothing given
    (lodash,) = osv_db.vulnerabilities_for(Ecosystem.NPM, "lodash")
    assert lodash.severity is Severity.HIGH                    # CVSS 7.4


# ---------------------------------------------------------------------------
# Age
# ---------------------------------------------------------------------------

def test_missing_database(tmp_path: Path) -> None:
    database = OSVDatabase(str(tmp_path / "osv.db"))

    assert database.exists() is False
    assert database.updated_at() is None
    assert database.age_days() is None
    assert database.vulnerabilities_for(Ecosystem.PYPI, "django") == []
    assert "missing" in database.status_warning()


def test_fresh_database_has_no_warning(osv_db: OSVDatabase) -> None:
    assert osv_db.exists() is True
    assert osv_db.age_days() == 0
    assert osv_db.is_stale() is False
    assert osv_db.status_warning() == ""


@pytest.mark.parametrize("days, stale", [(14, False), (15, True), (40, True)])
def test_database_older_than_14_days_is_stale(
    tmp_path: Path, osv_records: Records, days: int, stale: bool
) -> None:
    built = datetime(2026, 1, 1, 12, 0, 0)
    path = str(tmp_path / "osv.db")
    OSVDatabase(path, clock=lambda: built).import_records(osv_records)

    later = OSVDatabase(path, clock=lambda: built + timedelta(days=days))

    assert later.updated_at() == built
    assert later.age_days() == days
    assert later.is_stale() is stale
    assert (f"{days} days old" in later.status_warning()) is stale


def test_a_file_that_is_not_a_database_counts_as_missing(tmp_path: Path) -> None:
    path = tmp_path / "osv.db"
    path.write_text("not sqlite", encoding="utf-8")
    database = OSVDatabase(str(path))

    assert database.exists() is False
    assert database.vulnerabilities_for(Ecosystem.PYPI, "django") == []


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

class FakeDownload:
    """Stands in for ``urllib.request.urlopen``: serves prepared zip files."""

    def __init__(self, files: Dict[str, Path]) -> None:
        self._files = files
        self.urls: List[str] = []

    def __call__(self, url: str, timeout: float = 0) -> Any:
        self.urls.append(url)
        return open(self._files[url], "rb")


def test_update_downloads_both_exports_and_builds_the_database(
    tmp_path: Path, osv_records: Records, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        OSVDatabase.SOURCES[ecosystem]: write_archive(tmp_path / f"{ecosystem.value}.zip", records)
        for ecosystem, records in osv_records.items()
    }
    download = FakeDownload(files)
    monkeypatch.setattr(osv_db_module.urllib.request, "urlopen", download)
    database = OSVDatabase(str(tmp_path / "osv.db"))
    messages: List[str] = []

    count = database.update(messages.append)

    assert count == 7
    assert download.urls == [
        "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    ]
    assert database.exists()
    assert len(database.vulnerabilities_for(Ecosystem.PYPI, "django")) == 3
    assert messages[-1] == "Importing advisories..."


def test_failed_download_keeps_the_old_database(
    osv_db: OSVDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(url: str, timeout: float = 0) -> Any:
        raise OSError("no network")

    monkeypatch.setattr(osv_db_module.urllib.request, "urlopen", refuse)
    before = osv_db.updated_at()

    with pytest.raises(OSVUpdateError):
        osv_db.update()

    assert osv_db.updated_at() == before
    assert len(osv_db.vulnerabilities_for(Ecosystem.PYPI, "django")) == 3


def test_broken_archive_keeps_the_old_database(osv_db: OSVDatabase, tmp_path: Path) -> None:
    broken = tmp_path / "PyPI.zip"
    broken.write_bytes(b"this is not a zip file")

    with pytest.raises(OSVUpdateError):
        osv_db.import_archives({Ecosystem.PYPI: broken})

    assert len(osv_db.vulnerabilities_for(Ecosystem.PYPI, "django")) == 3


def test_lookup_never_uses_the_network(osv_db: OSVDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access during a lookup")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    assert osv_db.vulnerabilities_for(Ecosystem.NPM, "lodash")
    assert osv_db.status_warning() == ""
