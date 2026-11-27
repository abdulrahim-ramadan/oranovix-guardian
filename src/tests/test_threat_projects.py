"""Project registry, dependency inventory and the link to the scan history."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.threat_intel.projects import (
    InventoryBuilder,
    Project,
    ProjectError,
    ProjectRegistry,
    ScanSummary,
    ScanSummaryLookup,
)
from oranovix_guardian.threat_intel.store import FeedDatabase

PROJECTS = Path(__file__).parent / "fixtures" / "projects"
OLD_SHOP = PROJECTS / "old_shop"
PATCHED_SHOP = PROJECTS / "patched_shop"
TRANSLATIONS = AppPaths.resource("translations")


@pytest.fixture
def registry(tmp_path: Path) -> ProjectRegistry:
    return ProjectRegistry(FeedDatabase(str(tmp_path / "feed.db")))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_add_list_remove(registry: ProjectRegistry) -> None:
    shop = registry.add("Shop", str(OLD_SHOP), "https://shop.example.org/")
    blog = registry.add("blog", str(PATCHED_SHOP))

    assert shop == Project("Shop", str(OLD_SHOP.resolve()), "https://shop.example.org/")
    assert blog.site_url is None
    assert [p.name for p in registry.list()] == ["blog", "Shop"]

    assert registry.remove("blog") is True
    assert registry.remove("blog") is False
    assert [p.name for p in registry.list()] == ["Shop"]


def test_projects_are_persisted(tmp_path: Path) -> None:
    path = str(tmp_path / "feed.db")
    ProjectRegistry(FeedDatabase(path)).add("Shop", str(OLD_SHOP), "https://shop.example.org/")

    reopened = ProjectRegistry(FeedDatabase(path))

    assert reopened.get("Shop") == Project("Shop", str(OLD_SHOP.resolve()), "https://shop.example.org/")


def test_site_address_brings_the_ownership_notice(registry: ProjectRegistry) -> None:
    with_site = registry.add("Shop", str(OLD_SHOP), "https://shop.example.org/")
    without = registry.add("Blog", str(PATCHED_SHOP))

    assert ProjectRegistry.site_notice_key(with_site) == "proj_site_notice"
    assert ProjectRegistry.site_notice_key(without) == ""
    english = json.loads((TRANSLATIONS / "en.json").read_text(encoding="utf-8"))
    assert english["proj_site_notice"] == "Only add sites you own."


@pytest.mark.parametrize("url", ["ftp://shop.example.org", "javascript:alert(1)", "shop.example.org", "file:///c:/x"])
def test_site_address_must_be_a_web_address(registry: ProjectRegistry, url: str) -> None:
    with pytest.raises(ProjectError, match="http"):
        registry.add("Shop", str(OLD_SHOP), url)
    assert registry.list() == []


def test_name_and_folder_are_required_and_unique(registry: ProjectRegistry, tmp_path: Path) -> None:
    registry.add("Shop", str(OLD_SHOP))
    with pytest.raises(ProjectError, match="already exists"):
        registry.add("shop", str(PATCHED_SHOP))
    with pytest.raises(ProjectError, match="already the project Shop"):
        registry.add("Other", str(OLD_SHOP))
    with pytest.raises(ProjectError, match="name"):
        registry.add("  ", str(PATCHED_SHOP))
    with pytest.raises(ProjectError, match="folder"):
        registry.add("Ghost", str(tmp_path / "missing"))


def test_site_address_can_be_changed_and_cleared(registry: ProjectRegistry) -> None:
    registry.add("Shop", str(OLD_SHOP))
    assert registry.set_site_url("Shop", "http://localhost:8000/").site_url == "http://localhost:8000/"
    assert registry.set_site_url("Shop", "").site_url is None
    assert registry.get("Shop") == Project("Shop", str(OLD_SHOP.resolve()))


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def test_inventory_lists_ecosystem_name_and_version() -> None:
    inventory = InventoryBuilder().build(Project("Shop", str(OLD_SHOP)))

    assert sorted(inventory.packages(), key=lambda p: (p[0], p[1].lower())) == [
        ("PyPI", "Django", "2.2.0"),
        ("PyPI", "example-archive-tool", "1.4.2"),
        ("PyPI", "requests", None),                 # a range, not a pinned version
        ("npm", "express", "4.18.2"),
        ("npm", "lodash", "4.17.15"),
    ]
    assert inventory.warnings == ()


def test_inventory_knows_where_a_package_is_declared() -> None:
    inventory = InventoryBuilder().build(Project("Shop", str(OLD_SHOP)))
    django = next(d for d in inventory.dependencies if d.name == "Django")
    assert Path(django.file_path) == OLD_SHOP / "requirements.txt"
    assert django.line == 2


def test_inventory_of_every_project() -> None:
    projects = [Project("Shop", str(OLD_SHOP)), Project("Patched", str(PATCHED_SHOP))]
    shop, patched = InventoryBuilder().build_all(projects)
    assert patched.packages() == [("PyPI", "Django", "5.1.0")]
    assert shop.project.name == "Shop"


def test_broken_manifest_is_a_warning_not_an_error(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    inventory = InventoryBuilder().build(Project("Broken", str(tmp_path)))

    assert inventory.packages() == [("PyPI", "flask", "3.0.0")]
    assert len(inventory.warnings) == 1 and "package-lock.json" in inventory.warnings[0]


def test_missing_folder_gives_an_empty_inventory(tmp_path: Path) -> None:
    inventory = InventoryBuilder().build(Project("Gone", str(tmp_path / "gone")))
    assert inventory.dependencies == () and inventory.warnings


# ---------------------------------------------------------------------------
# Latest scan
# ---------------------------------------------------------------------------

def history(tmp_path: Path, *rows: tuple) -> str:
    path = str(tmp_path / "scan_history.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_date TEXT NOT NULL, "
            "target_path TEXT NOT NULL, files_scanned INTEGER DEFAULT 0, total_issues INTEGER DEFAULT 0, "
            "critical_count INTEGER DEFAULT 0, high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0, "
            "low_count INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0, duration_secs REAL DEFAULT 0.0)"
        )
        conn.executemany(
            "INSERT INTO scans (scan_date, target_path, total_issues, critical_count, high_count, risk_score) "
            "VALUES (?, ?, ?, ?, ?, ?)", rows,
        )
    return path


def test_project_is_linked_to_its_latest_scan(tmp_path: Path) -> None:
    db_path = history(
        tmp_path,
        ("2026-11-01T10:00:00", str(OLD_SHOP), 9, 3, 4, 100),
        ("2026-11-10T08:30:00", str(PATCHED_SHOP), 0, 0, 0, 0),
        ("2026-11-15T17:45:00", str(OLD_SHOP), 5, 1, 2, 80),
    )
    lookup = ScanSummaryLookup(db_path)

    assert lookup.latest_for(Project("Shop", str(OLD_SHOP))) == ScanSummary(
        datetime(2026, 11, 15, 17, 45), critical=1, high=2, total_issues=5, risk_score=80
    )
    assert lookup.latest_for(Project("Patched", str(PATCHED_SHOP))) == ScanSummary(
        datetime(2026, 11, 10, 8, 30), 0, 0, 0, 0
    )


def test_scan_of_the_same_folder_typed_differently_still_matches(tmp_path: Path) -> None:
    typed = str(OLD_SHOP / "frontend" / "..")
    lookup = ScanSummaryLookup(history(tmp_path, ("2026-11-15T17:45:00", typed, 5, 1, 2, 80)))
    summary = lookup.latest_for(Project("Shop", str(OLD_SHOP)))
    assert summary is not None and summary.critical == 1


def test_project_never_scanned_has_no_summary(tmp_path: Path) -> None:
    lookup = ScanSummaryLookup(history(tmp_path, ("2026-11-15T17:45:00", str(OLD_SHOP / "frontend"), 1, 0, 0, 5)))
    assert lookup.latest_for(Project("Shop", str(OLD_SHOP))) is None
    assert ScanSummaryLookup(str(tmp_path / "none.db")).latest_for(Project("Shop", str(OLD_SHOP))) is None
