"""Relevance matching against the fixture projects and the fixture OSV database."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

import pytest

from feed_fakes import FakeFetcher
from oranovix_guardian.scanner_engine.base import Severity
from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.threat_intel.models import FeedItem, PackageRef, Relevance
from oranovix_guardian.threat_intel.projects import Inventory, InventoryBuilder, Project
from oranovix_guardian.threat_intel.relevance import NameMatcher, RelevanceMatcher, Verdict
from oranovix_guardian.threat_intel.sources import CisaKevSource

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURES = Path(__file__).parent / "fixtures"
OLD_SHOP = Project("Shop", str(FIXTURES / "projects" / "old_shop"))
PATCHED_SHOP = Project("Patched", str(FIXTURES / "projects" / "patched_shop"))
TOOLBOX = Project("Toolbox", str(FIXTURES / "projects" / "toolbox"))


def inventories(*projects: Project) -> List[Inventory]:
    return InventoryBuilder().build_all(list(projects))


def kev_items() -> Dict[str, FeedItem]:
    body = (FIXTURES / "feeds" / "kev.json").read_bytes()
    items = CisaKevSource().fetch(FakeFetcher({CisaKevSource.URL: body}))
    return {item.cve_ids[0]: item for item in items}


def verdict(osv_db: OSVDatabase, item: FeedItem, projects: Sequence[Project]) -> Verdict:
    return RelevanceMatcher(osv_db).match([item], inventories(*projects))[item.id]


def news(title: str, **extra) -> FeedItem:
    item = FeedItem.build("News", title, title, "https://news.example.org/a", **extra)
    assert item is not None
    return item


# ---------------------------------------------------------------------------
# AFFECTS_YOU
# ---------------------------------------------------------------------------

def test_kev_item_for_a_package_pinned_in_the_vulnerable_range_affects_you(osv_db: OSVDatabase) -> None:
    result = verdict(osv_db, kev_items()["CVE-2019-14234"], [OLD_SHOP])

    assert result.relevance is Relevance.AFFECTS_YOU
    (match,) = result.matches
    assert match.project == "Shop"
    assert match.package == "Django" and match.version == "2.2.0" and match.ecosystem == "PyPI"
    assert match.advisory_id == "CVE-2019-14234"
    assert match.severity is Severity.CRITICAL          # the worst of the two OSV records
    assert match.fixed_version == "2.2.4"
    assert Path(match.file_path).name == "requirements.txt" and match.line == 2
    assert match.confirmed


def test_same_package_in_a_fixed_version_does_not_affect_you(osv_db: OSVDatabase) -> None:
    result = verdict(osv_db, kev_items()["CVE-2019-14234"], [PATCHED_SHOP])

    assert result.relevance is not Relevance.AFFECTS_YOU
    # The local database knows the range of this CVE, so it is not even "possible".
    assert result == Verdict(Relevance.GENERAL)


def test_only_the_project_with_the_vulnerable_version_is_named(osv_db: OSVDatabase) -> None:
    result = verdict(osv_db, kev_items()["CVE-2019-14234"], [PATCHED_SHOP, OLD_SHOP, TOOLBOX])
    assert [m.project for m in result.matches] == ["Shop"]


def test_news_item_that_names_the_cve_affects_you(osv_db: OSVDatabase) -> None:
    item = news("Attackers exploit Django flaw", summary="Tracked as cve-2019-14234.")
    result = verdict(osv_db, item, [OLD_SHOP])
    assert result.relevance is Relevance.AFFECTS_YOU
    assert result.matches[0].package == "Django"


def test_npm_package_from_a_lock_file_is_matched(osv_db: OSVDatabase, osv_records) -> None:
    lodash_advisory = osv_records[next(e for e in osv_records if e.value == "npm")][0]
    item = news(f"lodash advisory {lodash_advisory['id']}", cve_ids=lodash_advisory.get("aliases", []))
    assert item.cve_ids, "the fixture advisory has a CVE alias"

    result = verdict(osv_db, item, [OLD_SHOP])

    assert result.relevance is Relevance.AFFECTS_YOU
    (match,) = result.matches
    assert (match.package, match.version, match.ecosystem) == ("lodash", "4.17.15", "npm")
    assert Path(match.file_path).name == "package-lock.json"


def test_item_without_cve_but_with_a_registry_package_affects_you(osv_db: OSVDatabase) -> None:
    item = news("Django security release", packages=[PackageRef("pypi", "django")])
    result = verdict(osv_db, item, [OLD_SHOP, PATCHED_SHOP])
    assert result.relevance is Relevance.AFFECTS_YOU
    assert {m.project for m in result.matches} == {"Shop"}


def test_item_with_an_unknown_cve_is_not_confirmed_by_the_package_alone(osv_db: OSVDatabase) -> None:
    item = news("New Django flaw CVE-2099-7777", packages=[PackageRef("PyPI", "django")])
    assert verdict(osv_db, item, [OLD_SHOP]).relevance is Relevance.POSSIBLE


def test_unpinned_dependency_is_never_confirmed(osv_db: OSVDatabase, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("Django>=2.0\n", encoding="utf-8")
    result = verdict(osv_db, kev_items()["CVE-2019-14234"], [Project("Loose", str(tmp_path))])
    assert result.relevance is Relevance.POSSIBLE
    assert result.matches[0].version == "" and not result.matches[0].confirmed


# ---------------------------------------------------------------------------
# POSSIBLE and GENERAL
# ---------------------------------------------------------------------------

def test_product_name_only_match_is_possible(osv_db: OSVDatabase) -> None:
    result = verdict(osv_db, kev_items()["CVE-2099-1111"], [TOOLBOX])

    assert result.relevance is Relevance.POSSIBLE
    (match,) = result.matches
    assert match.project == "Toolbox" and match.package == "Lodash-Enterprise-Gateway"
    assert match.advisory_id == "" and match.severity is None and not match.confirmed


def test_unrelated_item_is_general(osv_db: OSVDatabase) -> None:
    result = verdict(osv_db, kev_items()["CVE-2099-2222"], [OLD_SHOP, PATCHED_SHOP, TOOLBOX])
    assert result == Verdict(Relevance.GENERAL)


def test_news_without_cve_or_package_is_general(osv_db: OSVDatabase) -> None:
    item = news("Ransomware gang hits hospital chain", summary="Django is not mentioned as a package here.")
    assert verdict(osv_db, item, [OLD_SHOP]) == Verdict(Relevance.GENERAL)


def test_no_projects_means_everything_is_general(osv_db: OSVDatabase) -> None:
    results = RelevanceMatcher(osv_db).match(kev_items().values(), [])
    assert {v.relevance for v in results.values()} == {Relevance.GENERAL}


def test_without_the_osv_database_nothing_is_confirmed(tmp_path: Path) -> None:
    matcher = RelevanceMatcher(OSVDatabase(str(tmp_path / "missing.db")))
    assert matcher.database_ready is False

    item = kev_items()["CVE-2019-14234"]
    result = matcher.match([item], inventories(OLD_SHOP))[item.id]

    assert result.relevance is Relevance.POSSIBLE       # the product name still matches


def test_every_item_gets_a_verdict(osv_db: OSVDatabase) -> None:
    items = list(kev_items().values())
    results = RelevanceMatcher(osv_db).match(items, inventories(OLD_SHOP, TOOLBOX))
    assert set(results) == {item.id for item in items}
    assert results[kev_items()["CVE-2019-14234"].id].relevance is Relevance.AFFECTS_YOU


@pytest.mark.parametrize("package, product, expected", [
    ("Django", "Django", True),
    ("django", "Django REST Framework", True),          # the product starts with the package
    ("lodash-enterprise-gateway", "Lodash Enterprise Gateway", True),
    ("log4j", "Log4j2", False),
    ("router", "Contoso Router", False),                # generic word, and not at the start
    ("server", "Server", False),                        # generic word
    ("ws", "WS_FTP Server", False),                     # too short to mean anything
    ("requests", "Multiple Products", False),
    ("flask", "", False),
])
def test_name_matching(package: str, product: str, expected: bool) -> None:
    assert NameMatcher.same(package, product) is expected
