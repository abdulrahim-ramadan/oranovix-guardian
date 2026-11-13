"""Version comparison per ecosystem and the OSV range rules."""
from __future__ import annotations

from typing import List, Optional, Tuple

import pytest

from scanner_engine.base import Severity
from scanner_engine.deps.matcher import VersionMatcher
from scanner_engine.deps.osv_db import AffectedRange, OSVDatabase, RangeEvent, Vulnerability
from scanner_engine.deps.versions import Ecosystem, SemVer, scheme_for

Events = List[Tuple[str, str]]


def vulnerability(*ranges: Events, range_type: str = "ECOSYSTEM") -> Vulnerability:
    return Vulnerability(
        id="TEST-1", aliases=(), summary="", severity=Severity.MEDIUM,
        ranges=tuple(
            AffectedRange(range_type, tuple(RangeEvent(kind, version) for kind, version in events))
            for events in ranges
        ),
    )


def affected(ecosystem: Ecosystem, installed: str, *ranges: Events) -> bool:
    return VersionMatcher(ecosystem).match(installed, vulnerability(*ranges)) is not None


# ---------------------------------------------------------------------------
# semver
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "lower, higher",
    [
        ("1.0.0", "2.0.0"),
        ("2.0.0", "2.1.0"),
        ("2.1.0", "2.1.1"),
        ("4.17.9", "4.17.15"),
        ("1.0.0-alpha", "1.0.0"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-alpha.beta", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
        ("0", "0.0.1"),
    ],
)
def test_semver_order(lower: str, higher: str) -> None:
    low, high = SemVer.parse(lower), SemVer.parse(higher)

    assert low is not None and high is not None
    assert low < high and high > low and low != high


@pytest.mark.parametrize(
    "left, right", [("1.2.3", "v1.2.3"), ("1.2.3", "1.2.3+build.5"), ("1", "1.0.0"), ("1.2", "1.2.0")]
)
def test_semver_equality(left: str, right: str) -> None:
    assert SemVer.parse(left) == SemVer.parse(right)


@pytest.mark.parametrize("text", ["", "latest", "^1.2.3", "1.2.x", "~1.2", ">=1.0.0", "a.b.c"])
def test_ranges_and_tags_are_not_versions(text: str) -> None:
    assert SemVer.parse(text) is None


def test_pypi_versions_follow_pep_440() -> None:
    scheme = scheme_for(Ecosystem.PYPI)
    parse = scheme.parse

    assert parse("2.2") == parse("2.2.0")
    assert parse("2.2.0rc1") < parse("2.2.0") < parse("2.2.0.post1")   # type: ignore[operator]
    assert parse("1.10") > parse("1.9")                                # type: ignore[operator]
    assert parse("not a version") is None
    assert scheme.normalize_name("Flask_SQLAlchemy.ext") == "flask-sqlalchemy-ext"


# ---------------------------------------------------------------------------
# Range events
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "installed, expected",
    [("1.0.0", False), ("2.2.0", True), ("2.2.3", True), ("2.2.4", False), ("3.0", False)],
)
def test_introduced_and_fixed(installed: str, expected: bool) -> None:
    events = [("introduced", "2.2"), ("fixed", "2.2.4")]

    assert affected(Ecosystem.PYPI, installed, events) is expected


@pytest.mark.parametrize("installed, expected", [("0.0.1", True), ("3.2.24", True), ("3.2.25", False)])
def test_introduced_zero_means_from_the_first_version(installed: str, expected: bool) -> None:
    assert affected(Ecosystem.PYPI, installed, [("introduced", "0"), ("fixed", "3.2.25")]) is expected


@pytest.mark.parametrize(
    "installed, expected",
    [("0.9.0", False), ("1.0.0", True), ("1.4.2", True), ("1.4.3", False), ("2.0.0", False)],
)
def test_last_affected_is_inclusive(installed: str, expected: bool) -> None:
    events = [("introduced", "1.0.0"), ("last_affected", "1.4.2")]

    assert affected(Ecosystem.PYPI, installed, events) is expected
    assert affected(Ecosystem.NPM, installed, events) is expected


def test_introduced_without_an_end_stays_open() -> None:
    assert affected(Ecosystem.NPM, "99.0.0", [("introduced", "1.0.0")]) is True
    assert affected(Ecosystem.NPM, "0.9.9", [("introduced", "1.0.0")]) is False


@pytest.mark.parametrize(
    "installed, expected",
    [("1.5.0", True), ("2.0.1", False), ("2.5.0", False), ("3.0.0", True), ("3.0.9", True), ("3.1.0", False)],
)
def test_several_intervals_in_one_range(installed: str, expected: bool) -> None:
    events = [("introduced", "0"), ("fixed", "2.0.1"), ("introduced", "3.0.0"), ("fixed", "3.1.0")]

    assert affected(Ecosystem.PYPI, installed, events) is expected


def test_events_are_ordered_before_evaluation() -> None:
    shuffled = [("fixed", "3.1.0"), ("introduced", "3.0.0"), ("fixed", "2.0.1"), ("introduced", "0")]

    assert affected(Ecosystem.PYPI, "3.0.5", shuffled) is True
    assert affected(Ecosystem.PYPI, "2.5.0", shuffled) is False


def test_limit_ends_a_range_like_fixed() -> None:
    events = [("introduced", "1.0.0"), ("limit", "2.0.0")]

    assert affected(Ecosystem.NPM, "1.9.9", events) is True
    assert affected(Ecosystem.NPM, "2.0.0", events) is False


def test_any_of_several_ranges_is_enough() -> None:
    first = [("introduced", "1.11"), ("fixed", "1.11.23")]
    second = [("introduced", "2.2"), ("fixed", "2.2.4")]

    assert affected(Ecosystem.PYPI, "2.2.0", first, second) is True
    assert affected(Ecosystem.PYPI, "2.0.0", first, second) is False


def test_prerelease_before_the_fix_is_affected() -> None:
    events = [("introduced", "2.0.0-beta.1"), ("fixed", "2.0.0")]

    assert affected(Ecosystem.NPM, "2.0.0-beta.2", events) is True
    assert affected(Ecosystem.NPM, "2.0.0-alpha.9", events) is False
    assert affected(Ecosystem.NPM, "2.0.0", events) is False


@pytest.mark.parametrize("installed", ["", "latest", "^4.17.15", "not-a-version"])
def test_unparseable_installed_version_is_never_reported(installed: str) -> None:
    assert affected(Ecosystem.NPM, installed, [("introduced", "0")]) is False


def test_range_with_an_unparseable_event_is_not_evaluated() -> None:
    assert affected(Ecosystem.PYPI, "1.0", [("introduced", "0"), ("fixed", "abc123def")]) is False


# ---------------------------------------------------------------------------
# Fixed version
# ---------------------------------------------------------------------------

def match_fix(ecosystem: Ecosystem, installed: str, *ranges: Events) -> Optional[Tuple[str, str]]:
    match = VersionMatcher(ecosystem).match(installed, vulnerability(*ranges))
    return None if match is None else (match.fixed_version, match.last_affected)


def test_fix_is_the_lowest_fixed_version_above_the_installed_one() -> None:
    ranges: List[Events] = [
        [("introduced", "1.11"), ("fixed", "1.11.23")],
        [("introduced", "2.1"), ("fixed", "2.1.11")],
        [("introduced", "2.2"), ("fixed", "2.2.4")],
    ]

    assert match_fix(Ecosystem.PYPI, "2.2.0", *ranges) == ("2.2.4", "")
    assert match_fix(Ecosystem.PYPI, "1.11.5", *ranges) == ("1.11.23", "")
    assert match_fix(Ecosystem.PYPI, "2.1.0", *ranges) == ("2.1.11", "")


def test_no_fixed_version_reports_the_last_affected_one() -> None:
    events = [("introduced", "1.0.0"), ("last_affected", "1.4.2")]

    assert match_fix(Ecosystem.PYPI, "1.2.0", events) == ("", "1.4.2")
    assert match_fix(Ecosystem.PYPI, "1.4.2", events) == ("", "1.4.2")


def test_open_range_has_no_fix() -> None:
    assert match_fix(Ecosystem.NPM, "5.0.0", [("introduced", "1.0.0")]) == ("", "")


def test_fixture_database_and_matcher_together(osv_db: OSVDatabase) -> None:
    matcher = VersionMatcher(Ecosystem.NPM)
    (lodash,) = osv_db.vulnerabilities_for(Ecosystem.NPM, "lodash")

    old = matcher.match("4.17.15", lodash)
    assert old is not None and old.fixed_version == "4.17.19"
    assert matcher.match("4.17.19", lodash) is None
    assert matcher.match("4.17.21", lodash) is None
