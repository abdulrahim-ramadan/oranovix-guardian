"""Symlinks and junctions: severity by place and by where they point."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from live_defense.base import ChangeType, IntegrityEvent
from live_defense.baseline import Baseline, FileTree, IgnoreRules
from live_defense.file_integrity import ChangeClassifier, FileIntegrityMonitor
from live_defense.paths import LinkInfo
from scanner_engine.base import Severity


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


def write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def only(events: List[IntegrityEvent]) -> IntegrityEvent:
    assert len(events) == 1, [e.event_id for e in events]
    return events[0]


def symlink(target: Path, link: Path, directory: bool = False) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra rights on this system")


def junction(target: Path, link: Path) -> None:
    if os.name != "nt":
        pytest.skip("directory junctions exist on Windows only")
    import _winapi

    link.parent.mkdir(parents=True, exist_ok=True)
    _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    site = tmp_path / "site"
    write(site / "app" / "views.py", "def index(request):\n    return None\n")
    write(site / "uploads" / "logo.png", "png\n")
    write(site / "docs" / "guide.txt", "read me\n")
    return site


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    folder = tmp_path / "elsewhere"
    write(folder / "passwd", "root:x:0:0\n")
    return folder


@pytest.fixture
def monitor(root: Path, tmp_path: Path) -> FileIntegrityMonitor:
    baseline = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())
    baseline.create()
    return FileIntegrityMonitor(baseline, file_scanner=lambda path: [])


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

INSIDE = LinkInfo("../docs/guide.txt", "/srv/site/docs/guide.txt", outside_root=False)
OUTSIDE = LinkInfo("/etc/passwd", "/etc/passwd", outside_root=True)


@pytest.mark.parametrize(
    "relative, link, severity",
    [
        ("docs/readme", INSIDE, Severity.MEDIUM),
        ("docs/readme", OUTSIDE, Severity.MEDIUM),
        ("uploads/readme", INSIDE, Severity.HIGH),
        ("uploads/readme", OUTSIDE, Severity.CRITICAL),
        ("static/css/x", OUTSIDE, Severity.CRITICAL),
    ],
)
@pytest.mark.parametrize("change", [ChangeType.NEW, ChangeType.MODIFIED])
def test_link_severity(relative: str, link: LinkInfo, severity: Severity, change: ChangeType) -> None:
    assert ChangeClassifier().classify(change, relative, link=link)[0] is severity


def test_link_reason_names_the_target() -> None:
    _, reasons = ChangeClassifier().classify(ChangeType.NEW, "uploads/avatar.png", link=OUTSIDE)

    assert reasons[0] == (
        "New link in the uploads/ folder points outside the monitored folder: /etc/passwd"
    )


def test_changed_link_reason() -> None:
    _, reasons = ChangeClassifier().classify(ChangeType.MODIFIED, "docs/readme", link=INSIDE)

    assert reasons[0] == "Changed link points to ../docs/guide.txt"


def test_link_in_a_root_named_uploads() -> None:
    severity, _ = ChangeClassifier().classify(ChangeType.NEW, "x", root_name="uploads", link=OUTSIDE)

    assert severity is Severity.CRITICAL


def test_link_with_executable_name_in_public_stays_critical() -> None:
    assert ChangeClassifier().classify(ChangeType.NEW, "uploads/x.php", link=INSIDE)[0] is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Symlinks on disk (skipped where they cannot be created)
# ---------------------------------------------------------------------------

def test_symlink_to_outside_file_in_uploads_is_critical(
    monitor: FileIntegrityMonitor, root: Path, outside: Path
) -> None:
    symlink(outside / "passwd", root / "uploads" / "avatar.png")

    event = only(monitor.check())

    assert event.severity is Severity.CRITICAL
    assert str(outside / "passwd") in event.reasons[0]


def test_symlink_inside_root_in_uploads_is_high(monitor: FileIntegrityMonitor, root: Path) -> None:
    symlink(root / "docs" / "guide.txt", root / "uploads" / "guide.txt")

    assert only(monitor.check()).severity is Severity.HIGH


def test_symlink_outside_public_is_medium(
    monitor: FileIntegrityMonitor, root: Path, outside: Path
) -> None:
    symlink(outside / "passwd", root / "docs" / "passwd")

    assert only(monitor.check()).severity is Severity.MEDIUM


def test_dangling_symlink_counts_as_outside(monitor: FileIntegrityMonitor, root: Path, tmp_path: Path) -> None:
    symlink(tmp_path / "does-not-exist", root / "uploads" / "gone")

    assert only(monitor.check()).severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Junctions on disk (Windows)
# ---------------------------------------------------------------------------

def test_junction_to_outside_folder_in_uploads_is_critical(
    monitor: FileIntegrityMonitor, root: Path, outside: Path
) -> None:
    junction(outside, root / "uploads" / "etc")

    event = only(monitor.check())

    assert event.relative_path == "uploads/etc"
    assert event.severity is Severity.CRITICAL
    assert event.reasons[0].endswith(f"points outside the monitored folder: {outside}")


def test_junction_inside_root_in_uploads_is_high(monitor: FileIntegrityMonitor, root: Path) -> None:
    junction(root / "docs", root / "uploads" / "docs")

    event = only(monitor.check())

    assert event.severity is Severity.HIGH
    assert event.reasons[0] == f"New link in the uploads/ folder points to {root / 'docs'}"


def test_junction_outside_public_is_medium(
    monitor: FileIntegrityMonitor, root: Path, outside: Path
) -> None:
    junction(outside, root / "app" / "etc")

    assert only(monitor.check()).severity is Severity.MEDIUM


def test_link_in_uploads_is_left_out_of_a_new_baseline(
    root: Path, tmp_path: Path, outside: Path
) -> None:
    junction(outside, root / "uploads" / "etc")
    junction(root / "docs", root / "app" / "docs")
    baseline = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())

    result = baseline.create()

    assert [s.relative_path for s in result.suspicious] == ["uploads/etc"]
    assert "points outside the monitored folder" in result.suspicious[0].reasons[0]
    assert "app/docs" in baseline.entries()
    event = only(FileIntegrityMonitor(baseline, file_scanner=lambda path: []).check())
    assert event.relative_path == "uploads/etc"
    assert event.severity is Severity.CRITICAL


def test_retargeted_junction_is_a_modified_link(
    root: Path, tmp_path: Path, outside: Path
) -> None:
    baseline = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())
    baseline.create()
    monitor = FileIntegrityMonitor(baseline, file_scanner=lambda path: [])
    junction(root / "docs", root / "uploads" / "docs")
    assert only(monitor.check()).severity is Severity.HIGH
    assert monitor.accept_all() == 1
    os.rmdir(root / "uploads" / "docs")
    junction(outside, root / "uploads" / "docs")

    event = only(monitor.check())

    assert event.change is ChangeType.MODIFIED
    assert event.severity is Severity.CRITICAL
    assert event.reasons[0].startswith("Changed link in the uploads/ folder points outside")


def test_link_info_of_a_junction(root: Path, outside: Path) -> None:
    junction(outside, root / "uploads" / "etc")

    info = FileTree(str(root), IgnoreRules()).link_info("uploads/etc")

    assert info.target == str(outside)
    assert info.outside_root is True
