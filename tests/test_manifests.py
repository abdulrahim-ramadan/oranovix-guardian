"""Manifest parsers: names, exact versions, unpinned entries and line numbers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from scanner_engine.deps.manifests import (
    Dependency,
    ManifestError,
    ManifestFinder,
    PackageJsonParser,
    PackageLockParser,
    PipfileLockParser,
    PoetryLockParser,
    PyprojectParser,
    RequirementsParser,
)
from scanner_engine.deps.versions import Ecosystem


def by_name(dependencies: List[Dependency]) -> Dict[str, Dependency]:
    return {d.name: d for d in dependencies}


def summary(dependencies: List[Dependency]) -> List[Tuple[str, Optional[str], int]]:
    return [(d.name, d.version, d.line) for d in dependencies]


# ---------------------------------------------------------------------------
# requirements*.txt
# ---------------------------------------------------------------------------

REQUIREMENTS = """\
# web
Django==2.2.0
requests>=2.0        # unpinned
flask
-r base.txt
--index-url https://example.test/simple
-e git+https://example.test/repo.git#egg=local
celery[redis]==5.3.1 ; python_version >= "3.8"
urllib3==1.26.5 \\
    --hash=sha256:aaaa
pkg @ https://example.test/pkg.whl
numpy==1.*
Pillow===10.0.0
"""


def test_requirements_file() -> None:
    found = RequirementsParser().parse_text(REQUIREMENTS, "requirements.txt")

    assert summary(found) == [
        ("Django", "2.2.0", 2),
        ("requests", None, 3),
        ("flask", None, 4),
        ("celery", "5.3.1", 8),
        ("urllib3", "1.26.5", 9),
        ("numpy", None, 12),
        ("Pillow", "10.0.0", 13),
    ]
    assert all(d.ecosystem is Ecosystem.PYPI for d in found)
    assert by_name(found)["Django"].source_line == "Django==2.2.0"
    assert by_name(found)["requests"].specifier == ">=2.0"
    assert by_name(found)["requests"].pinned is False


@pytest.mark.parametrize(
    "name, expected",
    [
        ("requirements.txt", True),
        ("requirements-dev.txt", True),
        ("requirements_prod.txt", True),
        ("Requirements.TXT", True),
        ("notes.txt", False),
        ("requirements.in", False),
    ],
)
def test_requirements_file_names(name: str, expected: bool) -> None:
    assert RequirementsParser().matches(name) is expected


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

PYPROJECT = """\
[project]
name = "shop"
dependencies = [
    "Django==2.2.0",
    "requests>=2.0",
]

[project.optional-dependencies]
dev = ["pytest==8.0.0"]

[dependency-groups]
lint = ["ruff", {include-group = "dev"}]

[tool.poetry.dependencies]
python = "^3.11"
flask = "2.0.1"
jinja2 = "^3.0"
gunicorn = {version = "==20.1.0", optional = true}
mylib = {git = "https://example.test/mylib.git"}

[tool.poetry.group.test.dependencies]
coverage = "*"
"""


def test_pyproject_file() -> None:
    found = PyprojectParser().parse_text(PYPROJECT, "pyproject.toml")

    assert summary(found) == [
        ("Django", "2.2.0", 4),
        ("requests", None, 5),
        ("pytest", "8.0.0", 9),
        ("ruff", None, 12),
        ("flask", "2.0.1", 16),
        ("jinja2", None, 17),
        ("gunicorn", "20.1.0", 18),
        ("coverage", None, 22),
    ]


def test_invalid_toml_is_reported() -> None:
    with pytest.raises(ManifestError):
        PyprojectParser().parse_text("[project\nname=", "pyproject.toml")


# ---------------------------------------------------------------------------
# Lock files
# ---------------------------------------------------------------------------

def test_pipfile_lock() -> None:
    text = json.dumps(
        {
            "_meta": {"hash": {"sha256": "x"}},
            "default": {
                "django": {"hashes": [], "version": "==2.2.0"},
                "local-lib": {"path": "./local"},
            },
            "develop": {"pytest": {"version": "==8.0.0"}},
        },
        indent=4,
    )

    found = PipfileLockParser().parse_text(text, "Pipfile.lock")

    assert [(d.name, d.version) for d in found] == [("django", "2.2.0"), ("pytest", "8.0.0")]
    assert by_name(found)["django"].source_line == '"django": {'
    assert all(d.pinned for d in found)


POETRY_LOCK = """\
[[package]]
name = "asgiref"
version = "3.7.2"

[[package]]
name = "django"
version = "2.2.0"

[package.dependencies]
name = "ignored"

[metadata]
lock-version = "2.0"
"""


def test_poetry_lock() -> None:
    found = PoetryLockParser().parse_text(POETRY_LOCK, "poetry.lock")

    assert summary(found) == [("asgiref", "3.7.2", 2), ("django", "2.2.0", 6)]


PACKAGE_JSON = """\
{
  "name": "shop",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "express": "^4.18.0",
    "left-pad": "*",
    "local": "file:../local",
    "forked": "someone/forked#main"
  },
  "devDependencies": {
    "jest": "~29.0.0",
    "typescript": "=5.4.2"
  }
}
"""


def test_package_json() -> None:
    found = PackageJsonParser().parse_text(PACKAGE_JSON, "package.json")

    assert summary(found) == [
        ("lodash", "4.17.15", 5),
        ("express", None, 6),
        ("left-pad", None, 7),
        ("jest", None, 12),
        ("typescript", "5.4.2", 13),
    ]
    assert all(d.ecosystem is Ecosystem.NPM for d in found)
    assert by_name(found)["express"].specifier == "^4.18.0"


def test_package_lock_v3() -> None:
    text = json.dumps(
        {
            "name": "shop",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "shop", "version": "1.0.0", "dependencies": {"lodash": "^4.17.15"}},
                "node_modules/lodash": {"version": "4.17.15", "resolved": "https://example.test/l.tgz"},
                "node_modules/@example/scoped-pkg": {"version": "2.0.0-beta.2"},
                "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                "node_modules/b/node_modules/lodash": {"version": "4.17.15"},
                "node_modules/linked": {"resolved": "packages/linked", "link": True},
                "packages/linked": {"version": "0.0.1"},
            },
        },
        indent=2,
    )

    found = PackageLockParser().parse_text(text, "package-lock.json")

    assert [(d.name, d.version) for d in found] == [
        ("lodash", "4.17.15"),
        ("@example/scoped-pkg", "2.0.0-beta.2"),
        ("lodash", "3.10.1"),
    ]
    assert found[0].source_line == '"node_modules/lodash": {'
    assert found[0].line == 12


def test_package_lock_v1() -> None:
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.15"},
                "outer": {
                    "version": "1.0.0",
                    "dependencies": {"inner": {"version": "0.5.0"}},
                },
                "from-git": {"version": "github:someone/from-git#abc"},
            },
        },
        indent=2,
    )

    found = PackageLockParser().parse_text(text, "package-lock.json")

    assert [(d.name, d.version) for d in found] == [
        ("lodash", "4.17.15"), ("outer", "1.0.0"), ("inner", "0.5.0"),
    ]


def test_invalid_json_is_reported() -> None:
    with pytest.raises(ManifestError):
        PackageJsonParser().parse_text("{not json", "package.json")


# ---------------------------------------------------------------------------
# Finding manifests
# ---------------------------------------------------------------------------

def touch(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def found_names(root: Path) -> List[str]:
    return sorted(
        Path(path).relative_to(root).as_posix() for path, _ in ManifestFinder.find(str(root))
    )


def test_lock_files_are_preferred_in_the_same_folder(tmp_path: Path) -> None:
    for name in (
        "package.json", "package-lock.json", "pyproject.toml", "poetry.lock",
        "requirements.txt", "requirements-dev.txt", "README.md",
    ):
        touch(tmp_path / name)

    assert found_names(tmp_path) == [
        "package-lock.json", "poetry.lock", "requirements-dev.txt", "requirements.txt",
    ]


def test_a_manifest_without_a_lock_file_is_read(tmp_path: Path) -> None:
    touch(tmp_path / "web" / "package.json")
    touch(tmp_path / "api" / "pyproject.toml")
    touch(tmp_path / "api" / "Pipfile.lock")
    touch(tmp_path / "other" / "package-lock.json")

    assert found_names(tmp_path) == [
        "api/Pipfile.lock", "api/pyproject.toml", "other/package-lock.json", "web/package.json",
    ]


def test_third_party_folders_are_not_searched(tmp_path: Path) -> None:
    touch(tmp_path / "package.json")
    touch(tmp_path / "node_modules" / "lodash" / "package.json")
    touch(tmp_path / "venv" / "lib" / "requirements.txt")

    assert found_names(tmp_path) == ["package.json"]


def test_a_single_manifest_file_can_be_the_target(tmp_path: Path) -> None:
    touch(tmp_path / "package.json")
    touch(tmp_path / "package-lock.json")
    touch(tmp_path / "app.py")

    assert [Path(p).name for p, _ in ManifestFinder.find(str(tmp_path / "package.json"))] == [
        "package.json"
    ]
    assert ManifestFinder.find(str(tmp_path / "app.py")) == []


def test_parse_reads_the_file(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("Django==2.2.0\n", encoding="utf-8")

    (dependency,) = RequirementsParser().parse(str(path))

    assert (dependency.name, dependency.version, dependency.file_path) == (
        "Django", "2.2.0", str(path),
    )
    with pytest.raises(ManifestError):
        RequirementsParser().parse(str(tmp_path / "missing.txt"))
