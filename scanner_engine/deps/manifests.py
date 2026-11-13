"""
Manifest parsers: which packages a project depends on, and in which version.

One parser class per file format. A lock file gives exact versions; a
plain manifest may only give a range, in which case the dependency is
reported as unpinned and no version is guessed.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from packaging.requirements import InvalidRequirement, Requirement

from ..base import EXCLUDED_DIRS
from .versions import Ecosystem, SemVer, scheme_for


class ManifestError(ValueError):
    """A manifest could not be read or is not valid JSON / TOML."""


@dataclass(frozen=True)
class Dependency:
    """One declared dependency and where it is declared."""

    name: str
    ecosystem: Ecosystem
    version: Optional[str]      # exact version; None when the entry is not pinned
    specifier: str              # the constraint as written, e.g. ">=2.0" or "^4.17.15"
    file_path: str
    line: int
    source_line: str

    @property
    def pinned(self) -> bool:
        return self.version is not None

    @property
    def normalized_name(self) -> str:
        return scheme_for(self.ecosystem).normalize_name(self.name)


class _Lines:
    """Finds the line on which a dependency is written."""

    def __init__(self, text: str) -> None:
        self._lines = text.splitlines()

    def find(self, pattern: str, start: int = 1) -> int:
        """1-based number of the first line from *start* matching *pattern*; 1 if none."""
        regex = re.compile(pattern)
        for number in range(max(start, 1), len(self._lines) + 1):
            if regex.search(self._lines[number - 1]):
                return number
        return self.find(pattern) if start > 1 else 1

    def text(self, number: int) -> str:
        if 1 <= number <= len(self._lines):
            return self._lines[number - 1].strip()
        return ""

    def key_index(self) -> Dict[str, int]:
        """First line of every ``"key": {`` in a JSON file."""
        index: Dict[str, int] = {}
        opener = re.compile(r'^\s*"((?:[^"\\]|\\.)+)"\s*:\s*\{')
        for number, line in enumerate(self._lines, 1):
            match = opener.match(line)
            if match:
                index.setdefault(match.group(1), number)
        return index


class ManifestParser(ABC):
    """Reads one manifest format."""

    ecosystem: ClassVar[Ecosystem]
    is_lock_file: ClassVar[bool] = False
    # Manifests in the same folder that this lock file makes redundant.
    supersedes: ClassVar[Tuple[str, ...]] = ()

    @abstractmethod
    def matches(self, file_name: str) -> bool:
        """Whether this parser reads a file with that name."""

    @abstractmethod
    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        """Return the dependencies declared in *text*."""

    def parse(self, file_path: str) -> List[Dependency]:
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ManifestError(f"{os.path.basename(file_path)} could not be read") from exc
        return self.parse_text(text, file_path)

    def _dependency(
        self, name: str, version: Optional[str], specifier: str,
        file_path: str, lines: _Lines, line: int,
    ) -> Dependency:
        return Dependency(
            name=name, ecosystem=self.ecosystem, version=version, specifier=specifier,
            file_path=file_path, line=line, source_line=lines.text(line),
        )

    @staticmethod
    def _load_json(text: str, file_path: str) -> Mapping[str, Any]:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ManifestError(f"{os.path.basename(file_path)} is not valid JSON") from exc
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _load_toml(text: str, file_path: str) -> Mapping[str, Any]:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ManifestError(f"{os.path.basename(file_path)} is not valid TOML") from exc


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

class _Pep508:
    """Turns a PEP 508 requirement string into (name, exact version, specifier)."""

    @staticmethod
    def read(text: str) -> Optional[Tuple[str, Optional[str], str]]:
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            return None
        if requirement.url:
            return None                     # installed from a URL, not from PyPI
        specifiers = list(requirement.specifier)
        exact = None
        if len(specifiers) == 1 and specifiers[0].operator in ("==", "==="):
            if "*" not in specifiers[0].version:
                exact = specifiers[0].version
        return requirement.name, exact, str(requirement.specifier)


class RequirementsParser(ManifestParser):
    """``requirements.txt``, ``requirements-dev.txt``, ``requirements_prod.txt``..."""

    ecosystem = Ecosystem.PYPI

    def matches(self, file_name: str) -> bool:
        return fnmatch.fnmatch(file_name.lower(), "requirements*.txt")

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        lines = _Lines(text)
        found: List[Dependency] = []
        for number, entry in self._entries(text):
            parsed = _Pep508.read(entry)
            if parsed:
                name, version, specifier = parsed
                found.append(self._dependency(name, version, specifier, file_path, lines, number))
        return found

    @staticmethod
    def _entries(text: str) -> Iterator[Tuple[int, str]]:
        """Yield (first line number, requirement) with comments, options and
        line continuations removed."""
        pending = ""
        start = 0
        for number, raw in enumerate(text.splitlines(), 1):
            line = re.sub(r"(^|\s)#.*$", "", raw).strip()
            if not pending:
                start = number
            if line.endswith("\\"):
                pending += line[:-1] + " "
                continue
            entry = (pending + line).strip()
            pending = ""
            if not entry or entry.startswith("-"):
                continue                    # -r, -c, -e, --index-url ...
            entry = re.split(r"\s--", entry, maxsplit=1)[0].strip()   # --hash=...
            yield start, entry


class PyprojectParser(ManifestParser):
    """``pyproject.toml``: PEP 621 / PEP 735 tables and Poetry tables."""

    ecosystem = Ecosystem.PYPI
    _PLAIN_VERSION = re.compile(r"^=?=?\s*(\d[\w.!+-]*)$")

    def matches(self, file_name: str) -> bool:
        return file_name.lower() == "pyproject.toml"

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        data = self._load_toml(text, file_path)
        lines = _Lines(text)
        found: List[Dependency] = []

        for requirement in self._pep508_strings(data):
            parsed = _Pep508.read(requirement)
            if parsed:
                name, version, specifier = parsed
                line = lines.find(r"[\"']\s*" + re.escape(requirement) + r"\s*[\"']")
                found.append(self._dependency(name, version, specifier, file_path, lines, line))

        for name, constraint in self._poetry_entries(data):
            match = self._PLAIN_VERSION.match(constraint)
            version = match.group(1) if match and "*" not in constraint else None
            line = lines.find(r"^\s*[\"']?" + re.escape(name) + r"[\"']?\s*=")
            found.append(self._dependency(name, version, constraint, file_path, lines, line))
        return found

    @staticmethod
    def _pep508_strings(data: Mapping[str, Any]) -> Iterator[str]:
        project = data.get("project") or {}
        groups: List[Any] = [project.get("dependencies") or []]
        groups += list((project.get("optional-dependencies") or {}).values())
        groups += list((data.get("dependency-groups") or {}).values())
        for group in groups:
            for item in group if isinstance(group, list) else []:
                if isinstance(item, str):
                    yield item

    @staticmethod
    def _poetry_entries(data: Mapping[str, Any]) -> Iterator[Tuple[str, str]]:
        poetry = (data.get("tool") or {}).get("poetry") or {}
        tables: List[Any] = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
        tables += [
            (group or {}).get("dependencies") for group in (poetry.get("group") or {}).values()
        ]
        for table in tables:
            for name, value in (table or {}).items():
                if name.lower() == "python":
                    continue
                constraint = value.get("version") if isinstance(value, dict) else value
                if isinstance(constraint, str):
                    yield name, constraint.strip()


class PipfileLockParser(ManifestParser):
    ecosystem = Ecosystem.PYPI
    is_lock_file = True

    def matches(self, file_name: str) -> bool:
        return file_name.lower() == "pipfile.lock"

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        data = self._load_json(text, file_path)
        lines = _Lines(text)
        index = lines.key_index()
        found: List[Dependency] = []
        for section in ("default", "develop"):
            for name, entry in (data.get(section) or {}).items():
                version = str((entry or {}).get("version", "")) if isinstance(entry, dict) else ""
                if not version.startswith("=="):
                    continue                # git / path dependency
                line = index.get(name, 1)
                found.append(self._dependency(
                    name, version.lstrip("="), version, file_path, lines, line
                ))
        return found


class PoetryLockParser(ManifestParser):
    ecosystem = Ecosystem.PYPI
    is_lock_file = True
    supersedes = ("pyproject.toml",)

    def matches(self, file_name: str) -> bool:
        return file_name.lower() == "poetry.lock"

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        data = self._load_toml(text, file_path)
        lines = _Lines(text)
        found: List[Dependency] = []
        line = 1
        for package in data.get("package") or []:
            name, version = package.get("name"), package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            line = lines.find(r"^\s*name\s*=\s*[\"']" + re.escape(name) + r"[\"']", line)
            found.append(self._dependency(name, version, f"=={version}", file_path, lines, line))
            line += 1
        return found


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

class PackageJsonParser(ManifestParser):
    ecosystem = Ecosystem.NPM
    _SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
    # Not from the registry: git, URL, local path, workspace or alias.
    _NOT_REGISTRY = re.compile(r"^(?:git|https?|file|link|workspace|npm|github|portal)[:+]|/")

    def matches(self, file_name: str) -> bool:
        return file_name.lower() == "package.json"

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        data = self._load_json(text, file_path)
        lines = _Lines(text)
        found: List[Dependency] = []
        for section in self._SECTIONS:
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            section_line = lines.find(r'^\s*"' + section + r'"\s*:')
            for name, constraint in entries.items():
                if not isinstance(constraint, str) or self._NOT_REGISTRY.search(constraint):
                    continue
                exact = SemVer.parse(constraint) is not None
                version = constraint.strip().lstrip("v=") if exact else None
                line = lines.find(r'^\s*"' + re.escape(name) + r'"\s*:', section_line)
                found.append(self._dependency(name, version, constraint, file_path, lines, line))
        return found


class PackageLockParser(ManifestParser):
    """``package-lock.json`` / ``npm-shrinkwrap.json``, lockfile versions 1 to 3."""

    ecosystem = Ecosystem.NPM
    is_lock_file = True
    supersedes = ("package.json",)
    _MODULES = "node_modules/"

    def matches(self, file_name: str) -> bool:
        return file_name.lower() in ("package-lock.json", "npm-shrinkwrap.json")

    def parse_text(self, text: str, file_path: str) -> List[Dependency]:
        data = self._load_json(text, file_path)
        lines = _Lines(text)
        index = lines.key_index()
        packages = data.get("packages")
        if isinstance(packages, dict):
            entries = self._from_packages(packages)
        else:
            entries = self._from_dependencies(data.get("dependencies") or {})

        found: List[Dependency] = []
        seen: set[Tuple[str, str]] = set()
        for key, name, version in entries:
            if (name, version) in seen:
                continue
            seen.add((name, version))
            found.append(self._dependency(
                name, version, version, file_path, lines, index.get(key, 1)
            ))
        return found

    def _from_packages(self, packages: Mapping[str, Any]) -> Iterator[Tuple[str, str, str]]:
        for key, entry in packages.items():
            if self._MODULES not in key or not isinstance(entry, dict) or entry.get("link"):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                yield key, key.rsplit(self._MODULES, 1)[1], version

    def _from_dependencies(self, tree: Mapping[str, Any]) -> Iterator[Tuple[str, str, str]]:
        for name, entry in tree.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and SemVer.parse(version):
                yield name, name, version
            yield from self._from_dependencies(entry.get("dependencies") or {})


# ---------------------------------------------------------------------------
# Finding manifests in a project
# ---------------------------------------------------------------------------

class ManifestFinder:
    """Locates manifests under a target and picks the parser for each."""

    PARSERS: ClassVar[Sequence[ManifestParser]] = (
        RequirementsParser(),
        PyprojectParser(),
        PipfileLockParser(),
        PoetryLockParser(),
        PackageJsonParser(),
        PackageLockParser(),
    )

    @classmethod
    def parser_for(cls, file_name: str) -> Optional[ManifestParser]:
        return next((p for p in cls.PARSERS if p.matches(file_name)), None)

    @classmethod
    def is_manifest(cls, file_name: str) -> bool:
        return cls.parser_for(file_name) is not None

    @classmethod
    def find(cls, target: str) -> List[Tuple[str, ManifestParser]]:
        """Every manifest worth reading under *target*, lock files preferred.

        A manifest is left out when a lock file in the same folder
        supersedes it (``package.json`` beside ``package-lock.json``).
        """
        selected: List[Tuple[str, ManifestParser]] = []
        for folder, names in cls._folders(target):
            parsers = [(name, cls.parser_for(name)) for name in sorted(names)]
            present = [(name, parser) for name, parser in parsers if parser is not None]
            superseded = {
                name.lower() for _, parser in present for name in parser.supersedes
            }
            for name, parser in present:
                if name.lower() not in superseded:
                    selected.append((os.path.join(folder, name), parser))
        return selected

    @staticmethod
    def _folders(target: str) -> Iterable[Tuple[str, List[str]]]:
        path = Path(target)
        if path.is_file():
            # A single file is read as it is, even beside a lock file.
            return [(str(path.parent), [path.name])]
        folders = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRS]
            folders.append((root, files))
        return folders
