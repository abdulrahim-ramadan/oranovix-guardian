"""
Package ecosystems: how names are normalised and how versions compare.

PyPI versions follow PEP 440 and are compared with ``packaging``.
npm versions follow semver and are compared by the small ``SemVer`` class.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from typing import Any, Dict, Optional, Tuple

from packaging.version import InvalidVersion, Version


class Ecosystem(str, Enum):
    """Package registries, named as OSV names them."""

    PYPI = "PyPI"
    NPM = "npm"


class VersionScheme(ABC):
    """Name and version rules of one ecosystem."""

    @abstractmethod
    def parse(self, text: str) -> Optional[Any]:
        """Return a comparable version, or ``None`` when *text* is not a version."""

    @abstractmethod
    def normalize_name(self, name: str) -> str:
        """Return the form of *name* under which the registry treats names as equal."""


class PyPIVersionScheme(VersionScheme):
    _SEPARATORS = re.compile(r"[-_.]+")

    def parse(self, text: str) -> Optional[Version]:
        try:
            return Version(text.strip())
        except InvalidVersion:
            return None

    def normalize_name(self, name: str) -> str:
        # PEP 503
        return self._SEPARATORS.sub("-", name.strip()).lower()


@total_ordering
@dataclass(frozen=True, eq=False)
class SemVer:
    """A semver 2.0 version. Build metadata is ignored, as the spec requires."""

    major: int
    minor: int
    patch: int
    prerelease: Tuple[str, ...] = ()

    _PATTERN = re.compile(
        r"^[v=]*(\d+)(?:\.(\d+))?(?:\.(\d+))?"
        r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
    )

    @classmethod
    def parse(cls, text: str) -> Optional["SemVer"]:
        match = cls._PATTERN.match(text.strip())
        if not match:
            return None
        major, minor, patch, prerelease = match.groups()
        return cls(
            int(major), int(minor or 0), int(patch or 0),
            tuple(prerelease.split(".")) if prerelease else (),
        )

    def _key(self) -> Tuple[Any, ...]:
        # A release sorts after its pre-releases; numeric identifiers sort
        # before alphanumeric ones.
        if not self.prerelease:
            return (self.major, self.minor, self.patch, 1, ())
        identifiers = tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part)
            for part in self.prerelease
        )
        return (self.major, self.minor, self.patch, 0, identifiers)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other: "SemVer") -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


class NpmVersionScheme(VersionScheme):
    def parse(self, text: str) -> Optional[SemVer]:
        return SemVer.parse(text)

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()


_SCHEMES: Dict[Ecosystem, VersionScheme] = {
    Ecosystem.PYPI: PyPIVersionScheme(),
    Ecosystem.NPM: NpmVersionScheme(),
}


def scheme_for(ecosystem: Ecosystem) -> VersionScheme:
    return _SCHEMES[ecosystem]
