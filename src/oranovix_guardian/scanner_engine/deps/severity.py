"""
Severity of an OSV record.

Order of preference: a CVSS v3 vector (base score computed here), then the
severity label many advisories carry, then MEDIUM.
"""
from __future__ import annotations

import math
from typing import Any, Dict, Iterable, Mapping, Optional

from ..base import Severity


class CvssV3:
    """Base score of a CVSS v3.0 / v3.1 vector string."""

    _WEIGHTS: Dict[str, Dict[str, float]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    _PRIVILEGES = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }

    @classmethod
    def base_score(cls, vector: str) -> Optional[float]:
        parts = vector.strip().split("/")
        if not parts or not parts[0].startswith("CVSS:3"):
            return None
        metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
        try:
            scope = metrics["S"]
            weights = {name: table[metrics[name]] for name, table in cls._WEIGHTS.items()}
            privileges = cls._PRIVILEGES[scope][metrics["PR"]]
        except KeyError:
            return None

        iss = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]
        total = impact + exploitability
        if scope == "C":
            total *= 1.08
        return cls._round_up(min(total, 10.0))

    @staticmethod
    def _round_up(value: float) -> float:
        # "Roundup" of the CVSS specification: smallest one-decimal number >= value.
        scaled = round(value * 100000)
        if scaled % 10000 == 0:
            return scaled / 100000.0
        return (math.floor(scaled / 10000) + 1) / 10.0


class OSVSeverity:
    """Maps the severity information of an OSV record to our ``Severity``."""

    DEFAULT = Severity.MEDIUM

    _LABELS = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    @classmethod
    def of(cls, record: Mapping[str, Any], affected: Optional[Mapping[str, Any]] = None) -> Severity:
        sources = [record, *([affected] if affected else [])]

        for source in sources:
            score = cls._best_cvss(source.get("severity") or [])
            if score is not None:
                return cls.from_score(score)

        for source in sources:
            for holder in ("database_specific", "ecosystem_specific"):
                label = str((source.get(holder) or {}).get("severity", "")).upper()
                if label in cls._LABELS:
                    return cls._LABELS[label]
        return cls.DEFAULT

    @staticmethod
    def from_score(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _best_cvss(entries: Iterable[Any]) -> Optional[float]:
        scores = [
            score
            for entry in entries
            if isinstance(entry, Mapping)
            for score in [CvssV3.base_score(str(entry.get("score", "")))]
            if score is not None
        ]
        return max(scores) if scores else None
