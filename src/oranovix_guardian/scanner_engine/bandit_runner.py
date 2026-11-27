"""
Runs Bandit in-process through its library API.

Bandit is imported lazily so that a missing or broken installation
surfaces as ``BanditUnavailableError`` instead of an import crash.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


class BanditUnavailableError(RuntimeError):
    """Raised when Bandit cannot be imported or fails while running."""


@dataclass(frozen=True)
class BanditFinding:
    """One Bandit issue, detached from Bandit's own classes."""

    test_id: str
    test_name: str
    severity: str
    confidence: str
    line_number: int
    file_path: str
    text: str
    code: str = ""
    cwe_link: str = ""


@dataclass
class BanditReport:
    """Findings plus the files Bandit could not analyse."""

    findings: List[BanditFinding] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)


class BanditRunner:
    """Thin adapter around ``bandit.core.manager.BanditManager``."""

    def run(self, files: List[str]) -> BanditReport:
        """Analyse exactly *files* and return what Bandit found."""
        try:
            from bandit.core import config as b_config, manager as b_manager

            manager = b_manager.BanditManager(b_config.BanditConfig(), "file")
            manager.discover_files(list(files), recursive=False)
            manager.run_tests()
            issues = manager.get_issue_list()
        except Exception as exc:
            raise BanditUnavailableError(f"{type(exc).__name__}: {exc}") from exc

        if not manager.b_ts.tests:
            raise BanditUnavailableError("Bandit loaded without any security checks")

        return BanditReport(
            findings=[self._to_finding(issue) for issue in issues],
            skipped_files=[name for name, _reason in manager.skipped],
        )

    @staticmethod
    def _to_finding(issue) -> BanditFinding:
        cwe = getattr(issue, "cwe", None)
        return BanditFinding(
            test_id=issue.test_id,
            test_name=issue.test,
            severity=str(issue.severity).upper(),
            confidence=str(issue.confidence).upper(),
            line_number=issue.lineno,
            file_path=issue.fname,
            text=issue.text,
            code=BanditRunner._source_line(issue),
            cwe_link=cwe.link() if cwe else "",
        )

    @staticmethod
    def _source_line(issue) -> str:
        """Return the flagged line without Bandit's line-number prefix."""
        raw = issue.get_code(max_lines=1).strip()
        prefix = f"{issue.lineno} "
        return raw[len(prefix):].strip() if raw.startswith(prefix) else raw
