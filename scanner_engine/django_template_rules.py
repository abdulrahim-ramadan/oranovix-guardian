"""
Security rules for Django templates (``.html``).

Django escapes template variables by default.  These rules report the
two ways a template switches that protection off.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, List, Pattern

from .base import BaseScanner, Issue, Language, ScanResult, Severity
from .categories import category_for_rule
from .vulnerability_db import VulnerabilityDatabase

_CWE_XSS = "https://cwe.mitre.org/data/definitions/79.html"
_TEMPLATE_COMMENT = re.compile(r"\{#.*?#\}")


class DjangoTemplateRule(ABC):
    """One pattern that must not appear in a template line."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    recommendation: ClassVar[str]

    @property
    @abstractmethod
    def pattern(self) -> Pattern[str]:
        """Regex that matches the unsafe construct."""

    def check(self, line: str, line_number: int) -> List[Issue]:
        if not self.pattern.search(_TEMPLATE_COMMENT.sub("", line)):
            return []
        return [Issue(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            file_path="",
            line_number=line_number,
            code_snippet=line.strip(),
            recommendation=self.recommendation,
            cwe=_CWE_XSS,
            confidence="MEDIUM",
            category=category_for_rule(self.rule_id),
        )]


class SafeFilterRule(DjangoTemplateRule):
    rule_id = "DT001"
    title = "Template variable marked |safe"
    severity = Severity.MEDIUM
    description = (
        "The |safe filter prints the value without HTML escaping. If any part of it "
        "comes from a user, script in it runs in the visitor's browser."
    )
    recommendation = (
        "Remove |safe and let Django escape the value. For rich text, clean it on "
        "the server with an allowlist sanitizer before saving."
    )
    _PATTERN = re.compile(r"\{\{[^}]*\|\s*safe(?:seq)?\b[^}]*\}\}")

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class AutoescapeOffRule(DjangoTemplateRule):
    rule_id = "DT002"
    title = "Template auto-escaping switched off"
    severity = Severity.HIGH
    description = (
        "{% autoescape off %} disables HTML escaping for every variable in the "
        "block, so any user-controlled value inside it can inject script."
    )
    recommendation = "Remove the autoescape off block and escape values as usual."
    _PATTERN = re.compile(r"\{%-?\s*autoescape\s+off\s*-?%\}")

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class DjangoTemplateScanner(BaseScanner):
    """Applies the template rules to every ``.html`` file of the target."""

    SUPPORTED_EXTENSIONS: List[str] = [".html", ".htm", ".djhtml"]

    _RULES: List[DjangoTemplateRule] = [SafeFilterRule(), AutoescapeOffRule()]

    def __init__(self) -> None:
        super().__init__(name="Django Templates", supported_language=Language.HTML)

    def supports(self, file_path: str) -> bool:
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        files = self.collect_files(target, self.SUPPORTED_EXTENSIONS)
        result.files_scanned = len(files)
        for file_path in files:
            result.issues.extend(self.scan_file(file_path))
        return result

    def scan_file(self, file_path: str) -> List[Issue]:
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        issues: List[Issue] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule in self._RULES:
                for issue in rule.check(line, line_number):
                    issue.file_path = file_path
                    VulnerabilityDatabase.enrich_issue(issue, issue.rule_id.lower())
                    issues.append(issue)
        return issues
