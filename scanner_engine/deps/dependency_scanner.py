"""
Dependency scanner: known vulnerabilities in the packages a project uses.

Reads the manifests of the target, looks every pinned package up in the
local OSV database and reports one finding per package and vulnerability.
No network access: when the database is missing the scan says so and
carries on.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..base import BaseScanner, DependencyInfo, Issue, Language, ScanResult, Severity
from ..categories import IssueCategory
from .manifests import Dependency, ManifestError, ManifestFinder
from .matcher import VersionMatcher, VulnerabilityMatch
from .osv_db import OSVDatabase
from .versions import scheme_for


class DependencyScanner(BaseScanner):
    """Reports vulnerable (DEP001) and unpinned (DEP002) dependencies."""

    RULE_VULNERABLE = "DEP001"
    RULE_UNPINNED = "DEP002"
    OWASP = "A06:2021 - Vulnerable and Outdated Components"

    def __init__(self, database: Optional[OSVDatabase] = None) -> None:
        super().__init__(name="Dependency Scanner", supported_language=Language.CONFIG)
        self._database = database or OSVDatabase()

    def supports(self, file_path: str) -> bool:
        return ManifestFinder.is_manifest(Path(file_path).name)

    @staticmethod
    def manifest_files(target: str) -> List[str]:
        return [path for path, _ in ManifestFinder.find(target)]

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        manifests = ManifestFinder.find(target)
        result.files_scanned = len(manifests)
        if not manifests:
            return result

        warning = self._database.status_warning()
        if warning:
            result.engine_warnings.append(warning)
        database_ready = self._database.exists()

        for file_path, parser in manifests:
            try:
                dependencies = parser.parse(file_path)
            except ManifestError as exc:
                result.engine_warnings.append(f"Dependency scan: {exc}.")
                continue
            for dependency in dependencies:
                if not dependency.pinned:
                    result.issues.append(self._unpinned_issue(dependency))
                elif database_ready:
                    result.issues.extend(self._vulnerability_issues(dependency))
        return result

    # ------------------------------------------------------------------
    # DEP001
    # ------------------------------------------------------------------

    def _vulnerability_issues(self, dependency: Dependency) -> List[Issue]:
        version = dependency.version or ""
        matcher = VersionMatcher(dependency.ecosystem)
        matches = [
            match
            for vulnerability in self._database.vulnerabilities_for(
                dependency.ecosystem, dependency.name
            )
            for match in [matcher.match(version, vulnerability)]
            if match is not None
        ]
        return [self._vulnerability_issue(dependency, group) for group in self._group(matches)]

    @staticmethod
    def _group(matches: Sequence[VulnerabilityMatch]) -> List[List[VulnerabilityMatch]]:
        """Put advisories that describe the same vulnerability together.

        OSV often holds two records for one CVE (a GHSA and a PYSEC entry);
        records that share any id are one finding.
        """
        groups: List[Tuple[set, List[VulnerabilityMatch]]] = []
        for match in matches:
            ids = set(match.vulnerability.all_ids)
            related = [group for group in groups if group[0] & ids]
            members = [match]
            for group in related:
                ids |= group[0]
                members = group[1] + members
                groups.remove(group)
            groups.append((ids, members))
        return [members for _, members in groups]

    def _vulnerability_issue(
        self, dependency: Dependency, group: Sequence[VulnerabilityMatch]
    ) -> Issue:
        version = dependency.version or ""
        ids = self._ordered_ids(group)
        primary_id = ids[0]
        summary = next((m.vulnerability.summary for m in group if m.vulnerability.summary), "")
        severity = max((m.vulnerability.severity for m in group), key=lambda s: s.weight)
        fixed = self._lowest(dependency, [m.fixed_version for m in group if m.fixed_version])
        last = self._lowest(dependency, [m.last_affected for m in group if m.last_affected])

        title = f"{dependency.name} {version}: {primary_id}"
        short = self._short_summary(summary, dependency.name)
        if short:
            title += f" ({short})"

        if fixed:
            fix = f"Upgrade to {fixed} or later."
        elif last:
            fix = f"No fixed version is listed. Upgrade to a version later than {last}."
        else:
            fix = "No fixed version is known yet. Replace the package or follow the advisory."

        description = (
            f"{dependency.name} {version} ({dependency.ecosystem.value}) has a known "
            f"vulnerability: {', '.join(ids)}."
        )
        if summary:
            description += f" {summary.rstrip('.')}."

        return Issue(
            rule_id=self.RULE_VULNERABLE,
            title=title,
            description=description,
            severity=severity,
            file_path=dependency.file_path,
            line_number=dependency.line,
            code_snippet=dependency.source_line,
            recommendation=fix,
            confidence="HIGH",
            category=IssueCategory.DEPENDENCY,
            finding_key=f"{dependency.normalized_name}@{version}|{primary_id}",
            dependency=DependencyInfo(
                package=dependency.name,
                version=version,
                ecosystem=dependency.ecosystem.value,
                vulnerability_ids=tuple(ids),
                fixed_version=fixed,
            ),
            what_is_it=(
                "A publicly known vulnerability in a third-party package this "
                "project depends on."
            ),
            why_dangerous=(
                "The weakness is documented in public advisories, so attackers "
                "know which versions to look for and how to attack them."
            ),
            how_exploited=(
                "An attacker identifies the package version and uses the "
                "technique published with the advisory against the application."
            ),
            fix_suggestion=fix,
            owasp_category=self.OWASP,
        )

    @staticmethod
    def _ordered_ids(group: Sequence[VulnerabilityMatch]) -> List[str]:
        """Every id of the group once, CVE ids first, then GHSA, then the rest."""
        seen: Dict[str, None] = {}
        for match in group:
            for vuln_id in match.vulnerability.all_ids:
                seen.setdefault(vuln_id, None)

        def rank(vuln_id: str) -> Tuple[int, str]:
            upper = vuln_id.upper()
            return (0 if upper.startswith("CVE-") else 1 if upper.startswith("GHSA-") else 2, upper)

        return sorted(seen, key=rank)

    @staticmethod
    def _lowest(dependency: Dependency, versions: Sequence[str]) -> str:
        scheme = scheme_for(dependency.ecosystem)
        parsed: List[Tuple[Any, str]] = [
            (value, text) for text in versions for value in [scheme.parse(text)] if value is not None
        ]
        return min(parsed)[1] if parsed else ""

    @staticmethod
    def _short_summary(summary: str, package: str) -> str:
        """"SQL injection in Django" -> "SQL injection"; long texts are cut."""
        text = re.sub(
            rf"\s+(?:in|for|of)\s+{re.escape(package)}\.?$", "", summary.strip(), flags=re.IGNORECASE
        ).rstrip(".")
        return text if len(text) <= 70 else text[:67].rstrip() + "..."

    # ------------------------------------------------------------------
    # DEP002
    # ------------------------------------------------------------------

    def _unpinned_issue(self, dependency: Dependency) -> Issue:
        constraint = dependency.specifier or "no version"
        return Issue(
            rule_id=self.RULE_UNPINNED,
            title=f"Unpinned dependency: {dependency.name} ({constraint})",
            description=(
                f"{dependency.name} is declared without an exact version "
                f"({constraint}). The version that gets installed is not known, so "
                "it was not checked against the vulnerability database."
            ),
            severity=Severity.LOW,
            file_path=dependency.file_path,
            line_number=dependency.line,
            code_snippet=dependency.source_line,
            recommendation=(
                "Pin an exact version or commit a lock file, so the installed "
                "version is known and can be checked."
            ),
            confidence="HIGH",
            category=IssueCategory.DEPENDENCY,
            finding_key=f"{dependency.normalized_name}|unpinned",
            dependency=DependencyInfo(
                package=dependency.name,
                version="",
                ecosystem=dependency.ecosystem.value,
            ),
            owasp_category=self.OWASP,
        )
