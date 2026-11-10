"""
Custom Rule Engine for Oranovix Guardian.

A JSON-driven security rule system that lets users define, manage, and test
custom detection rules without modifying any Python code.

Architecture:
  - RuleLanguage (str Enum) — language scope values (ALL + supported languages).
  - Rule (dataclass)       — data model for a single detection rule.
  - RuleEngine             — loads, manages, and executes rules.

Rules are loaded from two JSON files:
  - rules/default_rules.json  — built-in rules shipped with the application.
  - rules/custom_rules.json   — user-defined rules persisted between sessions.

Version: 1.0.0
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional

from .base import Issue, Language, Severity
from .categories import IssueCategory


# ---------------------------------------------------------------------------
# RuleLanguage enum
# ---------------------------------------------------------------------------

class RuleLanguage(str, Enum):
    """Language scope for a rule.

    ``ALL`` means the rule is applied to every language scanner.
    Other values map to specific language names used by Language.value.
    """
    ALL        = "ALL"
    PYTHON     = "Python"
    JAVASCRIPT = "JavaScript"
    PHP        = "PHP"
    JAVA       = "Java"
    CSHARP     = "C#"

    @classmethod
    def from_language(cls, lang: Language) -> "RuleLanguage":
        """Convert a scanner Language enum member to a RuleLanguage value."""
        _map = {
            Language.PYTHON:     cls.PYTHON,
            Language.JAVASCRIPT: cls.JAVASCRIPT,
            Language.PHP:        cls.PHP,
            Language.JAVA:       cls.JAVA,
            Language.CSHARP:     cls.CSHARP,
        }
        return _map.get(lang, cls.ALL)


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """A single security detection rule with regex pattern and metadata.

    Attributes:
        id:             Unique rule identifier (e.g. "CUST-001").
        name:           Short human-readable rule name.
        description:    Longer explanation of what the rule detects.
        pattern:        Python regex pattern applied to source code.
        severity:       Severity string: "LOW", "MEDIUM", "HIGH", "CRITICAL".
        language:       Language scope string (RuleLanguage value or "ALL").
        enabled:        Whether the rule is currently active.
        fix_suggestion: Optional remediation advice shown in the UI.
        is_builtin:     True for default rules; False for user-defined rules.
        category:       IssueCategory value used to merge duplicate findings.
        exclude_line_pattern: Regex; a match on a line containing it is ignored.
    """
    id: str
    name: str
    description: str
    pattern: str
    severity: str           # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    language: str           # RuleLanguage.value or "ALL"
    enabled: bool = True
    fix_suggestion: str = ""
    is_builtin: bool = False
    category: str = IssueCategory.OTHER.value
    exclude_line_pattern: str = ""

    def category_enum(self) -> IssueCategory:
        return IssueCategory.parse(self.category)

    def severity_enum(self) -> Severity:
        """Return the Severity enum member corresponding to this rule's severity."""
        try:
            return Severity[self.severity.upper()]
        except KeyError:
            return Severity.MEDIUM

    def to_dict(self) -> dict:
        """Serialize the rule to a plain dictionary for JSON persistence."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "severity": self.severity,
            "language": self.language,
            "enabled": self.enabled,
            "fix_suggestion": self.fix_suggestion,
            "is_builtin": self.is_builtin,
            "category": self.category,
            "exclude_line_pattern": self.exclude_line_pattern,
        }


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Loads, manages, and executes regex-based custom security rules.

    Combines built-in rules from ``rules/default_rules.json`` with
    user-defined rules from ``rules/custom_rules.json``.  Rules are applied
    to source code using ``re`` and produce Issue objects compatible with the
    rest of the scanner pipeline.

    Public API:
        load_rules()        — reload from JSON files.
        add_rule(rule)      — add a custom rule and persist.
        disable_rule(id)    — disable a rule by ID and persist.
        enable_rule(id)     — enable a rule by ID and persist.
        delete_rule(id)     — delete a custom rule by ID and persist.
        scan(code, lang)    — scan a code string with all applicable rules.
        scan_file(path, lang) — scan a file with all applicable rules.
        test_rule(rule, code) — test a rule against sample code.
        export_rules(path)  — export custom rules to JSON.
        import_rules(path)  — import rules from a JSON file.
    """

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self._rules_dir: Path = self._resolve_rules_dir(rules_dir)
        self._rules: List[Rule] = []
        self.load_rules()

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_rules_dir(rules_dir: Optional[str]) -> Path:
        """Resolve the rules directory for both dev and frozen-exe deployments."""
        import sys
        if rules_dir:
            return Path(rules_dir)
        if getattr(sys, "frozen", False):
            return Path(sys.executable).parent / "rules"
        return Path(__file__).parent.parent / "rules"

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_rules(self) -> List[Rule]:
        """Load rules from default and custom JSON files.

        Returns:
            The combined list of Rule objects (also stored as self._rules).
        """
        self._rules = []
        default_path = self._rules_dir / "default_rules.json"
        custom_path  = self._rules_dir / "custom_rules.json"

        if default_path.exists():
            self._rules.extend(self._load_file(default_path, builtin=True))

        if custom_path.exists():
            self._rules.extend(self._load_file(custom_path, builtin=False))

        return self._rules

    def _load_file(self, path: Path, builtin: bool) -> List[Rule]:
        """Parse a rules JSON file and return Rule instances."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        result: List[Rule] = []
        for item in data.get("rules", []):
            try:
                result.append(Rule(
                    id=item["id"],
                    name=item["name"],
                    description=item.get("description", ""),
                    pattern=item["pattern"],
                    severity=item.get("severity", "MEDIUM"),
                    language=item.get("language", "ALL"),
                    enabled=item.get("enabled", True),
                    fix_suggestion=item.get("fix_suggestion", ""),
                    is_builtin=builtin,
                    category=item.get("category", IssueCategory.OTHER.value),
                    exclude_line_pattern=item.get("exclude_line_pattern", ""),
                ))
            except KeyError:
                continue  # skip malformed entries

        return result

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    @property
    def rules(self) -> List[Rule]:
        """Return the list of all loaded rules (live reference)."""
        return self._rules

    def add_rule(self, rule: Rule) -> None:
        """Add a new custom rule, replacing any existing rule with the same ID.

        Persists the change to custom_rules.json immediately.

        Args:
            rule: The Rule to add.
        """
        self._rules = [r for r in self._rules if r.id != rule.id]
        self._rules.append(rule)
        self._save_custom()

    def disable_rule(self, rule_id: str) -> None:
        """Disable a rule by ID and persist the change.

        Args:
            rule_id: The ID of the rule to disable.
        """
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = False
                break
        self._save_custom()

    def enable_rule(self, rule_id: str) -> None:
        """Enable a rule by ID and persist the change.

        Args:
            rule_id: The ID of the rule to enable.
        """
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = True
                break
        self._save_custom()

    def delete_rule(self, rule_id: str) -> None:
        """Delete a non-builtin rule by ID and persist the change.

        Builtin rules cannot be deleted (only disabled).

        Args:
            rule_id: The ID of the custom rule to delete.
        """
        self._rules = [
            r for r in self._rules
            if not (r.id == rule_id and not r.is_builtin)
        ]
        self._save_custom()

    def _save_custom(self) -> None:
        """Write all non-builtin rules to custom_rules.json."""
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        custom = [r for r in self._rules if not r.is_builtin]
        data = {"rules": [r.to_dict() for r in custom]}
        custom_path = self._rules_dir / "custom_rules.json"
        try:
            custom_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(
        self, code: str, language: Language, file_path: str = ""
    ) -> List[Issue]:
        """Scan a source code string with all enabled, applicable rules.

        Args:
            code:      Source code to scan.
            language:  Programming language of the code.
            file_path: Path to the file (populates Issue.file_path).

        Returns:
            List of Issue objects for every pattern match.
        """
        rule_lang = RuleLanguage.from_language(language)
        issues: List[Issue] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.language not in ("ALL", rule_lang.value):
                continue
            issues.extend(self._apply_rule(rule, code, file_path))
        return issues

    @staticmethod
    def _apply_rule(rule: Rule, code: str, file_path: str) -> List[Issue]:
        """Return one Issue per match of *rule*, honouring its line exclusion."""
        flags = re.MULTILINE | re.IGNORECASE
        try:
            compiled = re.compile(rule.pattern, flags)
            excluded = (
                re.compile(rule.exclude_line_pattern, flags)
                if rule.exclude_line_pattern else None
            )
        except re.error:
            return []

        lines = code.splitlines()
        issues: List[Issue] = []
        for match in compiled.finditer(code):
            line_num = code[: match.start()].count("\n") + 1
            line = lines[line_num - 1] if line_num <= len(lines) else ""
            if excluded and excluded.search(line):
                continue
            issues.append(Issue(
                rule_id=rule.id,
                title=rule.name,
                description=rule.description,
                severity=rule.severity_enum(),
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                recommendation=rule.fix_suggestion,
                confidence="MEDIUM",
                category=rule.category_enum(),
            ))
        return issues

    def scan_file(self, file_path: str, language: Language) -> List[Issue]:
        """Scan a single file with all applicable rules.

        Args:
            file_path: Absolute path to the file to scan.
            language:  Programming language of the file.

        Returns:
            List of Issue objects; empty if the file cannot be read.
        """
        try:
            code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.scan(code, language, file_path)

    def test_rule(self, rule: Rule, sample_code: str) -> List[Issue]:
        """Test a rule against sample code without persisting anything.

        Args:
            rule:        The Rule to test (may not yet be in self._rules).
            sample_code: Sample source code to match against.

        Returns:
            List of Issues the rule would generate on the sample.
        """
        return self._apply_rule(rule, sample_code, "<test>")

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    def export_rules(self, path: str, include_builtin: bool = False) -> None:
        """Export rules to a JSON file.

        Args:
            path:           Destination file path.
            include_builtin: Include built-in default rules in the export.
        """
        rules = self._rules if include_builtin else [
            r for r in self._rules if not r.is_builtin
        ]
        data = {"rules": [r.to_dict() for r in rules]}
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def import_rules(self, path: str) -> int:
        """Import rules from a JSON file as custom rules.

        Skips rules whose ID already exists in the current rule set.

        Args:
            path: Source JSON file to import from.

        Returns:
            Number of new rules successfully imported.
        """
        imported = self._load_file(Path(path), builtin=False)
        existing_ids = {r.id for r in self._rules}
        count = 0
        for rule in imported:
            if rule.id not in existing_ids:
                self._rules.append(rule)
                existing_ids.add(rule.id)
                count += 1
        if count:
            self._save_custom()
        return count
