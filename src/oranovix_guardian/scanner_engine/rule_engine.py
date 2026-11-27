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
import os
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Pattern

from oranovix_guardian.core.app_paths import AppPaths, DataFile
from oranovix_guardian.core.storage_problems import StorageProblems

from .base import Issue, Language, Severity
from .categories import IssueCategory


# ---------------------------------------------------------------------------
# Pattern checks
# ---------------------------------------------------------------------------

_FLAGS = re.MULTILINE | re.IGNORECASE

# A group repeated with + * or {n,} whose body itself repeats or offers
# alternatives: (a+)+ , (\w*)* , (a|aa)*. Python's re has no time limit,
# and such a pattern can backtrack for longer than the age of the universe.
_UNBOUNDED_REPEAT = re.compile(r"(?:[+*]|\{\d*,\})")
# {n}, {n,} or {n,m} after a group; group 1 is n.
_COUNTED_REPEAT = re.compile(r"\{(\d+)(?:,\d*)?\}")

#: Time one line may take for one custom rule (the ``regex`` module stops it).
CUSTOM_RULE_TIMEOUT = 0.2

try:  # optional at import time; listed in requirements and bundled with the exe
    import regex as _regex_module
except ImportError:  # pragma: no cover - only without the dependency
    _regex_module = None


class RulePatternError(ValueError):
    """A custom rule's regular expression was refused; the text says why."""


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> Pattern[str]:
    """Each pattern is compiled once for the whole process."""
    return re.compile(pattern, _FLAGS)


@lru_cache(maxsize=1024)
def _compiled_custom(pattern: str) -> Any:
    """A user's pattern, compiled with ``regex`` so that a match can be stopped.

    Falls back to ``re`` (no time limit) only if ``regex`` is missing.
    """
    if _regex_module is None:
        return _compiled(pattern)
    return _regex_module.compile(pattern, _regex_module.MULTILINE | _regex_module.IGNORECASE)


def _has_nested_repeat(pattern: str) -> bool:
    """A repeated group that contains a repeat or an alternation."""
    stack: List[int] = []           # start index of each open group
    groups: List[tuple] = []        # (start, end) of closed groups
    escaped = in_class = False
    for index, char in enumerate(pattern):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            stack.append(index)
        elif char == ")" and stack:
            groups.append((stack.pop(), index))
    for start, end in groups:
        after = pattern[end + 1:end + 16]
        body = _strip_classes_and_escapes(pattern[start + 1:end])
        if body.startswith("?"):
            body = body[2:] if body[1:2] in (":", "=", "!", ">") else body
        if _UNBOUNDED_REPEAT.match(after):
            if _UNBOUNDED_REPEAT.search(body) or "|" in body:
                return True
            continue
        counted = _COUNTED_REPEAT.match(after)
        if counted and int(counted.group(1)) >= 2 and _UNBOUNDED_REPEAT.search(body):
            # (.*a){8}X: every copy of the group can take any share of the
            # line, so a failing match tries every way to split it.
            return True
    return False


def _strip_classes_and_escapes(text: str) -> str:
    """Remove ``[...]`` and escaped characters, which cannot nest a repeat."""
    out: List[str] = []
    escaped = in_class = False
    for char in text:
        if escaped:
            escaped = False
            out.append("x")
        elif char == "\\":
            escaped = True
        elif in_class:
            if char == "]":
                in_class = False
                out.append("x")
        elif char == "[":
            in_class = True
        else:
            out.append(char)
    return "".join(out)


def check_pattern(pattern: str) -> str:
    """Why *pattern* cannot be used as a custom rule; ``""`` when it can."""
    try:
        _compiled(pattern)
    except re.error as exc:
        return f"not a valid regular expression ({exc})"
    if _has_nested_repeat(pattern):
        return (
            "a repeated group contains another repeat or alternatives, e.g. (a+)+, (a|aa)* "
            "or (.*a){8}; such a pattern can take practically forever on some lines. Use a "
            "character class or a single repeat instead, e.g. [ab]+ or [^a]*a"
        )
    return ""


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
        # The shipped rules are read-only; the user's rules live in the data
        # folder. With an explicit *rules_dir* both are in that folder.
        self._custom_path: Path = (
            Path(rules_dir) / "custom_rules.json" if rules_dir else AppPaths.data_file(DataFile.CUSTOM_RULES)
        )
        self._rules: List[Rule] = []
        #: Custom rules refused at the last load or import, as "<id>: <reason>".
        self.last_rejected: List[str] = []
        #: One message per custom rule that was stopped for taking too long.
        self.warnings: List[str] = []
        self.incomplete_files: set[str] = set()
        self._slow_rules: Dict[str, str] = {}
        self.load_rules()

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_rules_dir(rules_dir: Optional[str]) -> Path:
        """Folder of ``default_rules.json``: *rules_dir*, or the bundled resources."""
        if rules_dir:
            return Path(rules_dir)
        return AppPaths.resource("rules")

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_rules(self) -> List[Rule]:
        """Load rules from default and custom JSON files.

        Returns:
            The combined list of Rule objects (also stored as self._rules).
        """
        self._rules = []
        self.last_rejected = []
        default_path = self._rules_dir / "default_rules.json"
        custom_path  = self._custom_path

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
        for item in data.get("rules", []) if isinstance(data, dict) else []:
            try:
                rule = Rule(
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
                )
            except (KeyError, TypeError):
                continue  # skip malformed entries
            # The user's rules are checked every time they are loaded: a file
            # saved by an older version, or edited by hand, was never checked.
            problem = "" if builtin else self._problem(rule)
            if problem:
                self.last_rejected.append(f"{rule.id}: {problem}")
                continue
            result.append(rule)

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
        problem = "" if rule.is_builtin else self._problem(rule)
        if problem:
            raise RulePatternError(f"{rule.id}: {problem}")
        self._rules = [r for r in self._rules if r.id != rule.id]
        self._rules.append(rule)
        self._save_custom()

    @staticmethod
    def _problem(rule: Rule) -> str:
        problem = check_pattern(str(rule.pattern))
        if not problem and rule.exclude_line_pattern:
            problem = check_pattern(str(rule.exclude_line_pattern))
            problem = f"exclusion pattern is {problem}" if problem else ""
        return problem

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
        custom = [r for r in self._rules if not r.is_builtin]
        data = {"rules": [r.to_dict() for r in custom]}
        custom_path = self._custom_path
        temp = custom_path.with_name(custom_path.name + ".tmp")
        try:
            custom_path.parent.mkdir(parents=True, exist_ok=True)
            temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(temp, custom_path)
        except OSError as exc:
            StorageProblems.report("custom rules", custom_path, exc)

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

    #: Characters of a line a rule looks at. Long lines (minified code,
    #: data) are cut so that no pattern works on megabytes at once.
    MAX_LINE_LENGTH = 1000

    def _apply_rule(self, rule: Rule, code: str, file_path: str) -> List[Issue]:
        """One Issue per match of *rule*, line by line, honouring its line exclusion.

        A custom rule runs with a time limit per line. When a line takes
        longer, the rule is stopped for the rest of this file and reported
        once in ``warnings``. Built-in rules are fixed and checked by tests.
        """
        compile_ = _compiled if rule.is_builtin else _compiled_custom
        try:
            compiled = compile_(rule.pattern)
            excluded = compile_(rule.exclude_line_pattern) if rule.exclude_line_pattern else None
        except Exception:               # re.error or regex.error
            return []

        issues: List[Issue] = []
        try:
            for line_num, line, _match in self._matches(rule, compiled, excluded, code):
                issues.append(Issue(
                    rule_id=rule.id,
                    title=rule.name,
                    description=rule.description,
                    severity=rule.severity_enum(),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip()[:300],
                    recommendation=rule.fix_suggestion,
                    confidence="MEDIUM",
                    category=rule.category_enum(),
                ))
        except TimeoutError:
            self._report_slow(rule, file_path)
        return issues

    @classmethod
    def _matches(cls, rule: Rule, compiled: Any, excluded: Any, code: str) -> Iterator[tuple]:
        limit = {} if rule.is_builtin or _regex_module is None else {"timeout": CUSTOM_RULE_TIMEOUT}
        for line_num, line in enumerate(code.splitlines(), start=1):
            text = line[: cls.MAX_LINE_LENGTH]
            if excluded and excluded.search(text, **limit):
                continue
            for match in compiled.finditer(text, **limit):
                yield line_num, line, match

    def _report_slow(self, rule: Rule, file_path: str) -> None:
        if file_path:
            self.incomplete_files.add(file_path)
        if rule.id in self._slow_rules:
            return
        where = Path(file_path).name if file_path else "a file"
        message = (
            f"Custom rule {rule.id} was stopped: too slow on a line of {where} "
            f"(over {CUSTOM_RULE_TIMEOUT:g} s); it was skipped for the rest of that file."
        )
        self._slow_rules[rule.id] = message
        self.warnings.append(message)

    def scan_file(self, file_path: str, language: Language, *, strict_read: bool = False) -> List[Issue]:
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
            if strict_read:
                raise
            return []
        return self.scan(code, language, file_path)

    def test_rule(self, rule: Rule, sample_code: str) -> List[Issue]:
        """Test a rule against sample code without persisting anything.

        Args:
            rule:        The Rule to test (may not yet be in self._rules).
            sample_code: Sample source code to match against.

        Returns:
            List of Issues the rule would generate on the sample.

        Raises:
            RulePatternError: the pattern is invalid or could hang a scan.
        """
        problem = self._problem(rule)
        if problem:
            raise RulePatternError(problem)
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
        Rules whose pattern is invalid or could hang a scan are refused and
        listed in ``last_rejected``.

        Args:
            path: Source JSON file to import from.

        Returns:
            Number of new rules successfully imported.
        """
        self.last_rejected = []
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
