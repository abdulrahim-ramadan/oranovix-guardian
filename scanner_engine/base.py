"""
Base classes and shared data models for the Oranovix Guardian scanner engine.

This module forms the foundation of the scanner engine.  It defines the
enumeration types (``Severity``, ``ScanStatus``, ``Language``) used throughout
the project, the ``Issue`` and ``ScanResult`` data-transfer objects that every
scanner produces, and the abstract ``BaseScanner`` class that all language-
specific scanners must extend.  The design follows the Template Method pattern:
``BaseScanner.scan`` handles lifecycle management (status transitions, timing,
error capture) and delegates the language-specific work to the abstract
``_do_scan`` method implemented by each subclass.

Version: 1.1.0
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .categories import IssueCategory


# Third-party and generated folders that no engine should scan.
EXCLUDED_DIRS: frozenset[str] = frozenset({
    "venv", ".venv", "env", "node_modules", "__pycache__", ".git",
    "dist", "build", "site-packages", "migrations",
})


class FileMatcher:
    """Decides whether a file name belongs to a scan.

    A name matches when:
      - its suffix is a wanted extension (``app.py`` for ``.py``), or
      - the whole name is a wanted extension, optionally followed by more
        dotted parts (``.env``, ``.env.local``, ``.env.production``), or
      - it equals a wanted file name, optionally followed by dotted parts
        (``Dockerfile``, ``Dockerfile.dev``, ``docker-compose.override``).

    ``Path(".env").suffix`` is empty, which is why the suffix alone is not
    enough for dotfiles.
    """

    def __init__(self, extensions: Iterable[str], file_names: Iterable[str] = ()) -> None:
        self._extensions = frozenset(ext.lower() for ext in extensions)
        self._name_stems = tuple(
            stem.lower() for stem in (*self._extensions, *file_names)
        )

    def matches(self, file_name: str) -> bool:
        name = file_name.lower()
        if Path(name).suffix in self._extensions:
            return True
        return any(
            name == stem or name.startswith(stem + ".") for stem in self._name_stems
        )


# Files that hold settings or dependency lists rather than program code.
_CONFIG_FILES = FileMatcher(
    [
        ".env", ".cfg", ".conf", ".config", ".ini", ".yaml", ".yml", ".json",
        ".xml", ".toml", ".properties", ".lock", ".txt", ".tf", ".hcl",
        ".gradle", ".pom",
    ],
    [
        "Dockerfile", "docker-compose", "compose", ".htpasswd", ".npmrc",
        ".pypirc", "Pipfile",
    ],
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Severity levels for security issues, ordered LOW to CRITICAL.

    Each member carries two auxiliary properties: a ``color`` for UI rendering
    and a numeric ``weight`` for sorting and composite risk calculations.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def color(self) -> str:
        """Return a hex color string associated with the severity level.

        Returns:
            A CSS-compatible hex color code (e.g. ``"#4CAF50"`` for LOW).
        """
        return {
            Severity.LOW: "#4CAF50",       # green  – informational
            Severity.MEDIUM: "#FF9800",    # orange – moderate risk
            Severity.HIGH: "#F44336",      # red    – serious risk
            Severity.CRITICAL: "#9C27B0",  # purple – immediate action required
        }[self]

    @property
    def weight(self) -> int:
        """Return a numeric weight used for sorting and risk scoring.

        Returns:
            An integer in the range 1–4, where 1 is LOW and 4 is CRITICAL.
        """
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class ScanStatus(Enum):
    """Lifecycle states of a scan operation.

    A scan begins as ``PENDING``, transitions to ``RUNNING`` once
    ``BaseScanner.scan`` is entered, and finally lands on ``COMPLETED``,
    ``FAILED``, or ``CANCELLED`` depending on the outcome.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Language(Enum):
    """Supported programming languages recognised by the scanner engine.

    The ``UNKNOWN`` member is used as a fallback when a file extension does
    not map to any supported language, allowing callers to handle unsupported
    files gracefully without raising an exception.
    """

    PYTHON     = "Python"
    JAVASCRIPT = "JavaScript"
    PHP        = "PHP"
    JAVA       = "Java"
    CSHARP     = "C#"
    HTML       = "HTML"
    CONFIG     = "Config"
    UNKNOWN    = "Unknown"

    @classmethod
    def from_path(cls, file_path: str) -> "Language":
        """Language of a file: by extension, and ``CONFIG`` for settings,
        manifest and lock files (``.env``, ``Dockerfile``, ``.npmrc``...)."""
        path = Path(file_path)
        language = cls.from_extension(path.suffix)
        if language is cls.UNKNOWN and _CONFIG_FILES.matches(path.name):
            return cls.CONFIG
        return language

    @classmethod
    def from_extension(cls, ext: str) -> "Language":
        """Return the ``Language`` enum member that corresponds to a file extension.

        The lookup is case-insensitive; ``".TS"`` is treated the same as
        ``".ts"``.  TypeScript files (``.ts``) are mapped to ``JAVASCRIPT``
        because the same scanner handles both.

        Args:
            ext: A file extension string including the leading dot (e.g. ``".py"``).

        Returns:
            The matching ``Language`` member, or ``Language.UNKNOWN`` if the
            extension is not recognised.
        """
        # Map every supported extension to its corresponding Language member.
        # TypeScript shares the JavaScript scanner, so both map to JAVASCRIPT.
        mapping = {
            ".py":   cls.PYTHON,
            ".js":   cls.JAVASCRIPT,
            ".ts":   cls.JAVASCRIPT,
            ".jsx":  cls.JAVASCRIPT,
            ".tsx":  cls.JAVASCRIPT,
            ".mjs":  cls.JAVASCRIPT,
            ".php":  cls.PHP,
            ".java": cls.JAVA,
            ".cs":   cls.CSHARP,
            ".html": cls.HTML,
            ".htm":  cls.HTML,
            ".djhtml": cls.HTML,
        }
        return mapping.get(ext.lower(), cls.UNKNOWN)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DependencyInfo:
    """What a dependency finding is about; used by the report and the filter."""

    package: str
    version: str                        # "" for an unpinned dependency
    ecosystem: str                      # "PyPI" or "npm"
    vulnerability_ids: Tuple[str, ...] = ()  # CVE first, then the other ids
    fixed_version: str = ""             # lowest fixed version above the installed one

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerability_ids": list(self.vulnerability_ids),
            "fixed_version": self.fixed_version,
        }


@dataclass
class Issue:
    """A single security issue found in a source file.

    ``Issue`` is the central data-transfer object passed between the scanner
    engine, the vulnerability database, and the reporting layer.  Core fields
    (``rule_id`` through ``confidence``) are populated by the scanner itself;
    the education fields (``what_is_it`` through ``owasp_category``) are filled
    in by ``VulnerabilityDatabase.enrich_issue`` after the scan.
    """

    # ---- Core fields (set by the scanner) --------------------------------
    rule_id: str           # Unique identifier for the detection rule (e.g. "B102", "JS001")
    title: str             # Short human-readable title of the issue
    description: str       # Longer description with contextual details
    severity: Severity     # Severity classification (LOW / MEDIUM / HIGH / CRITICAL)
    file_path: str         # Absolute path to the file containing the issue
    line_number: int       # 1-based line number where the issue was detected
    code_snippet: str = "" # Relevant source code extract (may be empty)
    recommendation: str = "" # Concise remediation advice for developers
    cwe: str = ""          # CWE reference URL or identifier (e.g. CWE-79)
    confidence: str = "MEDIUM"  # Scanner confidence level: LOW / MEDIUM / HIGH
    category: IssueCategory = IssueCategory.OTHER  # Weakness class, used to merge duplicates
    also_detected_by: List[str] = field(default_factory=list)  # Rule IDs merged into this issue
    # Tells apart findings that share file, line and category (several
    # vulnerabilities of one package). Empty for ordinary findings.
    finding_key: str = ""
    dependency: Optional[DependencyInfo] = None  # Set only by the dependency scanner

    # ---- Vulnerability education fields (populated by VulnerabilityDatabase)
    what_is_it: str = ""      # Plain-English explanation of the vulnerability class
    why_dangerous: str = ""   # Business / security impact narrative
    how_exploited: str = ""   # Attack scenario description
    fix_suggestion: str = ""  # Step-by-step remediation guidance
    owasp_category: str = ""  # Relevant OWASP Top 10 category (e.g. "A03:2021")

    # ---- Derived helpers -------------------------------------------------

    @property
    def filename(self) -> str:
        """Return only the file name portion of ``file_path`` (no directory).

        Returns:
            The basename of the file where the issue was found.
        """
        return os.path.basename(self.file_path)

    @property
    def language(self) -> "Language":
        """Language of the file; ``CONFIG`` for settings and manifest files."""
        return Language.from_path(self.file_path)

    @property
    def severity_label(self) -> str:
        """Return the string value of the severity enum (e.g. ``"HIGH"``).

        Returns:
            A plain string representation of the issue's severity level.
        """
        return self.severity.value

    @property
    def needs_review(self) -> bool:
        """Low-confidence finding: shown with a badge, never announced by sound."""
        return str(self.confidence).upper() == "LOW"

    @property
    def rule_ids_label(self) -> str:
        """Primary rule ID followed by the rules merged into this issue."""
        if not self.also_detected_by:
            return self.rule_id
        return f"{self.rule_id} (+{', '.join(self.also_detected_by)})"

    def to_dict(self) -> dict:
        """Serialise the issue to a plain dictionary suitable for JSON export.

        All enum values are converted to their string representations so the
        result can be passed directly to ``json.dumps``.

        Returns:
            A dictionary containing every field of the issue.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,   # serialize enum to plain string
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "category": self.category.value,
            "also_detected_by": list(self.also_detected_by),
            "finding_key": self.finding_key,
            "dependency": self.dependency.to_dict() if self.dependency else None,
            "what_is_it": self.what_is_it,
            "why_dangerous": self.why_dangerous,
            "how_exploited": self.how_exploited,
            "fix_suggestion": self.fix_suggestion,
            "owasp_category": self.owasp_category,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete scan run.

    ``ScanResult`` is the top-level object returned by ``BaseScanner.scan``.
    It records metadata about the run (target path, scan ID, timing, status)
    and accumulates the list of ``Issue`` objects discovered.  A suite of
    computed properties provides convenient aggregations such as per-severity
    counts, a composite risk score, and a human-readable risk label.
    """

    target_path: str        # File or directory that was scanned
    scan_id: str            # UUID string uniquely identifying this scan run
    started_at: datetime = field(default_factory=datetime.now)  # Wall-clock start time
    finished_at: Optional[datetime] = None   # Set by BaseScanner.scan when done
    issues: List[Issue] = field(default_factory=list)  # All issues found in this scan
    status: ScanStatus = ScanStatus.PENDING  # Current lifecycle state of the scan
    files_scanned: int = 0   # Number of files examined (set by _do_scan implementations)
    scanner_name: str = "Unknown"  # Human-readable name of the scanner that ran
    error_message: str = ""  # Non-empty only when status == FAILED
    engine_warnings: List[str] = field(default_factory=list)  # Engines that could not run fully

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    @property
    def total_issues(self) -> int:
        """Return the total number of issues found across all severities.

        Returns:
            Count of all ``Issue`` objects in the ``issues`` list.
        """
        return len(self.issues)

    @property
    def critical_count(self) -> int:
        """Return the number of CRITICAL severity issues.

        Returns:
            Integer count of issues with ``Severity.CRITICAL``.
        """
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return the number of HIGH severity issues.

        Returns:
            Integer count of issues with ``Severity.HIGH``.
        """
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Return the number of MEDIUM severity issues.

        Returns:
            Integer count of issues with ``Severity.MEDIUM``.
        """
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return the number of LOW severity issues.

        Returns:
            Integer count of issues with ``Severity.LOW``.
        """
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def risk_score(self) -> int:
        """Risk score 0-100 that approaches 100 without saturating early.

        ``weighted = 40*C + 20*H + 5*M + 1*L`` and every 40 weighted points
        halve the remaining distance to 100, so 3 criticals (88) still
        score lower than 10 criticals (100).
        """
        weighted = (
            self.critical_count * 40
            + self.high_count * 20
            + self.medium_count * 5
            + self.low_count * 1
        )
        return round(100 * (1 - 0.5 ** (weighted / 40)))

    @property
    def severity_counts_label(self) -> str:
        """Raw counts shown next to the score, e.g. ``C:3 H:1 M:0 L:2``."""
        return (
            f"C:{self.critical_count} H:{self.high_count} "
            f"M:{self.medium_count} L:{self.low_count}"
        )

    @property
    def risk_label(self) -> str:
        """Return a human-readable risk label derived from ``risk_score``.

        The label thresholds are: 0 → "Safe", 1–20 → "Low Risk",
        21–50 → "Medium Risk", 51–80 → "High Risk", 81–100 → "Critical Risk".

        Returns:
            A plain-English label string describing the overall risk level.
        """
        s = self.risk_score
        if s == 0:
            return "Safe"
        if s <= 20:
            return "Low Risk"
        if s <= 50:
            return "Medium Risk"
        if s <= 80:
            return "High Risk"
        return "Critical Risk"

    @property
    def duration_seconds(self) -> float:
        """Return the elapsed scan time in seconds.

        Returns:
            A float representing the wall-clock duration between ``started_at``
            and ``finished_at``.  Returns ``0.0`` if the scan has not finished
            yet or timing data is unavailable.
        """
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0

    def issues_by_severity(self, severity: Severity) -> List[Issue]:
        """Filter issues to those matching a specific severity level.

        Args:
            severity: The ``Severity`` enum member to filter by.

        Returns:
            A list of ``Issue`` objects whose ``severity`` matches the argument.
        """
        return [i for i in self.issues if i.severity == severity]

    def issues_by_file(self) -> dict:
        """Group issues by the file in which they were found.

        Returns:
            A dictionary mapping each ``file_path`` string to a list of
            ``Issue`` objects found in that file.  Files with no issues are
            not present as keys.
        """
        grouped: dict = {}
        for issue in self.issues:
            # Use setdefault to initialise the list on first encounter
            grouped.setdefault(issue.file_path, []).append(issue)
        return grouped


# ---------------------------------------------------------------------------
# Abstract base scanner
# ---------------------------------------------------------------------------

class BaseScanner(ABC):
    """Abstract base class that every language-specific scanner must extend.

    ``BaseScanner`` enforces a consistent scanning contract across all scanner
    implementations via the Template Method pattern.  The public ``scan``
    method handles the full lifecycle of a scan (status transitions, UUID
    assignment, timing, and error capture), while the abstract ``_do_scan``
    method is the extension point where each subclass implements its
    language-specific detection logic.

    Subclasses must also implement ``supports``, which lets the factory layer
    determine at runtime whether a given scanner can handle a particular file.

    Key responsibilities:
        - Provide a stable public API (``scan``) for all callers.
        - Guarantee that ``ScanResult.status`` and ``ScanResult.finished_at``
          are always set correctly, even if ``_do_scan`` raises an exception.
        - Supply the ``collect_files`` utility so subclasses can enumerate
          target files without duplicating directory-walking logic.
    """

    def __init__(self, name: str, supported_language: Language) -> None:
        """Initialise the scanner with a display name and the language it handles.

        Args:
            name: A human-readable label for the scanner (e.g. ``"Python (Bandit)"``).
            supported_language: The ``Language`` enum member this scanner targets.
        """
        self._name = name
        self._language = supported_language

    @property
    def name(self) -> str:
        """Return the human-readable display name of the scanner.

        Returns:
            The name string supplied at construction time.
        """
        return self._name

    @property
    def language(self) -> Language:
        """Return the programming language handled by this scanner.

        Returns:
            The ``Language`` enum member supplied at construction time.
        """
        return self._language

    # ------------------------------------------------------------------
    # Template method – subclasses override _do_scan
    # ------------------------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        """Run the scanner against *target* and return a complete ``ScanResult``.

        This is the public entry point for all scan operations.  It manages
        the full lifecycle of the scan:

        1. Creates a ``ScanResult`` in ``RUNNING`` state with a fresh UUID.
        2. Delegates the actual work to ``_do_scan`` (implemented by subclasses).
        3. Marks the result ``COMPLETED`` on success or ``FAILED`` on exception.
        4. Always records ``finished_at`` in the ``finally`` block.

        Args:
            target: Absolute path to the file or directory to scan.

        Returns:
            A ``ScanResult`` whose ``status`` is either ``COMPLETED`` or
            ``FAILED``.  In the failure case, ``error_message`` contains the
            exception text.
        """
        import uuid  # imported here to keep top-level imports lean
        result = ScanResult(
            target_path=target,
            scan_id=str(uuid.uuid4()),   # unique identifier for this run
            scanner_name=self._name,
            status=ScanStatus.RUNNING,
        )
        try:
            result = self._do_scan(target, result)
            result.status = ScanStatus.COMPLETED
        except Exception as exc:
            # Capture the error details without propagating – callers check status
            result.status = ScanStatus.FAILED
            result.error_message = str(exc)
        finally:
            # Always record the wall-clock finish time regardless of outcome
            result.finished_at = datetime.now()
        return result

    @abstractmethod
    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Perform the language-specific scan and populate *result* with ``Issue`` objects.

        Subclasses must implement this method to carry out the actual analysis.
        They should add any discovered issues to ``result.issues`` and update
        ``result.files_scanned``, then return the mutated ``result`` object.

        Args:
            target: Absolute path to the file or directory to scan.
            result: A pre-initialised ``ScanResult`` object to populate.

        Returns:
            The same ``result`` object, now populated with issues and metadata.

        Raises:
            Any exception raised here is caught by ``scan`` and recorded in
            ``result.error_message``; the scan status is set to ``FAILED``.
        """

    @abstractmethod
    def supports(self, file_path: str) -> bool:
        """Return ``True`` if this scanner can analyse the given file.

        Typically implemented by checking the file's extension against
        ``SUPPORTED_EXTENSIONS``.  Used by the factory layer to route files
        to the correct scanner.

        Args:
            file_path: Path to the file whose language support is being queried.

        Returns:
            ``True`` if the scanner handles the file's language, ``False`` otherwise.
        """

    # ------------------------------------------------------------------
    # Shared utility
    # ------------------------------------------------------------------

    @staticmethod
    def collect_files(
        target: str,
        extensions: Iterable[str],
        file_names: Iterable[str] = (),
    ) -> List[str]:
        """Return every file under *target* that matches by extension or name.

        Directories listed in ``EXCLUDED_DIRS`` are never entered.  A single
        file passed as *target* is accepted whenever it matches.  See
        ``FileMatcher`` for the matching rules (dotfiles such as ``.env``
        and ``.env.production`` match the ``.env`` extension).
        """
        matcher = FileMatcher(extensions, file_names)
        target_path = Path(target)
        if target_path.is_file():
            return [str(target_path)] if matcher.matches(target_path.name) else []

        collected: List[str] = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRS]
            for name in files:
                if matcher.matches(name):
                    collected.append(os.path.join(root, name))
        collected.sort()
        return collected
