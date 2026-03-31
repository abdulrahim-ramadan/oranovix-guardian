"""
Regex-based security scanner for C# and ASP.NET source files.

This module provides ``CSharpScanner``, a ``BaseScanner`` subclass that analyses
C# source files (``*.cs``) for common security vulnerabilities using regular
expression matching applied line-by-line.

The scanner is rule-driven: ``_build_rules`` returns an ordered list of
``(pattern, title, severity, vuln_key, rule_id)`` tuples covering 13 distinct
vulnerability classes across three severity tiers:

- **CRITICAL** (CS001–CS003): ``Process.Start()`` (command injection),
  hardcoded passwords or secrets in string variables, and hardcoded passwords
  embedded in connection strings.
- **HIGH** (CS004–CS010): SQL queries built by string concatenation, SQL
  command objects constructed with concatenated strings, ``Response.Write()``
  (reflected XSS), and four insecure .NET deserialization formatters
  (``BinaryFormatter``, ``SoapFormatter``, ``LosFormatter``,
  ``ObjectStateFormatter``).
- **LOW** (CS011–CS013): ``Debug.Assert()`` (silently compiled out in Release
  builds), ``Console.WriteLine()`` logging of sensitive variable names, and
  ``Trace.WriteLine()`` logging of sensitive variable names.

After a match is found, ``VulnerabilityDatabase.enrich_issue`` attaches
educational content to each ``Issue`` object.

Version: 1.1.0
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from .base import BaseScanner, Issue, Language, ScanResult, Severity
from .vulnerability_db import VulnerabilityDatabase


# Type alias for a compiled rule tuple:
# (pattern, title, severity, vuln_key, rule_id)
_Rule = Tuple[str, str, Severity, str, str]


class CSharpScanner(BaseScanner):
    """Scanner for C# and ASP.NET source files using regex-based detection rules.

    ``CSharpScanner`` is the concrete ``BaseScanner`` implementation for C#.
    It operates purely at the source-line level: each line is matched against
    an ordered list of compiled regex patterns, and the first matching pattern
    produces an ``Issue`` object.  The "first match wins" strategy (``break``
    after a match) prevents a single line from generating multiple issues for
    overlapping patterns.

    Rules span three severity tiers ranging from CRITICAL (``Process.Start()``
    command injection, hardcoded passwords, connection-string embedded
    passwords) through HIGH (SQL concatenation, insecure .NET deserialization
    formatters, ``Response.Write()`` XSS) down to LOW (``Debug.Assert()``,
    ``Console.WriteLine``/``Trace.WriteLine`` logging of sensitive data).

    After each ``Issue`` is constructed, ``VulnerabilityDatabase.enrich_issue``
    is called to populate the educational content fields on the issue.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".cs"]

    def __init__(self) -> None:
        """Initialise the scanner and pre-build the list of detection rules."""
        super().__init__(name="C# Scanner", supported_language=Language.CSHARP)
        # Build the rule list once at startup to avoid recompiling on every scan
        self._rules: List[_Rule] = self._build_rules()

    # ------------------------------------------------------------------
    # BaseScanner contract
    # ------------------------------------------------------------------

    def supports(self, file_path: str) -> bool:
        """Return ``True`` if *file_path* has a ``.cs`` extension.

        Args:
            file_path: Path to the file being evaluated.

        Returns:
            ``True`` for ``.cs`` files; ``False`` for all other extensions.
        """
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Scan all C# files under *target* and populate *result*.

        Args:
            target: Absolute path to a ``.cs`` file or a directory.
            result: Pre-initialised ``ScanResult`` to populate.

        Returns:
            The same ``result`` object, populated with all discovered issues
            and an updated ``files_scanned`` count.
        """
        files = self.collect_files(target, self.SUPPORTED_EXTENSIONS)
        result.files_scanned = len(files)
        for fpath in files:
            result.issues.extend(self._scan_file(fpath))
        return result

    # ------------------------------------------------------------------
    # Per-file scanning
    # ------------------------------------------------------------------

    def _scan_file(self, fpath: str) -> List[Issue]:
        """Apply all detection rules to a single C# source file.

        Reads the file line by line, skips comment lines (``//`` and ``#``),
        and tests each line against the ordered rule list.  At most one issue
        is generated per line (the first matching rule wins).

        Args:
            fpath: Absolute path to the C# file to analyse.

        Returns:
            A list of ``Issue`` objects for every matched line; may be empty.
        """
        issues: List[Issue] = []
        try:
            lines = Path(fpath).read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            # File unreadable – return empty list and let the caller continue
            return issues

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip single-line C# and shell-style comments to avoid false positives
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            for pattern, title, severity, vuln_key, rule_id in self._rules:
                if re.search(pattern, line, re.IGNORECASE):
                    issue = Issue(
                        rule_id=rule_id,
                        title=title,
                        # Truncate the snippet in the description to 120 chars
                        description=f"Detected: {stripped[:120]}",
                        severity=severity,
                        file_path=fpath,
                        line_number=lineno,
                        code_snippet=stripped[:200],  # cap snippet at 200 chars
                        confidence="HIGH",
                    )
                    # Attach educational content from the vulnerability database
                    VulnerabilityDatabase.enrich_issue(issue, vuln_key)
                    issues.append(issue)
                    break  # one issue per line max – first matching rule wins

        return issues

    # ------------------------------------------------------------------
    # Rule definitions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules() -> List[_Rule]:
        """Build and return the ordered list of regex detection rules.

        Each entry is a 5-tuple of:
            ``(pattern, title, severity, vuln_key, rule_id)``

        where *pattern* is a regex string, *vuln_key* is the key used to look
        up educational content in ``VulnerabilityDatabase``, and *rule_id* is
        a unique identifier for the rule (e.g. ``"CS001"``).

        Rules are ordered from most severe to least severe so that the
        ``break`` after the first match always surfaces the highest-priority
        finding when patterns overlap.

        Returns:
            A list of ``_Rule`` tuples ready for use in ``_scan_file``.
        """
        return [
            # --- CRITICAL -----------------------------------------------

            # Process.Start() – OS command injection
            (
                r"\bProcess\s*\.\s*Start\s*\(",
                "Process.Start() – Potential Command Injection",
                Severity.CRITICAL,
                "cs_process_start",
                "CS001",
            ),
            # Hardcoded password / secret in a string assignment
            (
                r"\bstring\s+(password|passwd|secret|apiKey|api_key|token|credential)\s*=\s*\"[^\"]{3,}\"",
                "Hardcoded Password or Secret",
                Severity.CRITICAL,
                "cs_hardcoded_password",
                "CS002",
            ),
            # Connection string with embedded password= value
            (
                r"password\s*=\s*[^;\"'\s]{3,}",
                "Hardcoded Password in Connection String",
                Severity.CRITICAL,
                "cs_hardcoded_password",
                "CS003",
            ),

            # --- HIGH ---------------------------------------------------

            # SQL query built by string concatenation
            (
                r"\"(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+",
                "SQL Query Built by String Concatenation",
                Severity.HIGH,
                "cs_sql_concat",
                "CS004",
            ),
            # SqlCommand / NpgsqlCommand / OleDbCommand with a + (concat)
            (
                r"new\s+(SqlCommand|NpgsqlCommand|OleDbCommand|MySqlCommand)\s*\([^)]*\+",
                "SQL Command Constructed with String Concatenation",
                Severity.HIGH,
                "cs_sql_concat",
                "CS005",
            ),
            # Response.Write() – potential reflected XSS
            (
                r"\bResponse\s*\.\s*Write\s*\(",
                "Response.Write() – Potential Reflected XSS",
                Severity.HIGH,
                "cs_response_write",
                "CS006",
            ),
            # BinaryFormatter – insecure .NET deserialization
            (
                r"\bBinaryFormatter\b",
                "BinaryFormatter – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "CS007",
            ),
            # SoapFormatter – insecure .NET deserialization
            (
                r"\bSoapFormatter\b",
                "SoapFormatter – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "CS008",
            ),
            # LosFormatter – insecure .NET deserialization
            (
                r"\bLosFormatter\b",
                "LosFormatter – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "CS009",
            ),
            # ObjectStateFormatter – insecure .NET deserialization
            (
                r"\bObjectStateFormatter\b",
                "ObjectStateFormatter – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "CS010",
            ),

            # --- LOW ----------------------------------------------------

            # Debug.Assert – silently removed in Release builds
            (
                r"\bDebug\s*\.\s*Assert\s*\(",
                "Debug.Assert() – Compiled Out in Release Builds",
                Severity.LOW,
                "cs_debug_assert",
                "CS011",
            ),
            # Console.WriteLine with a potentially sensitive variable name
            (
                r"Console\s*\.\s*Write(?:Line)?\s*\([^)]*"
                r"(password|secret|token|key|credential)",
                "Console.WriteLine() Logging Potentially Sensitive Data",
                Severity.LOW,
                "cs_debug_assert",
                "CS012",
            ),
            # Trace.WriteLine with sensitive data – leaks to diagnostics listeners
            (
                r"Trace\s*\.\s*Write(?:Line)?\s*\([^)]*"
                r"(password|secret|token|key|credential)",
                "Trace.WriteLine() Logging Potentially Sensitive Data",
                Severity.LOW,
                "cs_debug_assert",
                "CS013",
            ),
        ]
