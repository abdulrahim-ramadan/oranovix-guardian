"""
Regex-based security scanner for Java source files.

This module provides ``JavaScanner``, a ``BaseScanner`` subclass that analyses
Java source files (``*.java``) for common security vulnerabilities using
regular expression matching applied line-by-line.

The scanner is rule-driven: ``_build_rules`` returns an ordered list of
``(pattern, title, severity, vuln_key, rule_id)`` tuples covering 12 distinct
vulnerability classes across four severity tiers:

- **CRITICAL** (JAVA001–JAVA003): ``Runtime.getRuntime().exec()`` command
  injection, ``ProcessBuilder`` with string concatenation, and hardcoded
  credentials in string variables.
- **HIGH** (JAVA004–JAVA007): SQL queries built by string concatenation,
  ``Statement.execute`` with a concatenated string, ``ObjectInputStream``
  (insecure deserialization), and ``XMLDecoder`` (insecure XML deserialization).
- **MEDIUM** (JAVA008–JAVA010): ``java.util.Random`` (weak PRNG),
  ``Math.random()`` (also weak), and ``Class.forName()`` with a dynamic class
  name (potential class injection).
- **LOW** (JAVA011–JAVA012): ``printStackTrace()`` (information disclosure)
  and ``System.out.print*`` logging of sensitive variable names.

After a match is found, ``VulnerabilityDatabase.enrich_issue`` attaches
educational content to each ``Issue`` object.

Version: 1.1.0
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from .categories import category_for_rule
from .base import BaseScanner, Issue, Language, ScanResult, Severity
from .vulnerability_db import VulnerabilityDatabase


# Type alias for a compiled rule tuple:
# (pattern, title, severity, vuln_key, rule_id)
_Rule = Tuple[str, str, Severity, str, str]


class JavaScanner(BaseScanner):
    """Scanner for Java source files using regex-based detection rules.

    ``JavaScanner`` is the concrete ``BaseScanner`` implementation for Java.
    It operates purely at the source-line level: each line is matched against
    an ordered list of compiled regex patterns, and the first matching pattern
    produces an ``Issue`` object.  The "first match wins" strategy (``break``
    after a match) prevents a single line from generating multiple issues for
    overlapping patterns.

    Rules span four severity tiers ranging from CRITICAL (``Runtime.exec()``
    command injection, ``ProcessBuilder`` with concatenation, hardcoded
    credentials) down to LOW (``printStackTrace()``, ``System.out`` logging of
    sensitive values).

    After each ``Issue`` is constructed, ``VulnerabilityDatabase.enrich_issue``
    is called to populate the educational content fields on the issue.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".java"]

    def __init__(self) -> None:
        """Initialise the scanner and pre-build the list of detection rules."""
        super().__init__(name="Java Scanner", supported_language=Language.JAVA)
        # Build the rule list once at startup to avoid recompiling on every scan
        self._rules: List[_Rule] = self._build_rules()

    # ------------------------------------------------------------------
    # BaseScanner contract
    # ------------------------------------------------------------------

    def supports(self, file_path: str) -> bool:
        """Return ``True`` if *file_path* has a ``.java`` extension.

        Args:
            file_path: Path to the file being evaluated.

        Returns:
            ``True`` for ``.java`` files; ``False`` for all other extensions.
        """
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Scan all Java files under *target* and populate *result*.

        Args:
            target: Absolute path to a ``.java`` file or a directory.
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
        """Apply all detection rules to a single Java source file.

        Reads the file line by line, skips comment lines (``//`` and ``#``),
        and tests each line against the ordered rule list.  At most one issue
        is generated per line (the first matching rule wins).

        Args:
            fpath: Absolute path to the Java file to analyse.

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

            # Skip single-line Java and shell-style comments to avoid false positives
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            for pattern, title, severity, vuln_key, rule_id in self._rules:
                if re.search(pattern, line, re.IGNORECASE):
                    issue = Issue(
                        rule_id=rule_id,
                        category=category_for_rule(rule_id),
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
        a unique identifier for the rule (e.g. ``"JAVA001"``).

        Rules are ordered from most severe to least severe so that the
        ``break`` after the first match always surfaces the highest-priority
        finding when patterns overlap.

        Returns:
            A list of ``_Rule`` tuples ready for use in ``_scan_file``.
        """
        return [
            # --- CRITICAL -----------------------------------------------

            # Runtime.getRuntime().exec() – OS command injection
            (
                r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
                "Runtime.exec() – Potential Command Injection",
                Severity.CRITICAL,
                "java_runtime_exec",
                "JAVA001",
            ),
            # ProcessBuilder constructed with a variable (possible injection)
            (
                r"new\s+ProcessBuilder\s*\([^)]*\+[^)]*\)",
                "ProcessBuilder with String Concatenation",
                Severity.CRITICAL,
                "java_runtime_exec",
                "JAVA002",
            ),
            # Hardcoded password / secret string literal
            (
                r"\bString\s+(password|passwd|secret|apiKey|api_key|token|credential)\s*=\s*\"[^\"]{3,}\"",
                "Hardcoded Credential in String Variable",
                Severity.CRITICAL,
                "java_hardcoded_creds",
                "JAVA003",
            ),

            # --- HIGH ---------------------------------------------------

            # SQL query built by concatenating a variable
            (
                r"\"(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+",
                "SQL Query Built by String Concatenation",
                Severity.HIGH,
                "java_sql_concat",
                "JAVA004",
            ),
            # Statement.execute / executeQuery with a concatenated string
            (
                r"\.(execute|executeQuery|executeUpdate)\s*\(\s*\"[^\"]*\"\s*\+",
                "SQL Statement Executed with Concatenated String",
                Severity.HIGH,
                "java_sql_concat",
                "JAVA005",
            ),
            # ObjectInputStream – insecure Java deserialization
            (
                r"\bnew\s+ObjectInputStream\s*\(",
                "ObjectInputStream – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "JAVA006",
            ),
            # XMLDecoder – insecure deserialization via XML
            (
                r"\bnew\s+XMLDecoder\s*\(",
                "XMLDecoder – Insecure Deserialization",
                Severity.HIGH,
                "insecure_deserialization",
                "JAVA007",
            ),

            # --- MEDIUM -------------------------------------------------

            # java.util.Random – weak PRNG (not SecureRandom)
            # Exclude SecureRandom from the match
            (
                r"\bnew\s+(?:java\.util\.)?Random\s*\(",
                "java.util.Random – Weak Pseudo-Random Number Generator",
                Severity.MEDIUM,
                "java_weak_random",
                "JAVA008",
            ),
            # Math.random() – also a weak PRNG
            (
                r"\bMath\s*\.\s*random\s*\(\s*\)",
                "Math.random() – Weak Random Value",
                Severity.MEDIUM,
                "java_weak_random",
                "JAVA009",
            ),
            # Class.forName() with a variable argument – potential class injection
            (
                r"\bClass\s*\.\s*forName\s*\(\s*[^\")\s][^)]*\)",
                "Class.forName() with Dynamic Class Name",
                Severity.MEDIUM,
                "",
                "JAVA010",
            ),

            # --- LOW ----------------------------------------------------

            # printStackTrace() – information disclosure
            (
                r"\.\s*printStackTrace\s*\(\s*\)",
                "printStackTrace() – Potential Information Disclosure",
                Severity.LOW,
                "java_print_stacktrace",
                "JAVA011",
            ),
            # System.out.print* with sensitive-sounding variable names
            (
                r"System\s*\.\s*out\s*\.\s*print[lnf]*\s*\([^)]*"
                r"(password|secret|token|key|credential)",
                "System.out Logging of Potentially Sensitive Value",
                Severity.LOW,
                "java_print_stacktrace",
                "JAVA012",
            ),
        ]
