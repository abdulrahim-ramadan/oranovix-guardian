"""
Regex-based security scanner for PHP source files.

This module provides ``PHPScanner``, a ``BaseScanner`` subclass that analyses
PHP source files (``*.php``) for common security vulnerabilities using regular
expression matching applied line-by-line.

The scanner is rule-driven: ``_build_rules`` returns an ordered list of
``(pattern, title, severity, vuln_key, rule_id)`` tuples covering 12 distinct
vulnerability classes across four severity tiers:

- **CRITICAL** (PHP001–PHP004): ``eval()``, shell-execution functions
  (``system``, ``exec``, ``shell_exec``, etc.), dynamic file inclusion (LFI/RFI),
  and SQL queries built by string concatenation.
- **HIGH** (PHP005–PHP007): unsanitised superglobal output (XSS via ``echo``
  and ``print``), and weak password hashing with MD5 or SHA1.
- **MEDIUM** (PHP008–PHP010): deprecated ``mysql_connect``/``mysql_query``
  functions (no prepared-statement support), and backtick shell execution
  with a variable argument.
- **LOW** (PHP011–PHP012): verbose error reporting (``E_ALL``) and
  ``display_errors`` enabled in code.

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


class PHPScanner(BaseScanner):
    """Scanner for PHP source files using regex-based detection rules.

    ``PHPScanner`` is the concrete ``BaseScanner`` implementation for PHP.
    It operates purely at the source-line level: each line is matched against
    an ordered list of compiled regex patterns, and the first matching pattern
    produces an ``Issue`` object.  The "first match wins" strategy (``break``
    after a match) prevents a single line from generating multiple issues for
    overlapping patterns.

    Rules span four severity tiers ranging from CRITICAL (``eval()``, shell
    execution, LFI/RFI, SQL injection) down to LOW (verbose error reporting,
    ``display_errors`` set in code).

    After each ``Issue`` is constructed, ``VulnerabilityDatabase.enrich_issue``
    is called to populate the educational content fields on the issue.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".php"]

    def __init__(self) -> None:
        """Initialise the scanner and pre-build the list of detection rules."""
        super().__init__(name="PHP Scanner", supported_language=Language.PHP)
        # Build the rule list once at startup to avoid recompiling on every scan
        self._rules: List[_Rule] = self._build_rules()

    # ------------------------------------------------------------------
    # BaseScanner contract
    # ------------------------------------------------------------------

    def supports(self, file_path: str) -> bool:
        """Return ``True`` if *file_path* has a ``.php`` extension.

        Args:
            file_path: Path to the file being evaluated.

        Returns:
            ``True`` for ``.php`` files; ``False`` for all other extensions.
        """
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Scan all PHP files under *target* and populate *result*.

        Args:
            target: Absolute path to a ``.php`` file or a directory.
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
        """Apply all detection rules to a single PHP source file.

        Reads the file line by line, skips comment lines (``//`` and ``#``),
        and tests each line against the ordered rule list.  At most one issue
        is generated per line (the first matching rule wins).

        Args:
            fpath: Absolute path to the PHP file to analyse.

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

            # Skip single-line PHP and shell-style comments to avoid false positives
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
        a unique identifier for the rule (e.g. ``"PHP001"``).

        Rules are ordered from most severe to least severe so that the
        ``break`` after the first match always surfaces the highest-priority
        finding when patterns overlap.

        Returns:
            A list of ``_Rule`` tuples ready for use in ``_scan_file``.
        """
        return [
            # --- CRITICAL -----------------------------------------------

            # eval() – arbitrary PHP code execution
            (
                r"\beval\s*\(",
                "Dangerous eval() Usage",
                Severity.CRITICAL,
                "php_eval",
                "PHP001",
            ),
            # Shell-execution functions
            (
                r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
                "Shell Command Execution Function",
                Severity.CRITICAL,
                "php_system",
                "PHP002",
            ),
            # File inclusion with a variable (LFI/RFI)
            (
                r"\b(include|require|include_once|require_once)\s*[\(\s][^'\"]*\$",
                "Dynamic File Inclusion",
                Severity.CRITICAL,
                "php_file_inclusion",
                "PHP003",
            ),

            # --- HIGH ---------------------------------------------------

            # SQL query built by concatenating a variable (no prepared statement)
            (
                r"(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM).{0,80}\$",
                "SQL Injection – Query Built with Variable",
                Severity.CRITICAL,
                "php_sql_injection",
                "PHP004",
            ),
            # $_GET / $_POST / $_REQUEST echoed directly (reflected XSS)
            (
                r"echo\s+.*\$_(GET|POST|REQUEST|COOKIE)\s*\[",
                "Unsanitised User Input Echoed (XSS)",
                Severity.HIGH,
                "php_xss",
                "PHP005",
            ),
            # print echoing superglobals
            (
                r"\bprint\s+.*\$_(GET|POST|REQUEST|COOKIE)\s*\[",
                "Unsanitised User Input Printed (XSS)",
                Severity.HIGH,
                "php_xss",
                "PHP006",
            ),
            # MD5 / SHA1 used for password hashing
            (
                r"\b(md5|sha1)\s*\(\s*\$?(password|passwd|pass|pwd)",
                "Weak Password Hashing (MD5/SHA1)",
                Severity.HIGH,
                "php_md5_password",
                "PHP007",
            ),

            # --- MEDIUM -------------------------------------------------

            # Deprecated mysql_connect() – superseded by mysqli / PDO
            (
                r"\bmysql_connect\s*\(",
                "Deprecated mysql_connect() Usage",
                Severity.MEDIUM,
                "php_sql_injection",
                "PHP008",
            ),
            # Deprecated mysql_query() – no prepared-statement support
            (
                r"\bmysql_query\s*\(",
                "Deprecated mysql_query() Usage",
                Severity.MEDIUM,
                "php_sql_injection",
                "PHP009",
            ),
            # Backtick operator (shell execution shorthand)
            (
                r"`[^`]*\$[^`]*`",
                "Backtick Shell Execution with Variable",
                Severity.MEDIUM,
                "php_system",
                "PHP010",
            ),

            # --- LOW ----------------------------------------------------

            # error_reporting(E_ALL) with display_errors leaks internals
            (
                r"\berror_reporting\s*\(\s*E_ALL",
                "Verbose Error Reporting Enabled",
                Severity.LOW,
                "php_error_reporting",
                "PHP011",
            ),
            # display_errors = On / 1 / true
            (
                r"ini_set\s*\(\s*['\"]display_errors['\"]",
                "display_errors Configuration Set in Code",
                Severity.LOW,
                "php_error_reporting",
                "PHP012",
            ),
        ]
