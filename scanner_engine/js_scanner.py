"""
Regex-based security scanner for JavaScript and TypeScript source files.

This module provides ``JSScanner``, a ``BaseScanner`` subclass that analyses
JavaScript and TypeScript source files (``*.js``, ``*.ts``, ``*.jsx``,
``*.tsx``, ``*.mjs``) for common security vulnerabilities using regular
expression matching.

The scanner is rule-driven: ``_build_rules`` returns an ordered list of
``(pattern, title, severity, vuln_key, rule_id)`` tuples covering 15 distinct
vulnerability classes from CRITICAL (``eval()``, hardcoded secrets,
``document.write()``), through HIGH (``innerHTML`` assignment, SQL
concatenation, ``child_process.exec``), down to LOW (``debugger`` statements,
security-related TODO comments).

After a match is found, ``VulnerabilityDatabase.enrich_issue`` attaches
educational content (what it is, why it is dangerous, how it is exploited, and
how to fix it) to each ``Issue`` object so that the reporting layer can
present rich, developer-friendly findings.

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


class JSScanner(BaseScanner):
    """Scanner for JavaScript and TypeScript files using regex-based rules.

    ``JSScanner`` is the concrete ``BaseScanner`` implementation for JavaScript
    and TypeScript.  It operates purely at the source-line level: each line is
    matched against an ordered list of compiled regex patterns, and the first
    matching pattern produces an ``Issue`` object.  The "first match wins"
    approach (``break`` after a match) prevents a single line from generating
    multiple issues for overlapping patterns.

    Rules are divided into four severity tiers:

    - **CRITICAL** (JS001–JS005): ``eval()``, ``new Function()``, string-argument
      ``setTimeout``/``setInterval``, hardcoded secrets, ``document.write()``.
    - **HIGH** (JS006–JS010): ``innerHTML``/``outerHTML`` assignment, SQL
      concatenation, ``child_process`` execution with concatenated args, open redirect.
    - **MEDIUM** (JS011–JS013): sensitive data logged to ``console.log``,
      ``localStorage`` storing secrets, ``Math.random()`` for security.
    - **LOW** (JS014–JS015): ``debugger`` statements, security TODO comments.

    After each ``Issue`` is constructed, ``VulnerabilityDatabase.enrich_issue``
    is called to populate the educational content fields.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".js", ".ts", ".jsx", ".tsx", ".mjs"]

    def __init__(self) -> None:
        """Initialise the scanner and pre-build the list of detection rules."""
        super().__init__(name="JS/TS Scanner", supported_language=Language.JAVASCRIPT)
        # Build the rule list once at startup to avoid recompiling on every scan
        self._rules: List[_Rule] = self._build_rules()

    # ------------------------------------------------------------------
    # BaseScanner contract
    # ------------------------------------------------------------------

    def supports(self, file_path: str) -> bool:
        """Return ``True`` if *file_path* has a JS/TS-compatible extension.

        Args:
            file_path: Path to the file being evaluated.

        Returns:
            ``True`` for ``.js``, ``.ts``, ``.jsx``, ``.tsx``, and ``.mjs``
            files; ``False`` for all other extensions.
        """
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Scan all JS/TS files under *target* and populate *result*.

        Args:
            target: Absolute path to a JS/TS file or a directory.
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
        """Apply all detection rules to a single JS/TS source file.

        Reads the file line by line, skips comment lines, and tests each line
        against the ordered rule list.  At most one issue is generated per line
        (the first matching rule wins).

        Args:
            fpath: Absolute path to the JS/TS file to analyse.

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

            # Skip single-line comments to avoid false positives in documentation
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
        a unique identifier for the rule (e.g. ``"JS001"``).

        Rules are ordered from most severe to least severe so that the
        ``break`` after the first match always surfaces the highest-priority
        finding when patterns overlap.

        Returns:
            A list of ``_Rule`` tuples ready for use in ``_scan_file``.
        """
        return [
            # --- CRITICAL -----------------------------------------------

            # eval() with a non-literal argument
            (
                r"\beval\s*\(\s*(?!['\"`])",
                "Dangerous eval() Usage",
                Severity.CRITICAL,
                "js_eval",
                "JS001",
            ),
            # new Function() – equivalent to eval, executes arbitrary code
            (
                r"\bnew\s+Function\s*\(",
                "new Function() – Dynamic Code Execution",
                Severity.CRITICAL,
                "js_eval",
                "JS002",
            ),
            # setTimeout / setInterval with a string argument (executes code)
            (
                r"\b(setTimeout|setInterval)\s*\(\s*['\"`]",
                "setTimeout/setInterval with String Argument",
                Severity.CRITICAL,
                "js_eval",
                "JS003",
            ),
            # Hardcoded password / secret / API key in a variable declaration
            (
                r"(?:const|let|var)\s+(?:password|passwd|secret|api[_-]?key|token|"
                r"auth[_-]?token|access[_-]?token|private[_-]?key)\s*=\s*['\"`][^'\"`]{4,}['\"`]",
                "Hardcoded Secret or API Key",
                Severity.CRITICAL,
                "secret_exposed",
                "JS004",
            ),
            # document.write() with a variable – XSS via HTML injection
            (
                r"\bdocument\s*\.\s*write\s*\(",
                "document.write() – Potential XSS",
                Severity.CRITICAL,
                "js_dom_xss",
                "JS005",
            ),

            # --- HIGH ---------------------------------------------------

            # innerHTML / outerHTML assignment with a variable (reflected XSS)
            (
                r"\.(innerHTML|outerHTML)\s*=\s*(?!['\"`])",
                "innerHTML/outerHTML Assignment – Potential XSS",
                Severity.HIGH,
                "js_innerhtml",
                "JS006",
            ),
            # insertAdjacentHTML – another XSS vector
            (
                r"\.\s*insertAdjacentHTML\s*\(",
                "insertAdjacentHTML() – Potential XSS",
                Severity.HIGH,
                "js_innerhtml",
                "JS007",
            ),
            # SQL-like query string built with concatenation
            (
                r"['\"`](SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^'\"` ]*['\"`]\s*\+",
                "SQL Query Built by String Concatenation",
                Severity.HIGH,
                "sql_injection",
                "JS008",
            ),
            # child_process.exec / execSync with a variable (Node.js)
            (
                r"\.(exec|execSync|spawn|spawnSync)\s*\([^)]*\+",
                "child_process Execution with Concatenated Argument",
                Severity.HIGH,
                "command_injection",
                "JS009",
            ),
            # Location redirect to a variable – open redirect
            (
                r"\b(?:window\.)?location(?:\.href)?\s*=\s*(?!['\"`])",
                "Open Redirect – location Assigned from Variable",
                Severity.HIGH,
                "open_redirect",
                "JS010",
            ),

            # --- MEDIUM -------------------------------------------------

            # console.log with password / token in argument
            (
                r"\bconsole\s*\.\s*log\s*\([^)]*"
                r"(password|passwd|secret|token|api[_-]?key|credential)",
                "console.log() of Potentially Sensitive Value",
                Severity.MEDIUM,
                "secret_exposed",
                "JS011",
            ),
            # localStorage / sessionStorage storing sensitive keys
            (
                r"\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['\"`]"
                r"(?:password|token|secret|api_?key)",
                "Sensitive Data Stored in localStorage/sessionStorage",
                Severity.MEDIUM,
                "js_localstorage",
                "JS012",
            ),
            # Math.random() used in a security context
            (
                r"\bMath\s*\.\s*random\s*\(\s*\)",
                "Math.random() – Not Cryptographically Secure",
                Severity.MEDIUM,
                "weak_random",
                "JS013",
            ),

            # --- LOW ----------------------------------------------------

            # debugger statement left in code
            (
                r"^\s*debugger\s*;?\s*$",
                "debugger Statement in Production Code",
                Severity.LOW,
                "debug_mode",
                "JS014",
            ),
            # TODO / FIXME security-related comment
            (
                r"//.*\b(TODO|FIXME|HACK|XXX)\b.*\b(security|auth|password|sql|inject)",
                "Security-Related TODO/FIXME Comment",
                Severity.LOW,
                "",
                "JS015",
            ),
        ]
