"""
Python security scanner that wraps Bandit and supplements it with custom regex checks.

This module provides ``PythonScanner``, a ``BaseScanner`` subclass that analyses
Python source files for security vulnerabilities.  It shells out to the Bandit
static analysis tool (https://bandit.readthedocs.io), parses its JSON output,
and maps each finding to an ``Issue`` object using an internal severity-escalation
table that promotes certain Bandit test IDs to CRITICAL or HIGH regardless of
Bandit's own classification.

In addition to Bandit, two supplemental regex passes are performed on every
file:

- **SEC001** – Hardcoded secrets/API keys detected by variable-name heuristics.
- **SEC002** – Path traversal risk when ``open()`` is called with a non-literal
  argument.

The module also ships a comprehensive ``_build_recommendation`` lookup that
maps every common Bandit test ID (B101–B703) to actionable developer guidance.

Version: 1.1.0
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List

from .base import (
    BaseScanner,
    Issue,
    Language,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

# Direct translation from Bandit's severity strings to internal Severity enum values.
# Bandit does not emit a CRITICAL level, so we handle escalation separately below.
_BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

# Maps Bandit's confidence strings to numeric weights (currently kept for
# potential future use in confidence-weighted scoring).
_BANDIT_CONFIDENCE_MAP: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

# Bandit test IDs that represent truly critical vulnerabilities regardless of
# what Bandit labels them (Bandit tops out at HIGH, but these patterns are
# effectively CRITICAL in any real application).
_ESCALATE_TO_CRITICAL: set[str] = {
    "B102",  # exec()
    "B307",  # eval()
    "B501",  # SSL cert not verified
    "B602",  # subprocess shell=True
    "B605",  # os.system / start_process_with_shell
    "B606",  # os.startfile
    "B608",  # SQL injection via string formatting
}

# Bandit test IDs that should be promoted to HIGH severity to reflect their
# real-world exploitability even when Bandit assigns MEDIUM.
_ESCALATE_TO_HIGH: set[str] = {
    "B103",  # chmod permissive
    "B105",  # hardcoded password (variable)
    "B106",  # hardcoded password (arg)
    "B107",  # hardcoded password (default)
    "B324",  # weak hash (md5/sha1)
    "B603",  # subprocess without shell (still needs validation)
    "B607",  # partial path in subprocess
}

# ---------------------------------------------------------------------------
# Extra regex checks (supplement Bandit)
# ---------------------------------------------------------------------------

# Matches variable assignments where the variable name strongly suggests it
# holds a secret credential (API key, password, token, etc.) and the value is
# a non-empty string literal of at least 4 characters.
# Named groups:  var = the suspicious variable name, val = the literal value.
_SECRET_NAME_RE = re.compile(
    r'(?i)^[ \t]*(?:self\.)?(?:\w+\.)?'
    r'(?P<var>api[_-]?key|secret[_-]?key|secret|token|password|passwd|pwd|'
    r'auth[_-]?token|access[_-]?token|private[_-]?key|api[_-]?secret)'
    r'\s*=\s*(?:f?["\'])(?P<val>[^"\']{4,})["\']',
    re.MULTILINE,
)

# Matches calls to the built-in open() where the first argument is not a
# hard-coded string literal, Path(), or bytes literal — the usual indicators
# of a safe, developer-controlled path.  A dynamic argument may be influenced
# by user input and therefore constitutes a potential path-traversal risk.
_OPEN_TRAVERSAL_RE = re.compile(
    r'\bopen\s*\(\s*(?!["\']|b["\']|rb["\']|Path)(?P<arg>[^,\)]+)',
    re.MULTILINE,
)


class PythonScanner(BaseScanner):
    """Scanner for Python source files that combines Bandit with custom regex rules.

    ``PythonScanner`` is the concrete ``BaseScanner`` implementation for Python.
    Its primary strategy is to shell out to Bandit (``_run_bandit``), parse the
    JSON output (``_parse_bandit_output``), and apply the severity-escalation
    tables defined at module level to correct Bandit's conservative severity
    ratings for certain test IDs.

    A secondary pass (``_extra_checks``) runs two regex patterns over each file
    to catch hardcoded secrets (SEC001) and path traversal risks via ``open()``
    (SEC002) that Bandit may miss.

    Key responsibilities:
        - Resolve the Bandit executable path at construction time, handling
          both development environments and frozen PyInstaller bundles.
        - Translate Bandit's JSON report into ``Issue`` objects.
        - Escalate specific Bandit test IDs to CRITICAL or HIGH as appropriate.
        - Perform supplemental regex analysis for issues outside Bandit's scope.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".py"]

    def __init__(self) -> None:
        """Initialise the scanner and resolve the Bandit executable path."""
        super().__init__(name="Python (Bandit)", supported_language=Language.PYTHON)
        # Resolve once at startup to avoid repeated filesystem lookups per scan
        self._bandit_exe = self._resolve_bandit()

    # ------------------------------------------------------------------
    # BaseScanner contract
    # ------------------------------------------------------------------

    def supports(self, file_path: str) -> bool:
        """Return ``True`` if *file_path* has a ``.py`` extension.

        Args:
            file_path: Path to the file being evaluated.

        Returns:
            ``True`` for ``.py`` files, ``False`` for all other extensions.
        """
        return Path(file_path).suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _do_scan(self, target: str, result: ScanResult) -> ScanResult:
        """Scan *target* using Bandit, AST analysis, and supplemental regex checks.

        Collects all ``.py`` files under *target*, runs Bandit over the entire
        target path for efficiency, applies per-file AST analysis via
        ASTAnalyzer, and then applies the per-file regex checks for patterns
        that Bandit misses.  Duplicate issues (same rule_id + file + line) are
        de-duplicated before returning.

        Args:
            target: Absolute path to a ``.py`` file or directory.
            result: Pre-initialised ``ScanResult`` to populate with issues.

        Returns:
            The same ``result`` object, now containing all discovered issues
            and an updated ``files_scanned`` count.
        """
        from .ast_analyzer import ASTAnalyzer

        files = self.collect_files(target, self.SUPPORTED_EXTENSIONS)
        result.files_scanned = len(files)

        if not files:
            # Nothing to scan – return the empty result immediately
            return result

        # Run Bandit over the whole target at once and translate its output
        raw = self._run_bandit(target)
        allowed = {os.path.normcase(os.path.abspath(f)) for f in files}
        issues = [
            issue for issue in self._parse_bandit_output(raw)
            if os.path.normcase(os.path.abspath(issue.file_path)) in allowed
        ]
        result.issues.extend(issues)

        # Track (rule_id, file_path, line_number) to avoid duplicates
        seen: set = {
            (i.rule_id, i.file_path, i.line_number) for i in result.issues
        }

        for file_path in files:
            # Regex-based supplemental checks
            for issue in self._extra_checks(file_path):
                key = (issue.rule_id, issue.file_path, issue.line_number)
                if key not in seen:
                    result.issues.append(issue)
                    seen.add(key)

            # AST-based analysis (exact line numbers, no false positives from comments)
            try:
                code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                for issue in ASTAnalyzer.analyze(code, file_path):
                    key = (issue.rule_id, issue.file_path, issue.line_number)
                    if key not in seen:
                        result.issues.append(issue)
                        seen.add(key)
            except OSError:
                pass

        return result

    # ------------------------------------------------------------------
    # Bandit execution
    # ------------------------------------------------------------------

    def _resolve_bandit(self) -> str:
        """Return the absolute path to the Bandit executable.

        The resolution strategy handles three deployment scenarios in order:

        1. **Frozen PyInstaller bundle** (``sys.frozen == True``): looks for
           ``bandit.exe`` or ``bandit`` inside ``sys._MEIPASS`` (the temp
           extraction directory), then falls back to the directory that
           contains the application ``.exe``.
        2. **Development / virtual-environment**: looks inside the ``Scripts``
           (Windows) or ``bin`` (Unix) directory next to the Python interpreter.
        3. **Fallback**: returns the bare string ``"bandit"`` and relies on
           the system ``PATH`` to locate the executable at runtime.

        Returns:
            An absolute path string to the Bandit executable, or the plain
            string ``"bandit"`` if no absolute path could be determined.
        """
        # When packaged with PyInstaller --onefile, look in _MEIPASS first
        if getattr(sys, "frozen", False):
            meipass = getattr(sys, "_MEIPASS", "")
            for name in ("bandit.exe", "bandit"):
                candidate = os.path.join(meipass, name)
                if os.path.exists(candidate):
                    return candidate
            # Also try next to the .exe in case bandit was bundled separately
            exe_dir = os.path.dirname(sys.executable)
            for name in ("bandit.exe", "bandit"):
                candidate = os.path.join(exe_dir, name)
                if os.path.exists(candidate):
                    return candidate
        # Development environment: look in the same Scripts/bin dir as Python
        scripts_dir = Path(sys.executable).parent
        for candidate in ("bandit.exe", "bandit"):
            exe = scripts_dir / candidate
            if exe.exists():
                return str(exe)
        return "bandit"  # hope it is on PATH

    def _run_bandit(self, target: str) -> dict:
        """Execute Bandit as a subprocess and return its parsed JSON output.

        Runs Bandit with recursive mode (``-r``), JSON output format (``-f json``),
        and low-severity threshold (``-l``) so that every finding is included.
        Errors (timeout, missing executable, malformed JSON) are silently
        swallowed and an empty dict is returned, allowing the caller to proceed
        gracefully with the supplemental regex checks.

        Args:
            target: Absolute path to the file or directory to pass to Bandit.

        Returns:
            A dictionary containing Bandit's parsed JSON report, or an empty
            dict if Bandit could not be executed or produced no output.
        """
        cmd = [
            self._bandit_exe,
            "-r",         # recursive scan – Bandit handles directory walking itself
            "-f", "json", # machine-readable JSON output for programmatic parsing
            "-l",         # include LOW severity findings and above (report everything)
            target,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # abort if Bandit takes more than 2 minutes
            )
            if proc.stdout.strip():
                return json.loads(proc.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            # TimeoutExpired  – Bandit took too long; skip its output
            # JSONDecodeError – Bandit produced non-JSON output (e.g. an error message)
            # FileNotFoundError – Bandit executable not found at the resolved path
            pass
        return {}

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_bandit_output(self, data: dict) -> List[Issue]:
        """Translate Bandit's JSON report into a list of ``Issue`` objects.

        Applies the severity-escalation tables (``_ESCALATE_TO_CRITICAL`` and
        ``_ESCALATE_TO_HIGH``) before falling back to Bandit's own severity
        label.  The title is cleaned up by replacing underscores with spaces
        and applying title-casing so it is suitable for display in the UI.

        Args:
            data: Parsed JSON dictionary produced by Bandit.  Expected to
                contain a ``"results"`` key with a list of finding dicts.

        Returns:
            A list of ``Issue`` objects; empty if *data* has no results.
        """
        issues: List[Issue] = []
        results = data.get("results", [])
        for item in results:
            test_id = item.get("test_id", "B000")

            # Apply severity escalation: override Bandit's label for test IDs
            # that are known to be more dangerous than Bandit rates them.
            if test_id in _ESCALATE_TO_CRITICAL:
                severity = Severity.CRITICAL
            elif test_id in _ESCALATE_TO_HIGH:
                severity = Severity.HIGH
            else:
                # Fall back to Bandit's own severity; default to LOW if unknown
                severity = _BANDIT_SEVERITY_MAP.get(
                    item.get("issue_severity", "LOW").upper(), Severity.LOW
                )

            issue = Issue(
                rule_id=test_id,
                # Convert snake_case test names to "Title Case" for readability
                title=item.get("test_name", "Unknown Issue").replace("_", " ").title(),
                description=item.get("issue_text", ""),
                severity=severity,
                file_path=item.get("filename", ""),
                line_number=item.get("line_number", 0),
                code_snippet=item.get("code", "").strip(),
                recommendation=self._build_recommendation(item),
                # Extract the CWE link from the nested dict Bandit provides
                cwe=item.get("issue_cwe", {}).get("link", ""),
                confidence=item.get("issue_confidence", "MEDIUM"),
            )
            issues.append(issue)
        return issues

    def _extra_checks(self, file_path: str) -> List[Issue]:
        """Run regex-based security checks that supplement Bandit's analysis.

        Reads the entire source file and applies two compiled regex patterns:

        - ``_SECRET_NAME_RE`` (SEC001): detects hardcoded credentials assigned
          to variables with security-sensitive names.
        - ``_OPEN_TRAVERSAL_RE`` (SEC002): detects ``open()`` calls whose first
          argument is a non-literal expression (potential path traversal).

        Args:
            file_path: Absolute path to the Python source file to analyse.

        Returns:
            A list of ``Issue`` objects for any findings; empty list if the
            file cannot be read or no patterns match.
        """
        extra: List[Issue] = []
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            # File unreadable (permission error, deleted, etc.) – skip silently
            return extra

        lines = source.splitlines()

        # ── Hardcoded secrets ──────────────────────────────────────────
        for m in _SECRET_NAME_RE.finditer(source):
            # Compute the 1-based line number by counting preceding newlines
            line_num = source[: m.start()].count("\n") + 1
            var_name = m.group("var")
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            extra.append(Issue(
                rule_id="SEC001",
                title="Hardcoded Secret / API Key",
                description=(
                    f"Hardcoded credential found in variable '{var_name}'. "
                    "Secrets committed to source code can be extracted from "
                    "version control, compiled binaries, or process memory."
                ),
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=snippet,
                recommendation=(
                    "Store secrets in environment variables or a secrets manager "
                    "(e.g. python-decouple, AWS Secrets Manager, HashiCorp Vault). "
                    "Rotate any key that has been committed to version control."
                ),
                cwe="https://cwe.mitre.org/data/definitions/798.html",
                confidence="HIGH",
            ))

        # ── Path traversal via open() ──────────────────────────────────
        for m in _OPEN_TRAVERSAL_RE.finditer(source):
            arg = m.group("arg").strip()
            # Skip if the argument looks like a compile-time constant (string
            # literal, Path() call, or os.* call) – these are safe by default.
            if re.match(r'^["\']|^Path|^os\.', arg):
                continue
            line_num = source[: m.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            extra.append(Issue(
                rule_id="SEC002",
                title="Potential Path Traversal",
                description=(
                    f"open() called with non-literal argument '{arg}'. "
                    "If this value is derived from user input, an attacker "
                    "can read or overwrite arbitrary files (e.g. ../../etc/passwd)."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=snippet,
                recommendation=(
                    "Validate and sanitize file paths with os.path.abspath() "
                    "and verify the resolved path starts within an expected "
                    "base directory before opening the file."
                ),
                cwe="https://cwe.mitre.org/data/definitions/22.html",
                confidence="MEDIUM",
            ))

        return extra

    @staticmethod
    def _build_recommendation(item: dict) -> str:
        """Return a developer-facing remediation string for a Bandit finding.

        Looks up *item*'s ``test_id`` in a comprehensive recommendation table
        covering every Bandit test ID from B101 to B703.  Falls back to a
        generic least-privilege reminder for any test ID not in the table.

        Args:
            item: A single result dict from Bandit's JSON ``"results"`` list.

        Returns:
            A concise, actionable recommendation string for the developer.
        """
        test_id: str = item.get("test_id", "")
        recommendations: dict[str, str] = {
            "B101": "Remove assert statements in production code or use proper error handling.",
            "B102": "Avoid exec() — use safer alternatives like ast.literal_eval().",
            "B103": "Set restrictive file permissions (e.g. chmod 600).",
            "B104": "Bind to a specific IP address instead of 0.0.0.0.",
            "B105": "Avoid hardcoding passwords. Use environment variables or a secrets manager.",
            "B106": "Avoid hardcoding passwords. Use environment variables or a secrets manager.",
            "B107": "Avoid hardcoding passwords. Use environment variables or a secrets manager.",
            "B108": "Use a secure temp directory via tempfile.mkstemp().",
            "B110": "Avoid bare except clauses that silently swallow exceptions.",
            "B112": "Avoid bare except clauses that silently swallow exceptions.",
            "B201": "Never use debug mode (debug=True) in production Flask apps.",
            "B202": "Disable Flask debug mode in production.",
            "B301": "Avoid pickle / cPickle — use JSON or another safe format.",
            "B302": "Avoid marshal — use JSON or another safe format.",
            "B303": "Use SHA-256 or stronger instead of MD5/SHA1.",
            "B304": "Use SHA-256 or stronger instead of MD5/SHA1.",
            "B305": "Use SHA-256 or stronger cipher algorithms.",
            "B306": "Use tempfile.mkstemp() instead of tempfile.mktemp().",
            "B307": "Avoid eval() — use ast.literal_eval() for safe expression parsing.",
            "B308": "Avoid mark_safe() with user-supplied data to prevent XSS.",
            "B310": "Validate URL schemes before passing to urllib.urlopen().",
            "B311": "Use secrets module for cryptographic operations, not random.",
            "B312": "Avoid telnetlib — use Paramiko/SSH for encrypted connections.",
            "B313": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B314": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B315": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B316": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B317": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B318": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B319": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B320": "Use defusedxml to parse XML and prevent XXE attacks.",
            "B321": "Avoid FTP — use SFTP/FTPS for encrypted file transfer.",
            "B322": "Use input() instead of raw_input() (Python 2 only).",
            "B323": "Validate SSL/TLS certificates in production.",
            "B324": "Use SHA-256 or stronger hash functions.",
            "B325": "Use tempfile.mkstemp() instead of tempfile.mktemp().",
            "B401": "Avoid importing insecure modules.",
            "B402": "Avoid importing insecure modules.",
            "B403": "Be cautious with pickle imports; validate all deserialized data.",
            "B404": "Validate all input passed to subprocess calls.",
            "B405": "Use defusedxml instead of lxml for untrusted XML.",
            "B406": "Use defusedxml instead of xmltodict for untrusted XML.",
            "B407": "Use defusedxml instead of xmltodict for untrusted XML.",
            "B408": "Use defusedxml instead of xmltodict for untrusted XML.",
            "B409": "Use defusedxml instead of xmltodict for untrusted XML.",
            "B410": "Use defusedxml to parse untrusted XML.",
            "B411": "Avoid xmlrpc with untrusted data.",
            "B412": "Avoid httpoxy vulnerability — check PROXY env vars.",
            "B413": "Use cryptography library instead of pycrypto.",
            "B501": "Enable SSL/TLS certificate verification.",
            "B502": "Avoid deprecated SSL/TLS protocol versions.",
            "B503": "Avoid deprecated SSL/TLS protocol versions.",
            "B504": "Avoid deprecated SSL/TLS protocol versions.",
            "B505": "Use keys of at least 2048 bits for RSA/DSA.",
            "B506": "Use yaml.safe_load() instead of yaml.load().",
            "B507": "Enable SSH host key verification.",
            "B601": "Validate all input passed to paramiko exec_command().",
            "B602": "Avoid shell=True in subprocess calls with user input.",
            "B603": "Validate all input passed to subprocess calls.",
            "B604": "Validate all input in function calls with shell=True.",
            "B605": "Avoid os.system() — use subprocess with explicit args.",
            "B606": "Avoid os.startfile() with untrusted paths.",
            "B607": "Provide full paths to subprocess executables.",
            "B608": "Use parameterized queries to prevent SQL injection.",
            "B609": "Validate wildcard characters in Linux commands.",
            "B610": "Use Django's ORM instead of extra() with user input.",
            "B611": "Use Django's ORM instead of RawSQL with user input.",
            "B701": "Avoid Jinja2 autoescape=False; enable autoescaping.",
            "B702": "Enable Mako's html_error_template safely.",
            "B703": "Use Django's mark_safe() carefully with user data.",
        }
        return recommendations.get(
            test_id,
            "Review this finding and apply the principle of least privilege.",
        )
