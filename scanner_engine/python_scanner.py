"""
Python security scanner: Bandit (run as a library) plus AST and regex checks.

Bandit findings are mapped to ``Issue`` objects with an escalation table
that promotes selected test IDs to CRITICAL or HIGH.  If Bandit cannot
run, the scan continues with the other checks and records a visible
entry in ``ScanResult.engine_warnings``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from .bandit_runner import BanditFinding, BanditRunner, BanditUnavailableError
from .categories import IssueCategory, category_for_rule
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


class PythonScanner(BaseScanner):
    """Scanner for Python source files that combines Bandit with custom regex rules.

    ``PythonScanner`` is the concrete ``BaseScanner`` implementation for Python.
    Bandit runs in-process through ``BanditRunner``; AST rules and regex
    checks cover what Bandit misses.
    """

    SUPPORTED_EXTENSIONS: List[str] = [".py"]

    def __init__(self, bandit_runner: Optional[BanditRunner] = None) -> None:
        super().__init__(name="Python (Bandit)", supported_language=Language.PYTHON)
        self._bandit_runner = bandit_runner or BanditRunner()

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
        """Run Bandit, the regex checks and the AST rules over *target*."""
        from .ast_analyzer import ASTAnalyzer

        files = self.collect_files(target, self.SUPPORTED_EXTENSIONS)
        result.files_scanned = len(files)
        if not files:
            return result

        result.issues.extend(self._run_bandit(files, result))

        seen: set = {
            (i.rule_id, i.file_path, i.line_number) for i in result.issues
        }

        for file_path in files:
            for issue in self._extra_checks(file_path):
                key = (issue.rule_id, issue.file_path, issue.line_number)
                if key not in seen:
                    result.issues.append(issue)
                    seen.add(key)

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
    # Bandit
    # ------------------------------------------------------------------

    def _run_bandit(self, files: List[str], result: ScanResult) -> List[Issue]:
        """Run Bandit on *files*; record a warning instead of failing silently."""
        try:
            report = self._bandit_runner.run(files)
        except BanditUnavailableError as exc:
            result.engine_warnings.append(
                f"Bandit could not run ({exc}). Python results are incomplete: "
                "only the built-in AST and regex checks were applied."
            )
            return []

        if report.skipped_files:
            names = ", ".join(Path(f).name for f in report.skipped_files[:5])
            result.engine_warnings.append(
                f"Bandit could not parse {len(report.skipped_files)} file(s): {names}"
            )
        return [self._issue_from_finding(finding) for finding in report.findings]

    def _issue_from_finding(self, finding: BanditFinding) -> Issue:
        if finding.test_id in _ESCALATE_TO_CRITICAL:
            severity = Severity.CRITICAL
        elif finding.test_id in _ESCALATE_TO_HIGH:
            severity = Severity.HIGH
        else:
            severity = _BANDIT_SEVERITY_MAP.get(finding.severity, Severity.LOW)

        return Issue(
            rule_id=finding.test_id,
            title=finding.test_name.replace("_", " ").title(),
            description=finding.text,
            severity=severity,
            file_path=finding.file_path,
            line_number=finding.line_number,
            code_snippet=finding.code,
            recommendation=self._build_recommendation(finding.test_id),
            cwe=finding.cwe_link,
            confidence=finding.confidence,
            category=category_for_rule(finding.test_id),
        )

    def _extra_checks(self, file_path: str) -> List[Issue]:
        """Regex check for hardcoded credentials (SEC001).

        The former SEC002 open() path-traversal regex is disabled: it could
        not tell user input from safe paths.  It will return as a taint rule.
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
                category=IssueCategory.SECRET,
            ))

        return extra

    @staticmethod
    def _build_recommendation(test_id: str) -> str:
        """Return remediation advice for a Bandit test ID."""
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
