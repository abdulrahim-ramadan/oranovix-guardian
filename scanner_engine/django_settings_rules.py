"""
Security rules for Django settings files.

Applied only to ``settings.py`` and to Python files directly inside a
``settings`` folder.  A setting counts as *missing* only in a file that looks like a
complete settings module; a partial file that star-imports a base module
is checked for the values it sets, not for what it leaves out.
"""
from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Sequence

from .base import Issue, Severity
from .categories import category_for_rule
from .vulnerability_db import VulnerabilityDatabase

_CWE = "https://cwe.mitre.org/data/definitions/{}.html"


@dataclass(frozen=True)
class Setting:
    """One module-level assignment of a settings file."""

    name: str
    value: ast.expr
    line: int

    @property
    def is_constant(self) -> bool:
        return isinstance(self.value, ast.Constant)

    @property
    def constant(self) -> object:
        return self.value.value if isinstance(self.value, ast.Constant) else None

    @property
    def strings(self) -> List[str]:
        """String literals anywhere inside the value."""
        return [
            node.value for node in ast.walk(self.value)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]


class SettingsModule:
    """The settings assigned in one file (the last assignment wins)."""

    _MARKERS = ("INSTALLED_APPS", "MIDDLEWARE", "ROOT_URLCONF")

    def __init__(self, tree: ast.Module) -> None:
        self._settings: Dict[str, Setting] = {}
        self._inherits = False
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
                self._inherits = True
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._add(target, node.value, node.lineno)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._add(node.target, node.value, node.lineno)

    def _add(self, target: ast.AST, value: ast.expr, line: int) -> None:
        if isinstance(target, ast.Name) and target.id.isupper():
            self._settings[target.id] = Setting(target.id, value, line)

    def get(self, name: str) -> Optional[Setting]:
        return self._settings.get(name)

    @property
    def is_complete(self) -> bool:
        """True when a setting that is absent here is absent from the project."""
        return not self._inherits and any(name in self._settings for name in self._MARKERS)


class DjangoSettingsRule(ABC):
    """One check on a Django settings module."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    cwe_id: ClassVar[int]
    description: ClassVar[str]
    recommendation: ClassVar[str]
    confidence: ClassVar[str] = "HIGH"

    @abstractmethod
    def check(self, settings: SettingsModule) -> List[Issue]:
        """Return the issues found in *settings*."""

    def issue(self, line: int, detail: str = "") -> Issue:
        description = f"{self.description} {detail}".strip()
        return Issue(
            rule_id=self.rule_id,
            title=self.title,
            description=description,
            severity=self.severity,
            file_path="",
            line_number=line,
            recommendation=self.recommendation,
            cwe=_CWE.format(self.cwe_id),
            confidence=self.confidence,
            category=category_for_rule(self.rule_id),
        )

    def missing(self, names: Sequence[str]) -> Issue:
        issue = self.issue(1, f"Not set: {', '.join(names)}.")
        issue.code_snippet = f"# not set: {', '.join(names)}"
        return issue


class RequiredFlagsRule(DjangoSettingsRule):
    """Settings that must be present and switched on."""

    flags: ClassVar[Sequence[str]]

    def check(self, settings: SettingsModule) -> List[Issue]:
        issues: List[Issue] = []
        missing: List[str] = []
        for name in self.flags:
            setting = settings.get(name)
            if setting is None:
                missing.append(name)
            elif setting.is_constant and not setting.constant:
                issues.append(self.issue(setting.line, f"{name} is switched off."))
        if missing and settings.is_complete:
            issues.append(self.missing(missing))
        return issues


class RequiredMiddlewareRule(DjangoSettingsRule):
    """A middleware that must be listed in MIDDLEWARE."""

    middleware: ClassVar[str]

    def check(self, settings: SettingsModule) -> List[Issue]:
        setting = settings.get("MIDDLEWARE")
        if setting is None or not isinstance(setting.value, (ast.List, ast.Tuple)):
            return []
        if any(entry.endswith(self.middleware) for entry in setting.strings):
            return []
        return [self.issue(setting.line)]


class WildcardAllowedHostsRule(DjangoSettingsRule):
    rule_id = "DS001"
    title = 'ALLOWED_HOSTS accepts any host ("*")'
    severity = Severity.HIGH
    cwe_id = 644
    description = (
        'ALLOWED_HOSTS contains "*", so Django trusts any Host header. Password-reset '
        "links and cached pages can be poisoned with an attacker's domain."
    )
    recommendation = 'List the real domains: ALLOWED_HOSTS = ["example.com", "www.example.com"].'

    def check(self, settings: SettingsModule) -> List[Issue]:
        setting = settings.get("ALLOWED_HOSTS")
        if setting is not None and "*" in setting.strings:
            return [self.issue(setting.line)]
        return []


class SecureCookiesRule(RequiredFlagsRule):
    rule_id = "DS002"
    title = "Session or CSRF cookie sent without the Secure flag"
    severity = Severity.MEDIUM
    cwe_id = 614
    flags = ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE")
    description = (
        "Without the Secure flag the browser also sends the cookie over plain HTTP, "
        "where anyone on the network can read it and take over the session."
    )
    recommendation = "Set SESSION_COOKIE_SECURE = True and CSRF_COOKIE_SECURE = True in production."


class CsrfMiddlewareRule(RequiredMiddlewareRule):
    rule_id = "DS003"
    title = "CsrfViewMiddleware missing from MIDDLEWARE"
    severity = Severity.HIGH
    cwe_id = 352
    middleware = "CsrfViewMiddleware"
    description = (
        "Without CsrfViewMiddleware no view checks the CSRF token, so other websites "
        "can submit forms with the victim's session."
    )
    recommendation = 'Add "django.middleware.csrf.CsrfViewMiddleware" to MIDDLEWARE.'


class SecurityMiddlewareRule(RequiredMiddlewareRule):
    rule_id = "DS004"
    title = "SecurityMiddleware missing from MIDDLEWARE"
    severity = Severity.MEDIUM
    cwe_id = 693
    middleware = "SecurityMiddleware"
    description = (
        "Without SecurityMiddleware the HTTPS redirect, HSTS and nosniff settings "
        "have no effect."
    )
    recommendation = (
        'Put "django.middleware.security.SecurityMiddleware" first in MIDDLEWARE.'
    )


class CorsAllowAllRule(DjangoSettingsRule):
    rule_id = "DS005"
    title = "CORS allows every origin"
    severity = Severity.HIGH
    cwe_id = 942
    description = (
        "CORS_ALLOW_ALL_ORIGINS = True lets any website call the API from the "
        "visitor's browser and read the response."
    )
    recommendation = 'Use CORS_ALLOWED_ORIGINS = ["https://app.example.com"] instead.'

    _NAMES = ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL")

    def check(self, settings: SettingsModule) -> List[Issue]:
        issues: List[Issue] = []
        for name in self._NAMES:
            setting = settings.get(name)
            if setting is not None and setting.constant is True:
                issues.append(self.issue(setting.line))
        return issues


class HttpsEnforcementRule(RequiredFlagsRule):
    rule_id = "DS006"
    title = "HTTPS is not enforced (SSL redirect / HSTS)"
    severity = Severity.LOW
    cwe_id = 319
    flags = ("SECURE_SSL_REDIRECT", "SECURE_HSTS_SECONDS")
    description = (
        "Without SECURE_SSL_REDIRECT and SECURE_HSTS_SECONDS a first visit over HTTP "
        "stays unencrypted and can be intercepted."
    )
    recommendation = "Set SECURE_SSL_REDIRECT = True and SECURE_HSTS_SECONDS = 31536000 in production."


class DjangoSettingsAnalyzer:
    """Runs the settings rules over one settings file."""

    _RULES: List[DjangoSettingsRule] = [
        WildcardAllowedHostsRule(),
        SecureCookiesRule(),
        CsrfMiddlewareRule(),
        SecurityMiddlewareRule(),
        CorsAllowAllRule(),
        HttpsEnforcementRule(),
    ]

    @staticmethod
    def is_settings_file(file_path: str) -> bool:
        path = Path(file_path)
        if path.suffix.lower() != ".py":
            return False
        return path.name.lower() == "settings.py" or path.parent.name.lower() == "settings"

    @classmethod
    def analyze(cls, code: str, file_path: str) -> List[Issue]:
        """Return the settings issues of *code*; empty for any other file."""
        if not cls.is_settings_file(file_path):
            return []
        try:
            settings = SettingsModule(ast.parse(code))
        except (SyntaxError, ValueError):
            return []

        lines = code.splitlines()
        issues: List[Issue] = []
        for rule in cls._RULES:
            for issue in rule.check(settings):
                issue.file_path = file_path
                if not issue.code_snippet and 1 <= issue.line_number <= len(lines):
                    issue.code_snippet = lines[issue.line_number - 1].strip()
                VulnerabilityDatabase.enrich_issue(issue, issue.rule_id.lower())
                issues.append(issue)
        issues.sort(key=lambda issue: (issue.line_number, issue.rule_id))
        return issues
