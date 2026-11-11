"""
AST-based security analyzer for Python source code.

Uses Python's built-in ``ast`` module (zero external dependencies) to
inspect the abstract syntax tree of Python files, catching vulnerabilities
that regex scanners can miss (e.g. SQL injection via f-strings vs string
literals, actual function calls vs occurrences in comments/strings).

Architecture:
  - ASTRule (ABC) — base class for a single tree-inspection rule.
  - Five concrete rules covering the most impactful Python issues.
  - ASTAnalyzer — orchestrates parse → walk → apply rules.

Version: 1.0.0
"""
from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import List

from .base import Issue, Severity
from .categories import IssueCategory


# ---------------------------------------------------------------------------
# Abstract base for AST rules
# ---------------------------------------------------------------------------

class ASTRule(ABC):
    """Abstract base class for a single AST-based security inspection rule.

    Concrete subclasses receive each AST node and return any issues found.
    The check method must be side-effect-free and handle every node type
    gracefully (most nodes will simply return an empty list).
    """

    @abstractmethod
    def check(self, node: ast.AST) -> List[Issue]:
        """Inspect one AST node and return any security issues found.

        Args:
            node: A single AST node produced by ast.walk().

        Returns:
            A list of Issue objects; empty if the node is clean or not
            relevant to this rule.
        """


# ---------------------------------------------------------------------------
# Concrete rule: dangerous built-in functions
# ---------------------------------------------------------------------------

class DangerousFunctionRule(ASTRule):
    """Detects calls to eval(), exec(), and compile().

    Unlike regex scanners these calls are detected by examining actual
    Call nodes in the AST, so occurrences inside comments, docstrings, or
    string literals are correctly ignored.
    """

    _DANGEROUS: set = {"eval", "exec", "compile"}

    def check(self, node: ast.AST) -> List[Issue]:
        if not isinstance(node, ast.Call):
            return []

        # Resolve the function name — handle both bare names and attribute access
        func_name: str | None = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name is None or func_name not in self._DANGEROUS:
            return []

        return [Issue(
            rule_id=f"AST-{func_name.upper()[:3]}",
            title=f"Dangerous Function Call: {func_name}()",
            description=(
                f"{func_name}() executes arbitrary Python code at runtime. "
                "If the argument is derived from user input, an attacker can "
                "execute arbitrary Python and gain full system access."
            ),
            severity=Severity.CRITICAL,
            file_path="",        # populated by ASTAnalyzer.analyze()
            line_number=getattr(node, "lineno", 0),
            code_snippet="",
            recommendation=(
                f"Replace {func_name}() with a safe alternative: "
                "ast.literal_eval() for Python literals, json.loads() for JSON, "
                "or subprocess.run(['cmd', ...]) for shell commands."
            ),
            cwe="https://cwe.mitre.org/data/definitions/78.html",
            category=IssueCategory.CODE_EXEC,
            confidence="HIGH",
        )]


# ---------------------------------------------------------------------------
# Concrete rule: SQL injection via cursor.execute()
# ---------------------------------------------------------------------------

class SQLInjectionRule(ASTRule):
    """Detects string formatting inside DB cursor.execute() calls.

    Matches any .execute() call whose first argument is an f-string,
    a .format() call, or a + concatenation — all common patterns for
    constructing dynamic SQL from user input.
    """

    def check(self, node: ast.AST) -> List[Issue]:
        if not isinstance(node, ast.Call):
            return []
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"):
            return []
        if not node.args:
            return []

        arg = node.args[0]
        is_fstring = isinstance(arg, ast.JoinedStr)
        is_format = (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"
        )
        is_concat = isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add)

        if not (is_fstring or is_format or is_concat):
            return []

        return [Issue(
            rule_id="AST-SQL1",
            title="SQL Injection via String Formatting in execute()",
            description=(
                "cursor.execute() is called with a dynamically constructed "
                "SQL string (f-string, .format(), or + concatenation). "
                "An attacker can inject arbitrary SQL to dump, modify, or "
                "delete database contents."
            ),
            severity=Severity.CRITICAL,
            file_path="",
            line_number=getattr(node, "lineno", 0),
            code_snippet="",
            recommendation=(
                "Use parameterized queries: pass a query with ? or %s "
                "placeholders and supply values as a tuple — "
                "cursor.execute('SELECT … WHERE id = ?', (user_id,)). "
                "Never build SQL by string interpolation."
            ),
            cwe="https://cwe.mitre.org/data/definitions/89.html",
            category=IssueCategory.SQL_INJECTION,
            confidence="HIGH",
        )]


# ---------------------------------------------------------------------------
# Concrete rule: hardcoded secrets in assignments
# ---------------------------------------------------------------------------

class HardcodedSecretsRule(ASTRule):
    """Detects variable assignments where the name suggests a secret.

    Only flags assignments where the RHS is a non-empty string constant
    of at least 4 characters, avoiding false positives from placeholder
    values like password = "" or token = None.
    """

    _SECRET_NAMES: set = {
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "token", "auth_token", "access_token", "private_key",
        "secret_key", "api_secret", "client_secret",
    }

    def check(self, node: ast.AST) -> List[Issue]:
        if not isinstance(node, ast.Assign):
            return []

        for target in node.targets:
            var_name: str | None = None
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
            elif isinstance(target, ast.Attribute):
                var_name = target.attr.lower()

            if var_name is None or var_name not in self._SECRET_NAMES:
                continue

            value = node.value
            if not isinstance(value, ast.Constant):
                continue
            if not isinstance(value.value, str) or len(value.value) < 4:
                continue

            return [Issue(
                rule_id="AST-SEC1",
                title=f"Hardcoded Secret in Variable '{var_name}'",
                description=(
                    f"Variable '{var_name}' is assigned a hardcoded string "
                    "literal. Hardcoded credentials can be extracted from "
                    "version control history and compiled binaries."
                ),
                severity=Severity.CRITICAL,
                file_path="",
                line_number=getattr(node, "lineno", 0),
                code_snippet="",
                recommendation=(
                    f"Replace the hardcoded value with an environment variable: "
                    f"import os; {var_name} = os.environ.get('{var_name.upper()}'). "
                    "Use a secrets manager for production deployments."
                ),
                cwe="https://cwe.mitre.org/data/definitions/798.html",
                category=IssueCategory.SECRET,
                confidence="HIGH",
            )]

        return []


# ---------------------------------------------------------------------------
# Concrete rule: insecure module imports
# ---------------------------------------------------------------------------

class InsecureImportRule(ASTRule):
    """Detects imports of modules that allow arbitrary code execution."""

    _DANGEROUS_MODULES: dict = {
        "pickle":  "pickle allows arbitrary code execution during deserialization.",
        "marshal": "marshal allows arbitrary code execution during deserialization.",
        "shelve":  "shelve uses pickle internally and inherits all its risks.",
    }

    def check(self, node: ast.AST) -> List[Issue]:
        module = ""
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]
                if module in self._DANGEROUS_MODULES:
                    return [self._make_issue(module, node)]
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in self._DANGEROUS_MODULES:
                return [self._make_issue(module, node)]
        return []

    def _make_issue(self, module: str, node: ast.AST) -> Issue:
        reason = self._DANGEROUS_MODULES[module]
        return Issue(
            rule_id="AST-IMP1",
            title=f"Insecure Module Import: {module}",
            description=(
                f"Module '{module}' is imported. {reason} "
                "Loading untrusted data with this module can lead to "
                "arbitrary code execution on the server."
            ),
            severity=Severity.HIGH,
            file_path="",
            line_number=getattr(node, "lineno", 0),
            code_snippet="",
            recommendation=(
                f"Replace '{module}' with a safe serialization format: "
                "json.dumps()/json.loads() for data exchange, or "
                "msgpack / protobuf for binary formats."
            ),
            cwe="https://cwe.mitre.org/data/definitions/502.html",
            category=IssueCategory.INSECURE_IMPORT,
            confidence="HIGH",
        )


# ---------------------------------------------------------------------------
# Concrete rule: weak cryptographic hashes
# ---------------------------------------------------------------------------

class WeakCryptoRule(ASTRule):
    """Detects calls to hashlib.md5() and hashlib.sha1().

    Both MD5 and SHA-1 are cryptographically broken and should not be used
    for security-sensitive operations (password storage, integrity checks).
    """

    _WEAK: set = {"md5", "sha1"}

    def check(self, node: ast.AST) -> List[Issue]:
        if not isinstance(node, ast.Call):
            return []
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr in self._WEAK):
            return []
        # Only flag hashlib.md5 / hashlib.sha1 (not arbitrary .md5() methods)
        if not (isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"):
            return []

        algo = node.func.attr
        return [Issue(
            rule_id="AST-CRY1",
            title=f"Weak Cryptographic Hash: hashlib.{algo}()",
            description=(
                f"hashlib.{algo}() uses {algo.upper()} which is cryptographically "
                "broken and vulnerable to collision attacks. It should not be "
                "used for any security-sensitive hashing."
            ),
            severity=Severity.HIGH,
            file_path="",
            line_number=getattr(node, "lineno", 0),
            code_snippet="",
            recommendation=(
                f"Replace hashlib.{algo}() with hashlib.sha256() or "
                "hashlib.sha3_256() for general hashing. "
                "For password storage use bcrypt, argon2-cffi, or "
                "hashlib.scrypt()."
            ),
            cwe="https://cwe.mitre.org/data/definitions/327.html",
            category=IssueCategory.WEAK_CRYPTO,
            confidence="HIGH",
        )]


# ---------------------------------------------------------------------------
# ASTAnalyzer orchestrator
# ---------------------------------------------------------------------------

class ASTAnalyzer:
    """Analyzes Python source using all registered ASTRule implementations.

    Usage::

        issues = ASTAnalyzer.analyze(source_code, file_path="/path/to/file.py")

    The class method parses the source with ast.parse(), walks every node with
    ast.walk(), and applies each rule to each node. file_path and code_snippet
    are populated on every returned Issue before returning.
    """

    _RULES: List[ASTRule] = [
        DangerousFunctionRule(),
        SQLInjectionRule(),
        HardcodedSecretsRule(),
        InsecureImportRule(),
        WeakCryptoRule(),
    ]

    @classmethod
    def analyze(cls, code: str, file_path: str = "") -> List[Issue]:
        """Parse Python source and return all security issues found.

        Args:
            code:      Python source code as a plain string.
            file_path: Absolute path to the source file; used to populate
                       Issue.file_path on each returned issue.

        Returns:
            A list of Issue objects.  Empty if the code is clean, cannot be
            parsed (SyntaxError), or no rules match.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        lines = code.splitlines()
        issues: List[Issue] = []

        for node in ast.walk(tree):
            for rule in cls._RULES:
                found = rule.check(node)
                for issue in found:
                    # Patch file_path and code_snippet which the rules leave blank
                    issue.file_path = file_path
                    ln = issue.line_number
                    if ln and 1 <= ln <= len(lines):
                        issue.code_snippet = lines[ln - 1].strip()
                    issues.append(issue)

        return issues
