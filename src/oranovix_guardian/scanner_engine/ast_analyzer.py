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
from typing import Dict, FrozenSet, List, Optional

from .base import Issue, Severity
from .categories import IssueCategory
from .secret_heuristics import SecretHeuristics

# Variable names that suggest a secret. Shared with ``core.redactor``.
SECRET_VARIABLE_NAMES: frozenset = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key",
    "secret_key", "api_secret", "client_secret",
})


# ---------------------------------------------------------------------------
# What the whole module tells a rule
# ---------------------------------------------------------------------------

class ModuleContext:
    """Facts about the whole module that a single node cannot show.

    ``bound`` holds every name the module binds itself: imports, function
    and class names, parameters, assignment targets. A call to such a name
    is not a call to the builtin of the same name (``from re import
    compile``). ``from builtins import eval`` still means the builtin.
    """

    def __init__(self, tree: Optional[ast.AST] = None) -> None:
        self.bound: FrozenSet[str] = self._bound_names(tree) if tree is not None else frozenset()
        #: Names that hold the builtins module: ``builtins``, ``__builtins__``,
        #: and ``b`` after ``import builtins as b``.
        self.builtin_modules: FrozenSet[str] = BUILTIN_MODULE_NAMES
        #: Names that hold eval/exec/compile: ``e = eval``,
        #: ``fn = getattr(__builtins__, "exec")``, ``from builtins import eval as ev``.
        self.aliases: Dict[str, str] = {}
        if tree is not None:
            self._find_aliases(tree)

    def _find_aliases(self, tree: ast.AST) -> None:
        modules = set(BUILTIN_MODULE_NAMES)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "builtins" and alias.asname:
                        modules.add(alias.asname)
            elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
                for alias in node.names:
                    if alias.name in DANGEROUS_BUILTINS and alias.asname:
                        self.aliases[alias.asname] = alias.name
        self.builtin_modules = frozenset(modules)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
        for _ in range(3):              # e = eval; f = e: both are eval
            for node in assignments:
                name = dangerous_reference(node.value, self)
                if name is None:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = name

    @staticmethod
    def _bound_names(tree: ast.AST) -> FrozenSet[str]:
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if node.module == "builtins" and alias.asname is None:
                        continue
                    names.add(alias.asname or alias.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                names.add(node.name)
        return frozenset(names)


DANGEROUS_BUILTINS: FrozenSet[str] = frozenset({"eval", "exec", "compile"})
BUILTIN_MODULE_NAMES: FrozenSet[str] = frozenset({"builtins", "__builtins__"})
_NAMESPACE_CALLS: FrozenSet[str] = frozenset({"globals", "vars", "locals"})


def _constant_text(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def is_builtins_module(expr: ast.AST, context: "ModuleContext") -> bool:
    """``builtins``, an alias of it, ``globals()["__builtins__"]`` or ``__import__("builtins")``."""
    if isinstance(expr, ast.Name):
        return expr.id in context.builtin_modules
    if isinstance(expr, ast.Subscript):
        holder = expr.value
        return (
            _constant_text(expr.slice) == "__builtins__"
            and isinstance(holder, ast.Call)
            and isinstance(holder.func, ast.Name)
            and holder.func.id in _NAMESPACE_CALLS
        )
    if isinstance(expr, ast.Call) and expr.args:
        func = expr.func
        importer = (
            (isinstance(func, ast.Name) and func.id == "__import__")
            or (isinstance(func, ast.Attribute) and func.attr == "import_module")
        )
        return importer and _constant_text(expr.args[0]) == "builtins"
    return False


def builtin_lookup(expr: ast.AST, context: "ModuleContext") -> Optional[str]:
    """eval/exec/compile taken from the builtins module, however it is spelled."""
    if isinstance(expr, ast.Attribute) and expr.attr in DANGEROUS_BUILTINS:
        return expr.attr if is_builtins_module(expr.value, context) else None
    if isinstance(expr, ast.Subscript):
        key = _constant_text(expr.slice)
        if key in DANGEROUS_BUILTINS and is_builtins_module(expr.value, context):
            return key
        return None
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "getattr"
        and len(expr.args) >= 2
    ):
        key = _constant_text(expr.args[1])
        if key in DANGEROUS_BUILTINS and is_builtins_module(expr.args[0], context):
            return key
    return None


def dangerous_reference(expr: ast.AST, context: "ModuleContext") -> Optional[str]:
    """The builtin eval/exec/compile that *expr* stands for, or ``None``."""
    if isinstance(expr, ast.Name):
        if expr.id in context.aliases:
            return context.aliases[expr.id]
        if expr.id in DANGEROUS_BUILTINS and expr.id not in context.bound:
            return expr.id
        return None
    return builtin_lookup(expr, context)


EMPTY_CONTEXT = ModuleContext()


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

    def check_in(self, node: ast.AST, context: ModuleContext) -> List[Issue]:
        """Like ``check``, with facts about the whole module. Rules that need
        them override this; the others ignore the context."""
        return self.check(node)


# ---------------------------------------------------------------------------
# Concrete rule: dangerous built-in functions
# ---------------------------------------------------------------------------

class DangerousFunctionRule(ASTRule):
    """Detects calls to the builtins eval(), exec() and compile().

    Only the builtins count: a bare name the module does not bind itself,
    or ``builtins.eval`` / ``__builtins__.eval``. Methods with the same
    name (``re.compile``, ``model.eval()``, ``df.eval``, ``pattern.exec``)
    and names the module imports or assigns (``from re import compile``)
    are other functions. Unlike regex scanners, the AST also ignores the
    words in comments, docstrings and string literals.

    A call on a constant string is MEDIUM: the code is fixed in the
    source. Anything else (a variable, an f-string, request data) is
    CRITICAL.
    """

    _DANGEROUS: FrozenSet[str] = DANGEROUS_BUILTINS
    _BUILTIN_MODULES: FrozenSet[str] = BUILTIN_MODULE_NAMES

    def check(self, node: ast.AST) -> List[Issue]:
        return self.check_in(node, EMPTY_CONTEXT)

    def check_in(self, node: ast.AST, context: ModuleContext) -> List[Issue]:
        if isinstance(node, ast.Assign):
            # fn = getattr(__builtins__, "exec"): hiding the builtin behind a
            # lookup is itself the finding, wherever fn is called later.
            hidden = builtin_lookup(node.value, context)
            if hidden is None or isinstance(node.value, ast.Attribute):
                return []
            return [self._issue(hidden, node, constant=False)]
        if not isinstance(node, ast.Call):
            return []
        func_name = self._builtin_name(node.func, context)
        if func_name is None:
            return []
        return [self._issue(func_name, node, self.constant_source(node))]

    def _issue(self, func_name: str, node: ast.AST, constant: bool) -> Issue:
        severity = Severity.MEDIUM if constant else Severity.CRITICAL
        if constant:
            description = (
                f"{func_name}() runs code given as a constant string. The code is fixed in "
                "the source, so an attacker cannot change it, but the call is hard to review "
                "and easy to turn into a vulnerability later."
            )
        else:
            description = (
                f"{func_name}() executes arbitrary Python code at runtime. "
                "If the argument is derived from user input, an attacker can "
                "execute arbitrary Python and gain full system access."
            )
        return Issue(
            rule_id=f"AST-{func_name.upper()[:3]}",
            title=f"Dangerous Function Call: {func_name}()",
            description=description,
            severity=severity,
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
        )

    @staticmethod
    def _builtin_name(func: ast.expr, context: ModuleContext) -> Optional[str]:
        """The builtin a call goes to: by name, by alias, or looked up on builtins."""
        return dangerous_reference(func, context)

    @staticmethod
    def constant_source(call: ast.Call) -> bool:
        """``True`` when the code argument is a string (or bytes) literal."""
        source: Optional[ast.expr] = call.args[0] if call.args else None
        if source is None:
            source = next((k.value for k in call.keywords if k.arg in ("source", "expression")), None)
        return isinstance(source, ast.Constant) and isinstance(source.value, (str, bytes))


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

    Only flags assignments where the RHS is a string constant that looks
    like a real secret (``SecretHeuristics``): placeholders such as
    ``token = "test"``, short values, URLs and paths are skipped.
    """

    _SECRET_NAMES: frozenset = SECRET_VARIABLE_NAMES

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
            if not isinstance(value.value, str) or not SecretHeuristics.is_secret(var_name, value.value):
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
        # hashlib.md5(data, usedforsecurity=False): a checksum, not security.
        if any(
            k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in node.keywords
        ):
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
        context = ModuleContext(tree)

        for node in ast.walk(tree):
            for rule in cls._RULES:
                found = rule.check_in(node, context)
                for issue in found:
                    # Patch file_path and code_snippet which the rules leave blank
                    issue.file_path = file_path
                    ln = issue.line_number
                    if ln and 1 <= ln <= len(lines):
                        issue.code_snippet = lines[ln - 1].strip()
                    issues.append(issue)

        return issues
