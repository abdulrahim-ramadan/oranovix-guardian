"""
Security rules for Django and Django REST Framework view code.

Every rule is one ``DjangoRule`` subclass.  ``DjangoAnalyzer`` parses a
file, builds one ``TaintTracker`` per scope (the module and each
function) and hands every scope to every rule.
"""
from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import ClassVar, FrozenSet, Iterator, List, Optional, Sequence, Set, Tuple

from .base import Issue, Severity
from .categories import IssueCategory, category_for_rule
from .taint import TaintTracker, dotted_name, is_request
from .vulnerability_db import VulnerabilityDatabase

_FunctionNode = (ast.FunctionDef, ast.AsyncFunctionDef)
_CWE = "https://cwe.mitre.org/data/definitions/{}.html"


def _last_name(node: ast.AST) -> str:
    """Last part of a dotted name: ``permissions.AllowAny`` gives ``AllowAny``."""
    return dotted_name(node).rsplit(".", 1)[-1]


def _argument(call: ast.Call, index: int, *keywords: str) -> Optional[ast.expr]:
    if len(call.args) > index:
        return call.args[index]
    for item in call.keywords:
        if item.arg in keywords:
            return item.value
    return None


def _mentions_request_user(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Attribute) and child.attr == "user" and is_request(child.value)
        for child in ast.walk(node)
    )


def _permission_classes(value: ast.AST) -> List[str]:
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return [_last_name(element) for element in value.elts]
    return []


def _assigned_value(body: Sequence[ast.stmt], name: str) -> Optional[ast.Assign]:
    for statement in body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            return statement
    return None


# ---------------------------------------------------------------------------
# Base classes
# ---------------------------------------------------------------------------

class DjangoRule(ABC):
    """One Django security check."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    cwe_id: ClassVar[int]
    description: ClassVar[str]
    recommendation: ClassVar[str]
    confidence: ClassVar[str] = "MEDIUM"

    @abstractmethod
    def check(self, tree: ast.AST, tracker: TaintTracker) -> List[Issue]:
        """Return the issues found in *tree*, the scope *tracker* was built for."""

    @property
    def category(self) -> IssueCategory:
        return category_for_rule(self.rule_id)

    def issue(self, node: ast.AST) -> Issue:
        return Issue(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            file_path="",
            line_number=getattr(node, "lineno", 0),
            recommendation=self.recommendation,
            cwe=_CWE.format(self.cwe_id),
            confidence=self.confidence,
            category=self.category,
        )


class ModuleRule(DjangoRule):
    """A rule that looks at the structure of the whole file once."""

    def check(self, tree: ast.AST, tracker: TaintTracker) -> List[Issue]:
        if not isinstance(tree, ast.Module):
            return []
        return self.check_module(tree)

    @abstractmethod
    def check_module(self, module: ast.Module) -> List[Issue]:
        """Return the issues found in *module*."""


class TaintSinkRule(DjangoRule):
    """Reports a dangerous call that receives request data."""

    def check(self, tree: ast.AST, tracker: TaintTracker) -> List[Issue]:
        return [
            self.issue(call)
            for call in tracker.calls()
            if any(tracker.is_tainted(value) for value in self.dangerous_arguments(call))
        ]

    @abstractmethod
    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        """Arguments of *call* that must not be tainted; empty if it is no sink."""


# ---------------------------------------------------------------------------
# DJ001 - DJ010
# ---------------------------------------------------------------------------

class CsrfExemptRule(ModuleRule):
    rule_id = "DJ001"
    title = "CSRF protection disabled with @csrf_exempt"
    severity = Severity.HIGH
    cwe_id = 352
    confidence = "HIGH"
    description = (
        "The view is decorated with csrf_exempt, so Django accepts state-changing "
        "requests that another website sends with the victim's session cookie."
    )
    recommendation = (
        "Remove csrf_exempt and send the CSRF token with the request. For webhooks, "
        "verify a signature of the payload instead."
    )

    def check_module(self, module: ast.Module) -> List[Issue]:
        issues: List[Issue] = []
        for node in ast.walk(module):
            if not isinstance(node, (*_FunctionNode, ast.ClassDef)):
                continue
            for decorator in node.decorator_list:
                if any(_last_name(child) == "csrf_exempt" for child in ast.walk(decorator)):
                    issues.append(self.issue(decorator))
        return issues


class SsrfRule(TaintSinkRule):
    rule_id = "DJ002"
    title = "Server-side request forgery (SSRF)"
    severity = Severity.CRITICAL
    cwe_id = 918
    description = (
        "The server sends an HTTP request to a URL taken from the request. An attacker "
        "can reach internal services and cloud metadata endpoints through the server."
    )
    recommendation = (
        "Do not fetch user-supplied URLs. Map a user-supplied key to a fixed URL, or "
        "check the host against an allowlist before the request."
    )

    _CLIENTS: FrozenSet[str] = frozenset({"requests", "httpx"})
    _METHODS: FrozenSet[str] = frozenset({
        "get", "post", "put", "patch", "delete", "head", "options", "request", "stream",
    })

    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        name = dotted_name(call.func)
        root, _, method = name.rpartition(".")
        if method == "urlopen":
            url = _argument(call, 0, "url")
        elif root in self._CLIENTS and method in self._METHODS:
            url = _argument(call, 1 if method in ("request", "stream") else 0, "url")
        else:
            url = None
        return [url] if url is not None else []


class OpenRedirectRule(TaintSinkRule):
    rule_id = "DJ003"
    title = "Open redirect"
    severity = Severity.HIGH
    cwe_id = 601
    description = (
        "The redirect target comes from the request. A link to this site can send "
        "the victim to an attacker's page, which makes phishing convincing."
    )
    recommendation = (
        "Check the target with url_has_allowed_host_and_scheme() before redirecting "
        "and fall back to a fixed URL."
    )

    _REDIRECTS: FrozenSet[str] = frozenset({
        "redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect",
    })

    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        if _last_name(call.func) not in self._REDIRECTS:
            return []
        target = _argument(call, 0, "to", "redirect_to")
        return [target] if target is not None else []


class PathTraversalRule(TaintSinkRule):
    rule_id = "DJ004"
    title = "Path traversal"
    severity = Severity.CRITICAL
    cwe_id = 22
    description = (
        "A file path is built from request data. With ../ sequences or an absolute "
        "path an attacker can read or overwrite files outside the intended folder."
    )
    recommendation = (
        "Keep only the file name with os.path.basename() or get_valid_filename() and "
        "join it to a fixed base directory."
    )

    _PATH_CLASSES: FrozenSet[str] = frozenset({"Path", "PurePath"})
    _PATH_METHODS: FrozenSet[str] = frozenset({
        "read_text", "read_bytes", "write_text", "write_bytes",
    })

    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        name = dotted_name(call.func)
        last = name.rsplit(".", 1)[-1]
        if name in ("open", "io.open") or last == "FileResponse":
            path = _argument(call, 0, "file")
            return [path] if path is not None else []
        if last in self._PATH_CLASSES:
            return call.args
        if isinstance(call.func, ast.Attribute) and call.func.attr in self._PATH_METHODS:
            return [call.func.value]
        return []


class ReflectedXssRule(TaintSinkRule):
    rule_id = "DJ005"
    title = "Reflected cross-site scripting (XSS)"
    severity = Severity.HIGH
    cwe_id = 79
    description = (
        "Request data is written into an HTML response without escaping. Script in "
        "a crafted link runs in the victim's browser with the victim's session."
    )
    recommendation = (
        "Render a template (auto-escaped) or pass the value through "
        "django.utils.html.escape(). Never call mark_safe() on user input."
    )

    _RESPONSES: FrozenSet[str] = frozenset({
        "HttpResponse", "HttpResponseBadRequest", "HttpResponseNotFound",
        "HttpResponseForbidden", "HttpResponseServerError",
    })

    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        last = _last_name(call.func)
        if last == "mark_safe":
            return call.args[:1]
        if last in self._RESPONSES and self._serves_html(call):
            content = _argument(call, 0, "content")
            return [content] if content is not None else []
        return []

    @staticmethod
    def _serves_html(call: ast.Call) -> bool:
        content_type = _argument(call, 1, "content_type")
        if isinstance(content_type, ast.Constant) and isinstance(content_type.value, str):
            return "html" in content_type.value.lower()
        return True


class RawSqlRule(TaintSinkRule):
    rule_id = "DJ006"
    title = "SQL injection through raw SQL"
    severity = Severity.CRITICAL
    cwe_id = 89
    description = (
        "Request data is part of the SQL text passed to raw(), extra(), RawSQL() or "
        "cursor.execute(). An attacker can change the query and read or modify any table."
    )
    recommendation = (
        "Keep the SQL text constant and pass values as parameters: "
        'cursor.execute("... WHERE id = %s", [value]). Prefer the ORM.'
    )

    _EXECUTE: FrozenSet[str] = frozenset({"execute", "executemany", "executescript"})

    def dangerous_arguments(self, call: ast.Call) -> Sequence[ast.expr]:
        if _last_name(call.func) == "RawSQL":
            return call.args[:1]
        if not isinstance(call.func, ast.Attribute):
            return []
        method = call.func.attr
        if method == "raw" or method in self._EXECUTE:
            query = _argument(call, 0, "raw_query", "sql", "query")
            return [query] if query is not None else []
        if method == "extra":
            return [*call.args, *(keyword.value for keyword in call.keywords)]
        return []


class JwtVerificationRule(ModuleRule):
    rule_id = "DJ007"
    title = "JWT signature verification disabled"
    severity = Severity.CRITICAL
    cwe_id = 347
    confidence = "HIGH"
    description = (
        "The token is accepted without a verified signature (verify_signature False "
        'or algorithm "none"). Anyone can forge a token for any user.'
    )
    recommendation = (
        'Always verify the signature and pin the algorithm: jwt.decode(token, key, '
        'algorithms=["HS256"]).'
    )

    _ALGORITHM_KEYS: FrozenSet[str] = frozenset({"algorithm", "algorithms"})

    def check_module(self, module: ast.Module) -> List[Issue]:
        issues: List[Issue] = []
        for node in ast.walk(module):
            if isinstance(node, ast.Dict) and self._insecure_dict(node):
                issues.append(self.issue(node))
            elif isinstance(node, ast.Call) and self._insecure_call(node):
                issues.append(self.issue(node))
        return issues

    def _insecure_dict(self, node: ast.Dict) -> bool:
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if key.value == "verify_signature" and self._is_false(value):
                return True
            if key.value.lower() in self._ALGORITHM_KEYS and self._has_none(value):
                return True
        return False

    def _insecure_call(self, node: ast.Call) -> bool:
        if _last_name(node.func) not in ("decode", "encode"):
            return False
        for keyword in node.keywords:
            if keyword.arg in self._ALGORITHM_KEYS and self._has_none(keyword.value):
                return True
            if keyword.arg == "verify" and self._is_false(keyword.value):
                return True
        return False

    @staticmethod
    def _is_false(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is False

    @staticmethod
    def _has_none(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and child.value.lower() == "none"
            for child in ast.walk(node)
        )


class AllowAnyWriteRule(ModuleRule):
    rule_id = "DJ008"
    title = "DRF write endpoint open to everyone (AllowAny)"
    severity = Severity.HIGH
    cwe_id = 306
    description = (
        "permission_classes contains AllowAny on a view that creates, changes or "
        "deletes data. Anonymous users can modify records."
    )
    recommendation = (
        "Use IsAuthenticated plus an object-level permission, or "
        "IsAuthenticatedOrReadOnly when reading must stay public."
    )

    _WRITE_BASES: FrozenSet[str] = frozenset({
        "ModelViewSet", "CreateAPIView", "UpdateAPIView", "DestroyAPIView",
        "ListCreateAPIView", "RetrieveUpdateAPIView", "RetrieveDestroyAPIView",
        "RetrieveUpdateDestroyAPIView", "CreateModelMixin", "UpdateModelMixin",
        "DestroyModelMixin",
    })
    _WRITE_HANDLERS: FrozenSet[str] = frozenset({
        "post", "put", "patch", "delete", "create", "update", "partial_update", "destroy",
    })
    _SAFE_METHODS: FrozenSet[str] = frozenset({"GET", "HEAD", "OPTIONS"})

    def check_module(self, module: ast.Module) -> List[Issue]:
        issues: List[Issue] = []
        for node in ast.walk(module):
            if isinstance(node, ast.ClassDef):
                assignment = _assigned_value(node.body, "permission_classes")
                if (
                    assignment is not None
                    and "AllowAny" in _permission_classes(assignment.value)
                    and self._is_write_class(node)
                ):
                    issues.append(self.issue(assignment))
            elif isinstance(node, _FunctionNode):
                decorator = self._open_write_decorator(node)
                if decorator is not None:
                    issues.append(self.issue(decorator))
        return issues

    def _is_write_class(self, node: ast.ClassDef) -> bool:
        if any(_last_name(base) in self._WRITE_BASES for base in node.bases):
            return True
        return any(
            isinstance(member, _FunctionNode) and member.name in self._WRITE_HANDLERS
            for member in node.body
        )

    def _open_write_decorator(self, node: ast.AST) -> Optional[ast.expr]:
        allow_any: Optional[ast.expr] = None
        writes = False
        for decorator in node.decorator_list:  # type: ignore[attr-defined]
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            name = _last_name(decorator.func)
            if name == "permission_classes" and "AllowAny" in _permission_classes(decorator.args[0]):
                allow_any = decorator
            elif name == "api_view":
                methods = {
                    element.value.upper()
                    for element in getattr(decorator.args[0], "elts", [])
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                }
                writes = bool(methods - self._SAFE_METHODS)
        return allow_any if writes else None


class SerializerAllFieldsRule(ModuleRule):
    rule_id = "DJ009"
    title = 'DRF serializer exposes every model field (fields = "__all__")'
    severity = Severity.MEDIUM
    cwe_id = 915
    confidence = "HIGH"
    description = (
        'fields = "__all__" returns and accepts every column of the model, including '
        "ones added later (password hashes, is_staff, internal notes)."
    )
    recommendation = (
        "List the fields explicitly and mark server-controlled ones as read_only_fields."
    )

    def check_module(self, module: ast.Module) -> List[Issue]:
        issues: List[Issue] = []
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any("Serializer" in _last_name(base) for base in node.bases):
                continue
            for member in node.body:
                if isinstance(member, ast.ClassDef) and member.name == "Meta":
                    assignment = _assigned_value(member.body, "fields")
                    if (
                        assignment is not None
                        and isinstance(assignment.value, ast.Constant)
                        and assignment.value.value == "__all__"
                    ):
                        issues.append(self.issue(assignment))
        return issues


class IdorRule(ModuleRule):
    rule_id = "DJ010"
    title = "Possible IDOR: object loaded by id without an owner check"
    severity = Severity.HIGH
    cwe_id = 639
    confidence = "LOW"
    description = (
        "A view loads an object by pk/id and the lookup is not limited to "
        "request.user, and no permission check was found. Any logged-in user may be "
        "able to open other users' records by changing the id. Heuristic: needs review."
    )
    recommendation = (
        "Limit the lookup to the current user, for example "
        "get_object_or_404(Invoice, pk=pk, owner=request.user), or check an object "
        "permission before using the object."
    )

    _ID_LOOKUPS: FrozenSet[str] = frozenset({"pk", "id"})
    _SHORTCUTS: FrozenSet[str] = frozenset({"get_object_or_404", "aget_object_or_404"})
    _PERMISSION_DECORATORS: FrozenSet[str] = frozenset({
        "permission_required", "user_passes_test", "staff_member_required",
        "superuser_required",
    })
    _PERMISSION_NAMES: FrozenSet[str] = frozenset({
        "has_perm", "has_perms", "has_permission", "has_object_permission",
        "check_object_permissions", "PermissionDenied", "is_staff", "is_superuser",
    })
    _PERMISSION_MIXINS: FrozenSet[str] = frozenset({
        "PermissionRequiredMixin", "UserPassesTestMixin",
    })
    # DRF classes that say who may log in, not which object they may open.
    _NOT_OBJECT_LEVEL: FrozenSet[str] = frozenset({
        "AllowAny", "IsAuthenticated", "IsAuthenticatedOrReadOnly",
    })

    def check_module(self, module: ast.Module) -> List[Issue]:
        issues: List[Issue] = []
        for owner, view in self._views(module, None):
            if self._function_checks_permission(view):
                continue
            if owner is not None and self._class_checks_permission(owner):
                continue
            issues.extend(
                self.issue(node)
                for node in ast.walk(view)
                if isinstance(node, ast.Call) and self._is_unscoped_lookup(node)
            )
        return issues

    def _views(
        self, node: ast.AST, owner: Optional[ast.ClassDef]
    ) -> Iterator[Tuple[Optional[ast.ClassDef], ast.AST]]:
        for child in getattr(node, "body", []):
            if isinstance(child, ast.ClassDef):
                yield from self._views(child, child)
            elif isinstance(child, _FunctionNode) and self._is_view(child):
                yield owner, child

    @staticmethod
    def _is_view(function: ast.AST) -> bool:
        arguments = function.args  # type: ignore[attr-defined]
        names = {arg.arg for arg in (*arguments.posonlyargs, *arguments.args)}
        if "request" in names:
            return True
        return "self" in names and any(
            isinstance(child, ast.Attribute) and child.attr == "request"
            for child in ast.walk(function)
        )

    def _is_unscoped_lookup(self, call: ast.Call) -> bool:
        function = call.func
        is_manager_get = (
            isinstance(function, ast.Attribute)
            and function.attr == "get"
            and isinstance(function.value, ast.Attribute)
            and function.value.attr == "objects"
        )
        if not is_manager_get and _last_name(function) not in self._SHORTCUTS:
            return False
        if not any(keyword.arg in self._ID_LOOKUPS for keyword in call.keywords):
            return False
        return not _mentions_request_user(call)

    def _function_checks_permission(self, function: ast.AST) -> bool:
        for decorator in function.decorator_list:  # type: ignore[attr-defined]
            names = {_last_name(child) for child in ast.walk(decorator)}
            if names & self._PERMISSION_DECORATORS:
                return True
            if isinstance(decorator, ast.Call) and _last_name(decorator.func) == "permission_classes":
                if self._has_object_permission(decorator.args[0] if decorator.args else None):
                    return True
        for node in ast.walk(function):
            if isinstance(node, ast.Compare) and _mentions_request_user(node):
                return True
            if isinstance(node, ast.Name) and node.id in self._PERMISSION_NAMES:
                return True
            if isinstance(node, ast.Attribute) and node.attr in self._PERMISSION_NAMES:
                return True
        return False

    def _class_checks_permission(self, owner: ast.ClassDef) -> bool:
        if any(_last_name(base) in self._PERMISSION_MIXINS for base in owner.bases):
            return True
        assignment = _assigned_value(owner.body, "permission_classes")
        return assignment is not None and self._has_object_permission(assignment.value)

    def _has_object_permission(self, value: Optional[ast.AST]) -> bool:
        if value is None:
            return False
        return bool(set(_permission_classes(value)) - self._NOT_OBJECT_LEVEL)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class DjangoAnalyzer:
    """Runs every Django view rule over one Python file."""

    _RULES: List[DjangoRule] = [
        CsrfExemptRule(),
        SsrfRule(),
        OpenRedirectRule(),
        PathTraversalRule(),
        ReflectedXssRule(),
        RawSqlRule(),
        JwtVerificationRule(),
        AllowAnyWriteRule(),
        SerializerAllFieldsRule(),
        IdorRule(),
    ]

    @classmethod
    def analyze(cls, code: str, file_path: str = "") -> List[Issue]:
        """Return the Django issues of *code*; empty when it cannot be parsed."""
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            return []

        lines = code.splitlines()
        issues: List[Issue] = []
        seen: Set[Tuple[str, int]] = set()
        for scope in cls._scopes(tree):
            tracker = TaintTracker(scope)
            for rule in cls._RULES:
                for issue in rule.check(scope, tracker):
                    key = (issue.rule_id, issue.line_number)
                    if key in seen:
                        continue
                    seen.add(key)
                    issue.file_path = file_path
                    if 1 <= issue.line_number <= len(lines):
                        issue.code_snippet = lines[issue.line_number - 1].strip()
                    VulnerabilityDatabase.enrich_issue(issue, issue.rule_id.lower())
                    issues.append(issue)
        issues.sort(key=lambda issue: (issue.line_number, issue.rule_id))
        return issues

    @staticmethod
    def _scopes(tree: ast.Module) -> List[ast.AST]:
        functions = [node for node in ast.walk(tree) if isinstance(node, _FunctionNode)]
        return [tree, *functions]
