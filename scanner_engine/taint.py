"""
Taint tracking for one Python scope (a function body or a module).

Data read from the HTTP request is *tainted*.  Taint flows through
assignments and string building, and is removed by sanitizers or by a
validating ``if`` check.  Rules ask ``TaintTracker.is_tainted(node)``
for any expression of the scope.

The walk is flow-sensitive: every expression is judged with the set of
tainted names that holds at its own statement, so ``page = int(page)``
cleans ``page`` for the statements that follow.
"""
from __future__ import annotations

import ast
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union

Scope = Union[ast.Module, ast.FunctionDef, ast.AsyncFunctionDef]
_FunctionNode = (ast.FunctionDef, ast.AsyncFunctionDef)
_Guards = Tuple[FrozenSet[str], FrozenSet[str]]
_NO_NAMES: FrozenSet[str] = frozenset()


def dotted_name(node: ast.AST) -> str:
    """``os.path.basename`` for a Name/Attribute chain, ``""`` for anything else."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def is_request(node: ast.AST) -> bool:
    """True for ``request`` and ``self.request``."""
    if isinstance(node, ast.Name):
        return node.id == "request"
    return isinstance(node, ast.Attribute) and node.attr == "request"


class TaintTracker:
    """Answers whether an expression of one scope carries request data."""

    SOURCE_ATTRIBUTES: FrozenSet[str] = frozenset({
        "GET", "POST", "data", "query_params", "body", "COOKIES", "META", "FILES",
    })
    # Matched on the last part of the called name.
    SANITIZERS: FrozenSet[str] = frozenset({
        "int", "float", "UUID", "basename", "get_valid_filename", "escape",
    })
    _NOT_SANITIZERS: FrozenSet[str] = frozenset({"re.escape"})
    URL_GUARDS: FrozenSet[str] = frozenset({"url_has_allowed_host_and_scheme"})
    # Calls that hand their argument back in another shape.
    PASS_THROUGH: FrozenSet[str] = frozenset({
        "str", "bytes", "repr", "format", "join", "urljoin", "unquote",
        "unquote_plus", "quote", "urlparse", "urlsplit", "Path", "PurePath",
        "normpath", "abspath", "realpath", "loads", "list", "tuple", "dict",
        "set", "sorted", "reversed", "mark_safe",
    })

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._states: Dict[int, FrozenSet[str]] = {}
        self._nodes: List[ast.AST] = []
        self._run_block(scope.body, set())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def scope(self) -> Scope:
        return self._scope

    def is_tainted(self, node: ast.AST) -> bool:
        """True when *node* can hold data that came from the request."""
        return self._tainted(node, self._states.get(id(node), _NO_NAMES))

    def nodes(self) -> Iterator[ast.AST]:
        """Every expression node of this scope, nested functions excluded."""
        return iter(self._nodes)

    def calls(self) -> Iterator[ast.Call]:
        return (node for node in self._nodes if isinstance(node, ast.Call))

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------

    def _run_block(self, statements: Sequence[ast.stmt], state: Set[str]) -> Tuple[Set[str], bool]:
        """Walk *statements* in order; return the state after them and
        whether the block always leaves (return, raise, break, continue)."""
        for statement in statements:
            state, leaves = self._run_statement(statement, state)
            if leaves:
                return state, True
        return state, False

    def _run_statement(self, node: ast.stmt, state: Set[str]) -> Tuple[Set[str], bool]:
        if isinstance(node, _FunctionNode):
            return state, False
        if isinstance(node, ast.ClassDef):
            self._run_block(node.body, set(state))
            return state, False
        if isinstance(node, ast.Assign):
            self._record(node, state)
            for target in node.targets:
                self._bind(target, node.value, state)
            return state, False
        if isinstance(node, ast.AnnAssign):
            self._record(node, state)
            if node.value is not None:
                self._bind(node.target, node.value, state)
            return state, False
        if isinstance(node, ast.AugAssign):
            self._record(node, state)
            if self._tainted(node.value, frozenset(state)):
                self._mark(node.target, True, state)
            return state, False
        if isinstance(node, ast.If):
            return self._run_if(node, state)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            return self._run_for(node, state), False
        if isinstance(node, ast.While):
            return self._run_while(node, state), False
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._record(item.context_expr, state)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, item.context_expr, state)
            return self._run_block(node.body, state)
        if isinstance(node, ast.Try) or node.__class__.__name__ == "TryStar":
            return self._run_try(node, state), False
        if isinstance(node, ast.Match):
            self._record(node.subject, state)
            merged = set(state)
            for case in node.cases:
                merged |= self._run_block(case.body, set(state))[0]
            return merged, False

        self._record(node, state)
        self._bind_walrus(node, state)
        return state, isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue))

    def _run_if(self, node: ast.If, state: Set[str]) -> Tuple[Set[str], bool]:
        self._record(node.test, state)
        self._bind_walrus(node.test, state)
        cleared_if_true, cleared_if_false = self._guards(node.test, frozenset(state))
        body_state, body_leaves = self._run_block(node.body, state - cleared_if_true)
        else_state, else_leaves = self._run_block(node.orelse, state - cleared_if_false)
        if body_leaves and else_leaves:
            return body_state | else_state, True
        if body_leaves:
            return else_state, False
        if else_leaves:
            return body_state, False
        return body_state | else_state, False

    def _run_for(self, node: Union[ast.For, ast.AsyncFor], state: Set[str]) -> Set[str]:
        self._record(node.iter, state)
        loop_state = set(state)
        self._bind(node.target, node.iter, loop_state)
        # Two passes so taint created late in the body reaches its start.
        for _ in range(2):
            loop_state |= self._run_block(node.body, set(loop_state))[0]
        return loop_state | self._run_block(node.orelse, set(loop_state))[0]

    def _run_while(self, node: ast.While, state: Set[str]) -> Set[str]:
        loop_state = set(state)
        for _ in range(2):
            self._record(node.test, loop_state)
            cleared_if_true, _ = self._guards(node.test, frozenset(loop_state))
            loop_state |= self._run_block(node.body, loop_state - cleared_if_true)[0]
        return loop_state | self._run_block(node.orelse, set(loop_state))[0]

    def _run_try(self, node: ast.stmt, state: Set[str]) -> Set[str]:
        body_state = self._run_block(node.body, set(state))[0]  # type: ignore[attr-defined]
        merged = state | body_state
        for handler in node.handlers:  # type: ignore[attr-defined]
            merged |= self._run_block(handler.body, state | body_state)[0]
        merged |= self._run_block(node.orelse, set(body_state))[0]  # type: ignore[attr-defined]
        return self._run_block(node.finalbody, merged)[0]  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # State bookkeeping
    # ------------------------------------------------------------------

    def _record(self, node: ast.AST, state: Set[str]) -> None:
        """Remember which names are tainted while *node* is evaluated."""
        frozen = frozenset(state)
        for child in ast.walk(node):
            if not isinstance(child, ast.expr):
                continue
            if id(child) not in self._states:
                self._nodes.append(child)
            self._states[id(child)] = frozen

    def _bind(self, target: ast.AST, value: ast.AST, state: Set[str]) -> None:
        """Apply ``target = value`` to *state*."""
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
        ):
            for sub_target, sub_value in zip(target.elts, value.elts):
                self._bind(sub_target, sub_value, state)
            return
        self._mark(target, self._tainted(value, frozenset(state)), state)

    def _mark(self, target: ast.AST, tainted: bool, state: Set[str]) -> None:
        if isinstance(target, ast.Name):
            if tainted:
                state.add(target.id)
            else:
                state.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._mark(element, tainted, state)
        elif isinstance(target, ast.Starred):
            self._mark(target.value, tainted, state)
        elif isinstance(target, ast.Subscript) and tainted:
            # container[key] = tainted makes the container tainted, never clean.
            self._mark(target.value, True, state)

    def _bind_walrus(self, node: ast.AST, state: Set[str]) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self._bind(child.target, child.value, state)

    # ------------------------------------------------------------------
    # Validation checks
    # ------------------------------------------------------------------

    def _guards(self, test: ast.AST, state: FrozenSet[str]) -> _Guards:
        """Names proven safe when *test* is true, and when it is false."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if_true, if_false = self._guards(test.operand, state)
            return if_false, if_true
        if isinstance(test, ast.BoolOp):
            parts = [self._guards(value, state) for value in test.values]
            if isinstance(test.op, ast.And):
                return frozenset().union(*(p[0] for p in parts)), _NO_NAMES
            return _NO_NAMES, frozenset().union(*(p[1] for p in parts))
        if isinstance(test, ast.Call):
            if dotted_name(test.func).rsplit(".", 1)[-1] in self.URL_GUARDS:
                checked = self._argument(test, 0, "url")
                if isinstance(checked, ast.Name):
                    return frozenset({checked.id}), _NO_NAMES
            return _NO_NAMES, _NO_NAMES
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            # ``name in ALLOWED`` against a collection the user does not control.
            name, collection = test.left, test.comparators[0]
            if isinstance(name, ast.Name) and not self._tainted(collection, state):
                if isinstance(test.ops[0], ast.In):
                    return frozenset({name.id}), _NO_NAMES
                if isinstance(test.ops[0], ast.NotIn):
                    return _NO_NAMES, frozenset({name.id})
        return _NO_NAMES, _NO_NAMES

    @staticmethod
    def _argument(call: ast.Call, index: int, keyword: str) -> Optional[ast.expr]:
        if len(call.args) > index:
            return call.args[index]
        for item in call.keywords:
            if item.arg == keyword:
                return item.value
        return None

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------

    def _tainted(self, node: Optional[ast.AST], state: FrozenSet[str]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in state
        if isinstance(node, ast.Attribute):
            if node.attr in self.SOURCE_ATTRIBUTES and is_request(node.value):
                return True
            return self._tainted(node.value, state)
        if isinstance(node, ast.Call):
            return self._call_tainted(node, state)
        if isinstance(node, ast.Subscript):
            return self._tainted(node.value, state)
        if isinstance(node, ast.BinOp):
            return self._tainted(node.left, state) or self._tainted(node.right, state)
        if isinstance(node, ast.JoinedStr):
            return self._any(node.values, state)
        if isinstance(node, ast.FormattedValue):
            return self._tainted(node.value, state)
        if isinstance(node, ast.BoolOp):
            return self._any(node.values, state)
        if isinstance(node, ast.IfExp):
            cleared_if_true, cleared_if_false = self._guards(node.test, state)
            return (
                self._tainted(node.body, state - cleared_if_true)
                or self._tainted(node.orelse, state - cleared_if_false)
            )
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self._any(node.elts, state)
        if isinstance(node, ast.Dict):
            return self._any(node.values, state)
        if isinstance(node, (ast.Starred, ast.Await, ast.NamedExpr)):
            return self._tainted(node.value, state)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension_tainted(node, state)
        return False

    def _any(self, nodes: Iterable[Optional[ast.AST]], state: FrozenSet[str]) -> bool:
        return any(self._tainted(node, state) for node in nodes)

    def _call_tainted(self, node: ast.Call, state: FrozenSet[str]) -> bool:
        name = dotted_name(node.func)
        last = name.rsplit(".", 1)[-1] if name else getattr(node.func, "attr", "")
        if last in self.SANITIZERS and name not in self._NOT_SANITIZERS:
            return False
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        if isinstance(node.func, ast.Attribute):
            # request.GET.get("q"), tainted.strip(), tainted.format(...)
            if self._tainted(node.func.value, state):
                return True
            if node.func.attr == "format":
                return self._any(arguments, state)
        if last in self.PASS_THROUGH:
            return self._any(arguments, state)
        return False

    def _comprehension_tainted(self, node: ast.AST, state: FrozenSet[str]) -> bool:
        local = set(state)
        for generator in node.generators:  # type: ignore[attr-defined]
            if self._tainted(generator.iter, frozenset(local)):
                self._mark(generator.target, True, local)
        frozen = frozenset(local)
        if isinstance(node, ast.DictComp):
            return self._tainted(node.key, frozen) or self._tainted(node.value, frozen)
        return self._tainted(node.elt, frozen)  # type: ignore[attr-defined]
