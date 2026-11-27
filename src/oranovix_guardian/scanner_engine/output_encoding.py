"""
Is request data written to the page through an encoder?

``res.send(escapeHtml(req.query.n))`` and
``echo htmlspecialchars($_GET['name'], ENT_QUOTES);`` are the safe way to
output user input. The line-based XSS rules (JS017, PHP005, PHP006) ask
this module, for every occurrence of request data on the line, which calls
enclose it. When every occurrence sits inside a known encoder, the line is
not reported.

The scan is textual (one line, brackets counted outside string literals),
like the rules that use it.
"""
from __future__ import annotations

import re
from typing import FrozenSet, List, Pattern

_CALL_NAME = re.compile(r"([A-Za-z_$][\w$]*(?:\s*(?:\.|->|::)\s*[A-Za-z_$][\w$]*)*)\s*$")
_CAST = re.compile(r"\(\s*(int|integer|float|double|bool|boolean)\s*\)\s*$", re.IGNORECASE)


def _open_brackets(line: str, end: int) -> List[int]:
    """Positions of the ``(`` still open at *end*, outermost first.

    Brackets inside quotes do not count. In a JS template literal the
    ``${...}`` part is code again.
    """
    stack: List[int] = []
    quote = ""
    i = 0
    while i < end:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if quote == "`" and line.startswith("${", i):
                stack.append(-1)            # template field: code inside
                quote = ""
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            stack.append(i)
        elif ch == ")" and stack and stack[-1] != -1:
            stack.pop()
        elif ch == "}" and stack and stack[-1] == -1:
            stack.pop()
            quote = "`"
        i += 1
    return [pos for pos in stack if pos >= 0]


def enclosing_calls(line: str, index: int) -> List[str]:
    """Names of the calls around position *index*, innermost first.

    ``he.encode`` stays dotted, ``$obj->escape`` keeps its arrow. A PHP cast
    directly before the value counts as a call named ``(int)``.
    """
    names: List[str] = []
    cast = _CAST.search(line[:index])
    if cast:
        names.append(f"({cast.group(1).lower()})")
    for bracket in reversed(_open_brackets(line, index)):
        found = _CALL_NAME.search(line[:bracket])
        names.append(re.sub(r"\s+", "", found.group(1)) if found else "")
    return names


def all_wrapped(line: str, value: Pattern[str], encoders: FrozenSet[str]) -> bool:
    """``True`` when *value* occurs on *line* and each occurrence is inside an encoder.

    An encoder matches by its full dotted name (``DOMPurify.sanitize``) or
    by its last part (``escape`` also covers ``_.escape``).
    """
    found = False
    for match in value.finditer(line):
        found = True
        names = enclosing_calls(line, match.start())
        if not any(name in encoders or re.split(r"\.|->|::", name)[-1] in encoders for name in names):
            return False
    return found
