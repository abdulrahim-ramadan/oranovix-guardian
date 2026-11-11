"""
Removes secrets from text before it leaves the machine.

Every text that is sent to the online AI goes through the Redactor:
source code through ``redact_code`` and prose through ``redact``.

Code is redacted by allowlist: the content of every string literal and
every long letter/digit token is replaced, whatever it looks like, so a
secret in an unknown format does not get through. The known secret
patterns then run as a second layer. Those patterns are not defined here:
they are the patterns of ``SecretsDetector`` and the secret variable names
of the AST analyzer, so a new scanner pattern is covered automatically.
"""
from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Callable, Dict, List, Optional, Pattern, Tuple

REDACTED = "<REDACTED>"

_Replace = Callable[["re.Match[str]"], str]

COMMENT = "<COMMENT>"

# Languages where "#" never starts a comment, and where "//" never does.
_SLASH_COMMENT_ONLY = frozenset({
    ".js", ".jsx", ".mjs", ".ts", ".tsx", ".java", ".cs", ".go", ".rs",
    ".swift", ".dart", ".kt", ".c", ".cpp", ".h", ".vue", ".svelte",
})
_HASH_COMMENT_ONLY = frozenset({
    ".py", ".pyw", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".tf", ".hcl", ".properties",
})

_QUOTES = "\"'`"
_STRING_PREFIX_CHARS = "rRbBuUfF@$"
_PLACEHOLDER = re.compile(r"<(?:STR|VALUE)_\d+>|<REDACTED>|<COMMENT>")
# A run of token characters; it is replaced when it is long and mixes
# letters and digits (keys, hashes, base64).
_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+/])[A-Za-z0-9_\-+/]{16,}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class _CodeRedaction:
    """One redaction run; remembers which value got which placeholder."""

    def __init__(self, file_name: str = "") -> None:
        self._strings: Dict[str, str] = {}
        self._values: Dict[str, str] = {}
        suffix = PureWindowsPath(file_name).suffix.lower()
        # Which comment styles the language has. Unknown files get both.
        self._hash_comments = suffix not in _SLASH_COMMENT_ONLY
        self._slash_comments = suffix not in _HASH_COMMENT_ONLY

    # ------------------------------------------------------------------
    # Code: strings and comments first, then tokens in what is left
    # ------------------------------------------------------------------

    def code(self, text: str, comments: bool = True) -> str:
        out: List[str] = []
        start = 0
        i = 0
        while i < len(text):
            if text[i] in _QUOTES:
                out.append(self.tokens(text[start:i]))
                i = self._string(text, i, out)
                start = i
                continue
            end = self._comment_end(text, i) if comments else -1
            if end >= 0:
                out.append(self.tokens(text[start:i]))
                block = text.startswith("/*", i)
                out.append(text[i:i + (1 if text[i] == "#" else 2)] + " " + COMMENT)
                if block and text.startswith("*/", end - 2):
                    out.append(" */")
                i = start = end
                continue
            i += 1
        out.append(self.tokens(text[start:]))
        return "".join(out)

    def _comment_end(self, text: str, i: int) -> int:
        """Index after the comment that starts at ``text[i]``, or -1 if none does."""
        c = text[i]
        before = text[i - 1] if i > 0 else "\n"
        if c == "#" and self._hash_comments and before.isspace() and not text.startswith("#!", i):
            return self._line_end(text, i)
        if c == "/" and self._slash_comments:
            if text.startswith("//", i) and before != ":":
                return self._line_end(text, i)
            if text.startswith("/*", i):
                close = text.find("*/", i + 2)
                return len(text) if close < 0 else close + 2
        return -1

    @staticmethod
    def _line_end(text: str, i: int) -> int:
        newline = text.find("\n", i)
        return len(text) if newline < 0 else newline

    def tokens(self, text: str) -> str:
        """Replace long mixed letter/digit tokens in text that holds no strings."""
        def replace(match: "re.Match[str]") -> str:
            token = match.group(0)
            if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
                return token
            # A name that is being called is code, not a value.
            if _IDENTIFIER.match(token) and match.string[match.end():].lstrip(" \t").startswith("("):
                return token
            return self._values.setdefault(token, f"<VALUE_{len(self._values) + 1}>")

        return _TOKEN.sub(replace, text)

    # ------------------------------------------------------------------
    # String literals
    # ------------------------------------------------------------------

    def _string(self, text: str, i: int, out: List[str]) -> int:
        """Redact the literal that opens at ``text[i]``; return the index after it."""
        quote = text[i]
        prefix = self._prefix(text, i)
        verbatim = "@" in prefix                      # C# @"..." : "" is the escape
        interpolated = quote == "`" or any(c in prefix for c in "fF$")

        run = 1
        while quote != "`" and text[i + run:i + run + 1] == quote and run < 6:
            run += 1
        if run in (2, 6):                              # "" or """""" : empty
            out.append(quote * run)
            return i + run
        delimiter = quote * 3 if run >= 3 else quote
        multiline = len(delimiter) == 3 or quote == "`" or verbatim

        begin = i + len(delimiter)
        p = begin
        end = -1
        while p < len(text):
            c = text[p]
            if verbatim and text.startswith(quote * 2, p):
                p += 2
                continue
            if c == "\\" and not verbatim:
                p += 2
                continue
            if c == "\n" and not multiline:
                break
            if text.startswith(delimiter, p):
                end = p
                break
            p += 1

        terminated = end >= 0
        stop = end if terminated else min(p, len(text))
        content = text[begin:stop]
        out.append(delimiter)
        out.append(self._content(content, interpolated, template=quote == "`"))
        if terminated:
            out.append(delimiter)
            return stop + len(delimiter)
        # Unterminated (a cut line, an apostrophe in a comment): everything
        # up to the end of the line or text was treated as content.
        return stop

    @staticmethod
    def _prefix(text: str, i: int) -> str:
        j = i
        while j > 0 and i - j < 3 and text[j - 1] in _STRING_PREFIX_CHARS:
            j -= 1
        if j > 0 and (text[j - 1].isalnum() or text[j - 1] == "_"):
            return ""                                  # end of an identifier
        return text[j:i]

    def _content(self, content: str, interpolated: bool, template: bool) -> str:
        if not interpolated:
            return self._literal(content)

        # f-string / template string: literal parts are redacted, the
        # {...} fields are code and go through the code redaction.
        out: List[str] = []
        literal: List[str] = []
        opener = "${" if template else "{"
        i = 0
        while i < len(content):
            if not template and content.startswith("{{", i):
                literal.append("{{")
                i += 2
                continue
            if content.startswith(opener, i):
                close = self._field_end(content, i + len(opener))
                if close < 0:
                    literal.append(content[i:])
                    break
                out.append(self._literal("".join(literal)))
                literal = []
                field = self.code(content[i + len(opener):close], comments=False)
                out.append(opener + field + "}")
                i = close + 1
                continue
            literal.append(content[i])
            i += 1
        out.append(self._literal("".join(literal)))
        return "".join(out)

    @staticmethod
    def _field_end(content: str, start: int) -> int:
        depth = 1
        for p in range(start, len(content)):
            if content[p] == "{":
                depth += 1
            elif content[p] == "}":
                depth -= 1
                if depth == 0:
                    return p
        return -1

    def _literal(self, content: str) -> str:
        # Kept: empty, one character, one escape such as \n, or a placeholder
        # from an earlier run.
        if len(content) <= 1 or (len(content) == 2 and content[0] == "\\"):
            return content
        if _PLACEHOLDER.fullmatch(content):
            return content
        return self._strings.setdefault(content, f"<STR_{len(self._strings) + 1}>")


class Redactor:
    """Replaces secret values in a text with ``<REDACTED>``."""

    # Built once on first use. The scanner modules are imported lazily
    # because ``scanner_engine`` itself imports this module.
    _rules: Optional[List[Tuple[Pattern[str], _Replace]]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def redact(cls, text: str) -> str:
        """Redact prose (a title or a description).

        Replaces every value matched by the secret patterns, then every
        remaining long token that mixes letters and digits.
        """
        if not text:
            return text
        return _CodeRedaction().tokens(cls._apply_patterns(text))

    @classmethod
    def redact_code(cls, snippet: str, file_name: str = "") -> str:
        """Redact source code by allowlist: nothing a string holds is sent.

        *file_name* is optional; its extension tells which comment style
        the language uses. Comment text is replaced by ``<COMMENT>``.

        1. The content of every string literal becomes ``<STR_1>``,
           ``<STR_2>``... (same value, same placeholder). Quotes and
           prefixes stay, so the code keeps its shape. Only empty strings
           and single characters are kept. In f-strings and template
           strings the ``{...}`` fields stay as code.
        2. Outside strings, every token of 16 or more characters that mixes
           letters and digits becomes ``<VALUE_1>``..., unless it is
           clearly a function being called.
        3. The secret patterns run over the result as a second layer.
        """
        if not snippet:
            return snippet
        return cls._apply_patterns(_CodeRedaction(file_name).code(snippet))

    @classmethod
    def _apply_patterns(cls, text: str) -> str:
        for pattern, replace in cls._get_rules():
            text = pattern.sub(replace, text)
        return text

    @staticmethod
    def file_name(path: str) -> str:
        """Return only the file name of *path* (``/`` and ``\\`` both count)."""
        return PureWindowsPath(str(path or "")).name

    @classmethod
    def hide_path(cls, text: str, path: str) -> str:
        """Replace every occurrence of the full *path* in *text* by its file name."""
        if not text or not path:
            return text
        name = cls.file_name(path)
        for variant in {path, path.replace("\\", "/"), path.replace("/", "\\")}:
            if variant and variant != name:
                text = text.replace(variant, name)
        return text

    # ------------------------------------------------------------------
    # Rule construction
    # ------------------------------------------------------------------

    @classmethod
    def _get_rules(cls) -> List[Tuple[Pattern[str], _Replace]]:
        if cls._rules is None:
            cls._rules = cls._build_rules()
        return cls._rules

    @classmethod
    def _build_rules(cls) -> List[Tuple[Pattern[str], _Replace]]:
        from scanner_engine.ast_analyzer import SECRET_VARIABLE_NAMES
        from scanner_engine.secrets_detector import (
            ConnectionStringPattern,
            JWTPattern,
            PasswordPattern,
            PrivateKeyPattern,
            SecretsDetector,
        )

        rules: List[Tuple[Pattern[str], _Replace]] = []
        for secret in SecretsDetector.patterns():
            source = secret.pattern
            replace: _Replace = cls._replace_all
            if isinstance(secret, ConnectionStringPattern):
                replace = cls._replace_connection_password
            elif isinstance(secret, PasswordPattern):
                replace = cls._replace_last_literal
            elif isinstance(secret, PrivateKeyPattern):
                # The scanner only needs the BEGIN line; the key body follows it.
                source += r"(?s:.*?)(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"
            elif isinstance(secret, JWTPattern):
                # The scanner matches header.payload; the signature follows it.
                source += r"(?:\.[a-zA-Z0-9_-]+)?"
            rules.append((re.compile(source, re.MULTILINE), replace))

        rules.append((cls._assignment_pattern(SECRET_VARIABLE_NAMES), cls._replace_assigned))
        return rules

    @staticmethod
    def _assignment_pattern(names: frozenset) -> Pattern[str]:
        """A string literal assigned to (or compared with) a secret-like name.

        Covers ``password = "x"``, ``DB_PASSWORD: str = 'x'``,
        ``"api_key": "x"``, ``'token' => 'x'``, ``os.environ["SECRET"] = "x"``
        and ``if token == "x"``.
        """
        alternatives = "|".join(sorted((re.escape(n) for n in names), key=len, reverse=True))
        return re.compile(
            r"(?P<head>"
            rf"[\w\-]*(?:{alternatives})[\w\-]*"   # name that contains a secret word
            r"[\"'`]?\]?"                          # closing quote / bracket of a key
            r"(?:[ \t]*:[ \t]*[\w.\[\], |]+?)?"    # optional type annotation
            r"[ \t]*(?:[=!]=+|:=|=>|=|:)[ \t]*"    # assignment or comparison
            r"[A-Za-z]{0,2}"                       # string prefix (f, r, b, rb)
            r")"
            r"(?:"
            r"(?P<tq>\"\"\"|''')(?P<tv>(?s:.+?))(?P=tq)"
            r"|"
            r"(?P<q>[\"'`])(?P<v>(?:\\.|(?!(?P=q))[^\n\\])+)(?P=q)"
            r")",
            re.IGNORECASE,
        )

    # ------------------------------------------------------------------
    # Replacement functions
    # ------------------------------------------------------------------

    @staticmethod
    def _replace_all(match: "re.Match[str]") -> str:
        return REDACTED

    @staticmethod
    def _replace_connection_password(match: "re.Match[str]") -> str:
        # scheme://user:password@  ->  scheme://user:<REDACTED>@
        text = match.group(0)
        scheme, _, rest = text.partition("://")
        user = rest.partition(":")[0]
        return f"{scheme}://{user}:{REDACTED}@"

    @staticmethod
    def _replace_last_literal(match: "re.Match[str]") -> str:
        # name = "value"  ->  name = "<REDACTED>"
        return re.sub(
            r"([\"'])[^\"']*([\"'])$",
            lambda m: f"{m.group(1)}{REDACTED}{m.group(2)}",
            match.group(0),
        )

    @staticmethod
    def _replace_assigned(match: "re.Match[str]") -> str:
        quote = match.group("tq") or match.group("q")
        return f"{match.group('head')}{quote}{REDACTED}{quote}"
