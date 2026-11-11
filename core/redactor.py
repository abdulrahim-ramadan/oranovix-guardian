"""
Removes secrets from text before it leaves the machine.

Every text that is sent to the online AI goes through ``Redactor.redact``.
The secret formats are not defined here: they are the patterns of
``SecretsDetector`` and the secret variable names of the AST analyzer, so
a new pattern added to the scanner is redacted automatically.
"""
from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Callable, List, Optional, Pattern, Tuple

REDACTED = "<REDACTED>"

_Replace = Callable[["re.Match[str]"], str]


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
        """Return *text* with every recognised secret value replaced."""
        if not text:
            return text
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
