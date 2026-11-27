"""
Is a "hardcoded secret" really a secret?

Shared by the regex check SEC001, the AST rule AST-SEC1 and the Bandit
promotion of B105/B106/B107, so they all agree. A value is a placeholder
when it is a known filler word, shorter than 8 characters, a template
variable, a URL or a file path. A name ending in ``_url``, ``_field``,
``_header``, ``_name``, ``_path`` or ``_label`` describes where a secret
goes, not the secret itself.
"""
from __future__ import annotations

import re

MIN_SECRET_LENGTH = 8

_PLACEHOLDER_WORDS = frozenset({
    "test", "testing", "changeme", "change_me", "change-me", "empty", "none", "null", "nil",
    "example", "dummy", "fake", "sample", "placeholder", "todo", "fixme", "secret", "password",
    "passwd", "token", "default", "foobar", "redacted", "notset", "not-set", "unset",
})
# Markers that make any value a placeholder, wherever they appear.
_PLACEHOLDER_PARTS = (
    "changeme", "change_me", "change-me", "replace_me", "replace-me", "replaceme",
    "example", "dummy", "placeholder", "your_", "your-", "insert_", "insert-",
)
_TEMPLATE = re.compile(
    r"""^(?:
        <[^<>]*> |              # <your-token-here>
        \$\{[^}]*\} |           # ${DB_PASSWORD}
        \$[A-Za-z_]\w* |        # $DB_PASSWORD
        \{\{.*\}\} |            # {{ secret }}
        \{[^{}]*\} |            # {password}
        %\([^)]*\)[sd] |        # %(password)s
        %[A-Za-z_]\w*% |        # %PASSWORD%
        x+ | \*+ | \.+ | -+ | _+ | 0+ | 1234\d*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
_URL = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_URL_WITH_PASSWORD = re.compile(r"^[a-z][a-z0-9+.\-]*://[^/\s:@]*:[^/\s@]+@", re.IGNORECASE)
_PATH = re.compile(r"^(?:/|\./|\.\./|~/|[a-z]:[\\/]|\\\\)", re.IGNORECASE)

NON_SECRET_SUFFIXES = ("_url", "_uri", "_field", "_header", "_name", "_path", "_label", "_file")


class SecretHeuristics:
    """Static helpers; no state."""

    @staticmethod
    def is_placeholder(value: str) -> bool:
        text = value.strip().strip("'\"")
        if len(text) < MIN_SECRET_LENGTH:
            return True
        lower = text.lower()
        if lower in _PLACEHOLDER_WORDS or _TEMPLATE.match(text):
            return True
        if any(part in lower for part in _PLACEHOLDER_PARTS):
            return True
        if _URL.match(text):
            return not _URL_WITH_PASSWORD.match(text)      # user:pass@host is a secret
        return bool(_PATH.match(text))

    @staticmethod
    def is_non_secret_name(name: str) -> bool:
        lower = name.strip().strip("'\"").lower().rsplit(".", 1)[-1]
        return lower.endswith(NON_SECRET_SUFFIXES)

    @classmethod
    def is_secret(cls, name: str, value: str) -> bool:
        """``True`` when *name* = *value* looks like a real hardcoded secret."""
        return not cls.is_non_secret_name(name) and not cls.is_placeholder(value)
