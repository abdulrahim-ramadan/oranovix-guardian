"""
Hide secret values in text that leaves the machine (the PDF report).

A value is shown as its first and last four characters (``AKIA…MPLE``);
values shorter than 12 characters are hidden completely (``****``),
because eight shown characters would be the whole secret. Names stay
readable: ``password = "****"``.
"""
from __future__ import annotations

import re
from typing import Iterable

from oranovix_guardian.scanner_engine.base import Issue
from oranovix_guardian.scanner_engine.categories import IssueCategory

ELLIPSIS = "…"
HIDDEN = "****"
_SECRET_WORDS = r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|key_id|auth|credential)"

# Shapes that are secrets wherever they appear.
_TOKENS = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"                        # AWS access key id
    r"|\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b"        # GitHub tokens
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bsk-[A-Za-z0-9_-]{20,}\b"                           # OpenAI style keys
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}\b"                   # Slack
    r"|\b[sr]k_live_[0-9A-Za-z]{16,}"                       # Stripe live / restricted
    r"|\bAIza[0-9A-Za-z_-]{30,}"                            # Google API key
    r"|\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"        # SendGrid
    r"|\b[0-9]{8,10}:AA[0-9A-Za-z_-]{30,}"                  # Telegram bot token
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?"   # JWT
)
# scheme://user:password@host
_URL_PASSWORD = re.compile(r"(?P<head>://[^:/\s@'\"]+:)(?P<value>[^@\s/'\"]+)(?P<tail>@)")
# "value" or 'value' (not a dict key, which is followed by a colon)
_QUOTED = re.compile(r"(?P<q>[\"'])(?P<value>(?:(?!(?P=q)).){4,}?)(?P=q)(?!\s*:)")
# name = value / name: value without quotes, for names that hold secrets
_ASSIGNED = re.compile(
    r"(?P<head>[\w.-]*" + _SECRET_WORDS + r"[\w.-]*\s*[=:]\s*)(?P<value>[^\s'\"#;,)]{4,})",
    re.IGNORECASE,
)
_SECRET_RULES = frozenset({"B105", "B106", "B107"})


def _short(value: str) -> str:
    if ELLIPSIS in value or value == HIDDEN:
        return value                                    # already masked
    if len(value) >= 12:
        return value[:4] + ELLIPSIS + value[-4:]
    return HIDDEN


class SecretMasker:
    """Masks secret values in text."""

    @staticmethod
    def mask(text: str) -> str:
        if not text:
            return text
        text = _TOKENS.sub(lambda m: _short(m.group(0)), text)
        text = _URL_PASSWORD.sub(lambda m: m.group("head") + _short(m.group("value")) + m.group("tail"), text)
        text = _QUOTED.sub(lambda m: m.group("q") + _short(m.group("value")) + m.group("q"), text)
        return _ASSIGNED.sub(lambda m: m.group("head") + _short(m.group("value")), text)

    @staticmethod
    def holds_secret(issue: Issue) -> bool:
        """A finding whose texts may contain the secret itself."""
        rules: Iterable[str] = (issue.rule_id, *issue.also_detected_by)
        return issue.category is IssueCategory.SECRET or any(rule in _SECRET_RULES for rule in rules)
