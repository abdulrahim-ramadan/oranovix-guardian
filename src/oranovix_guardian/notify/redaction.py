"""Error texts without tokens, passwords or URLs.

The same idea as ``GeminiConfig.safe_error_text``: the secret is replaced
and every URL removed. A Telegram token also hides in ``bot<token>``
paths, so that shape is replaced even when the token is not known here.
"""
from __future__ import annotations

import re
from typing import Iterable, Union

from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig

REDACTED = "<REDACTED>"
_BOT_TOKEN = re.compile(r"bot\d{3,}:[A-Za-z0-9_-]{10,}")
_BARE_TOKEN = re.compile(r"\b\d{5,}:[A-Za-z0-9_-]{30,}\b")
MAX_LENGTH = 300


def safe_error_text(error: Union[BaseException, str], secrets: Iterable[str] = ()) -> str:
    """Describe *error* without any of *secrets*, without bot tokens and without URLs."""
    text = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
            # The secret part of a Telegram token alone must not survive either.
            if ":" in secret:
                tail = secret.split(":", 1)[1]
                if len(tail) >= 8:
                    text = text.replace(tail, REDACTED)
    text = _BOT_TOKEN.sub("bot" + REDACTED, text)
    text = _BARE_TOKEN.sub(REDACTED, text)
    text = GeminiConfig.safe_error_text(_Text(text))
    return text.split(": ", 1)[1][:MAX_LENGTH] if text.startswith("_Text: ") else text[:MAX_LENGTH]


class _Text(Exception):
    """Carries a finished text through ``GeminiConfig.safe_error_text`` (it removes URLs)."""


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])|::(?:[0-9A-Fa-f]{1,4}:?){1,7}")
_ANY_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)


def scrub_addresses(text: str) -> str:
    """Remove IP addresses and URLs from a text written by another part of the app."""
    text = _ANY_URL.sub("", text)
    text = _IPV4.sub("", text)
    text = _IPV6.sub("", text)
    return re.sub(r"\(\s*\)", "", re.sub(r"[ \t]{2,}", " ", text)).strip()
