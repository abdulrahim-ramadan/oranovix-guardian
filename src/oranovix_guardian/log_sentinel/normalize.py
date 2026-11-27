"""
Request normalisation.

Attackers hide payloads behind encodings (``%2527``), odd case
(``UnIoN``), comment tricks (``UNION/**/SELECT``), full-width letters and
null bytes. Every rule sees the request after all of that is undone, so
one pattern covers every disguise.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Tuple
from urllib.parse import unquote

Param = Tuple[str, str]


@dataclass(frozen=True)
class NormalizedRequest:
    """Path and query in two forms.

    ``decoded``: decoded, NFKC, no null bytes, case folded, whitespace collapsed.
    ``text``: the same with SQL comments removed. Rules match on this one
    unless the comment itself is the evidence.
    """

    path: str
    query: str
    decoded: str
    text: str
    params: Tuple[Param, ...] = ()       # decoded the same way as ``decoded``
    user_agent: str = ""
    had_null_byte: bool = False
    encoding_rounds: int = 0             # how often the request was URL encoded

    @property
    def values(self) -> Tuple[str, ...]:
        return tuple(value for _, value in self.params)


class RequestNormalizer:
    """Undoes encodings and tricks. Pure, no state."""

    ROUNDS = 3
    MAX_PARAMS = 100

    # Overlong UTF-8 and IIS %u forms that browsers never send.
    _OVERLONG = (
        ("%c0%af", "/"), ("%e0%80%af", "/"), ("%c1%9c", "\\"), ("%c0%ae", "."), ("%e0%80%ae", "."),
        ("%c0%2f", "/"), ("%c0%5c", "\\"),
    )
    _IIS_UNICODE = re.compile(r"%u([0-9a-fA-F]{4})")
    _BLOCK_COMMENT = re.compile(r"/\*.{0,200}?\*/", re.DOTALL)
    _OPEN_COMMENT = re.compile(r"/\*!?\d{0,6}")        # MySQL "/*!50000UNION" without a close
    _LINE_COMMENT = re.compile(r"--|#")
    _SPACE = re.compile(r"\s+")
    _CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    def normalize(self, path: str, query: str = "", user_agent: str = "") -> NormalizedRequest:
        decoded_path, rounds_path, null_path = self._decode(path, plus_is_space=False)
        decoded_query, rounds_query, null_query = self._decode(query, plus_is_space=True)
        decoded = decoded_path + ("?" + decoded_query if decoded_query else "")
        if "%" in query:
            params = tuple(
                (self._decode(key, True)[0], self._decode(value, True)[0])
                for key, value in self._split(query)
            )
        else:
            # Nothing was encoded, so splitting the decoded query gives the same pairs.
            params = tuple((key.strip(), value.strip()) for key, value in self._split(decoded_query))
        return NormalizedRequest(
            path=decoded_path,
            query=decoded_query,
            decoded=decoded,
            text=self.strip_comments(decoded),
            params=params,
            user_agent=self._decode(user_agent, plus_is_space=False, url=False)[0],
            had_null_byte=null_path or null_query,
            encoding_rounds=max(rounds_path, rounds_query),
        )

    def _decode(self, value: str, plus_is_space: bool, url: bool = True) -> Tuple[str, int, bool]:
        text = value
        rounds = 0
        if url:
            for _ in range(self.ROUNDS):
                # In the query "+" is a space, also when it was encoded again.
                if "%" not in text and not (plus_is_space and "+" in text):
                    break
                before = text
                lowered = text.lower() if "%c" in text.lower() or "%e0" in text.lower() else text
                for encoded, char in self._OVERLONG:
                    if encoded in lowered:
                        text = re.sub(re.escape(encoded), char, text, flags=re.IGNORECASE)
                        lowered = text.lower()
                text = self._IIS_UNICODE.sub(lambda m: chr(int(m.group(1), 16)), text)
                if plus_is_space:
                    text = text.replace("+", " ")
                text = unquote(text, errors="replace")
                if text == before:
                    break
                rounds += 1
        if not text.isascii():
            text = unicodedata.normalize("NFKC", text)
        null = "\x00" in text
        if null:
            text = text.replace("\x00", "")
        if text.isprintable() and "  " not in text:
            return text.casefold().strip(), rounds, null        # the common case: nothing to clean
        text = self._CONTROL.sub("", text).casefold()
        return self._SPACE.sub(" ", text).strip(), rounds, null

    @classmethod
    def strip_comments(cls, text: str) -> str:
        text = cls._BLOCK_COMMENT.sub(" ", text)
        text = cls._OPEN_COMMENT.sub(" ", text).replace("*/", " ")
        text = cls._LINE_COMMENT.sub(" ", text)
        return cls._SPACE.sub(" ", text).strip()

    @classmethod
    def _split(cls, query: str) -> Tuple[Param, ...]:
        if not query:
            return ()
        pairs = []
        for part in query.split("&")[: cls.MAX_PARAMS]:
            key, _, value = part.partition("=")
            pairs.append((key, value))
        return tuple(pairs)
