"""
Access log parsers.

Every line comes from the internet, so a parser never trusts it: lines
are capped before any regex sees them, the patterns have no nested
quantifiers, and a line that does not fit is counted and skipped.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .entry import AccessLogEntry, ClientAddressResolver

MAX_LINE = 8192


@dataclass
class ParseStats:
    """How many lines were read, and why some were not used."""

    lines: int = 0
    parsed: int = 0
    malformed: int = 0
    oversize: int = 0           # longer than MAX_LINE; counted in malformed when unusable too

    def add(self, other: "ParseStats") -> None:
        self.lines += other.lines
        self.parsed += other.parsed
        self.malformed += other.malformed
        self.oversize += other.oversize


class LogParser(ABC):
    """Turns one line into an ``AccessLogEntry``, or ``None``."""

    NAME = ""

    def __init__(self, resolver: Optional[ClientAddressResolver] = None) -> None:
        self._resolver = resolver or ClientAddressResolver()
        self.stats = ParseStats()

    def parse(self, line: str) -> Optional[AccessLogEntry]:
        """Never raises. ``None`` for an empty or malformed line."""
        raw_length = len(line)
        text = line.rstrip("\r\n")
        if not text.strip():
            return None
        self.stats.lines += 1
        if len(text) > MAX_LINE:
            self.stats.oversize += 1
            text = text[:MAX_LINE]
        try:
            entry = self._parse(text, raw_length)
        except Exception:
            entry = None
        if entry is None:
            self.stats.malformed += 1
        else:
            self.stats.parsed += 1
        return entry

    @abstractmethod
    def _parse(self, text: str, raw_length: int) -> Optional[AccessLogEntry]:
        """Parse a line that is already capped."""

    def client(self, peer: str, forwarded_for: str) -> Tuple[str, str]:
        """Client address and, when it differs, the direct peer."""
        client = self._resolver.resolve(peer, forwarded_for)
        return client, (peer.strip() if client != peer.strip() else "")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class LogTime:
    """The time formats of access logs, without the locale (``%b`` is locale dependent)."""

    _MONTHS = {
        name: number for number, name in enumerate(
            ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
        )
    }
    # 10/Oct/2026:13:55:36 +0200
    _CLF = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2})(\d{2}))?$")

    _last: Tuple[str, Optional[datetime]] = ("", None)

    @classmethod
    def parse(cls, value: Any) -> Optional[datetime]:
        if value is None or value == "":
            return None
        if isinstance(value, str) and value == cls._last[0]:
            return cls._last[1]             # many lines share one second
        moment = cls._parse(value)
        if isinstance(value, str):
            cls._last = (value, moment)
        return moment

    @classmethod
    def _parse(cls, value: Any) -> Optional[datetime]:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return cls._epoch(float(value))
        text = str(value).strip()[:64]
        match = cls._CLF.match(text)
        if match:
            return cls._clf(match)
        try:
            return cls._epoch(float(text))
        except ValueError:
            pass
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)

    @classmethod
    def _clf(cls, match: "re.Match[str]") -> Optional[datetime]:
        day, month, year, hour, minute, second, sign, off_h, off_m = match.groups()
        number = cls._MONTHS.get(month.lower())
        if number is None:
            return None
        offset = timedelta(0)
        if sign:
            offset = timedelta(hours=int(off_h), minutes=int(off_m))
            offset = -offset if sign == "-" else offset
        try:
            return datetime(int(year), number, int(day), int(hour), int(minute), int(second),
                            tzinfo=timezone(offset))
        except ValueError:
            return None

    @staticmethod
    def _epoch(seconds: float) -> Optional[datetime]:
        if seconds > 1e11:          # milliseconds
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None


class RequestLine:
    """``GET /path?query HTTP/1.1`` split into its parts. Anything else stays in the path."""

    _METHOD = re.compile(r"^[A-Z][A-Z_-]{0,19}$")

    @classmethod
    def split(cls, request: str) -> Tuple[str, str, str, str]:
        """Method, path, query, protocol."""
        parts = request.split(" ")
        if len(parts) >= 2 and cls._METHOD.match(parts[0]):
            method = parts[0]
            protocol = parts[-1] if len(parts) >= 3 and parts[-1].startswith("HTTP/") else ""
            target = " ".join(parts[1:-1] if protocol else parts[1:])
        else:
            method, protocol, target = "", "", request
        path, _, query = target.partition("?")
        return method, path, query, protocol

    @staticmethod
    def number(value: Any) -> int:
        text = str(value).strip()
        return int(text) if text.isdigit() and len(text) <= 15 else 0


def unescape_log(value: str) -> str:
    """Apache writes ``\\"`` and nginx ``\\x22``; turn both back into the character."""
    if "\\" not in value:
        return value
    return _ESCAPE.sub(_unescape_one, value)


_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|.)")


def _unescape_one(match: "re.Match[str]") -> str:
    code = match.group(1)
    if len(code) == 3 and code[0] == "x":
        return chr(int(code[1:], 16))
    return {"n": "\n", "t": "\t", "r": "\r"}.get(code, code)


# ---------------------------------------------------------------------------
# Combined / common
# ---------------------------------------------------------------------------

class NginxCombinedParser(LogParser):
    """nginx "combined", Apache "combined" and "common".

    An optional third quoted field after the user agent is read as
    ``X-Forwarded-For`` (the usual ``"$http_x_forwarded_for"`` addition).
    """

    NAME = "combined"

    # A quoted field: anything but a quote or backslash, or an escaped character.
    # Each alternative eats a fixed number of characters, so it cannot backtrack.
    _QUOTED = r'"((?:[^"\\]|\\.)*)"'
    _LINE = re.compile(
        r"^(\S+) \S+ \S+ \[([^\]]{1,64})\] "
        + _QUOTED
        + r" (\d{3}|-) (\d+|-)"
        + r"(?: " + _QUOTED + r" " + _QUOTED + r")?"
        + r"(?: " + _QUOTED + r")?"
    )

    def _parse(self, text: str, raw_length: int) -> Optional[AccessLogEntry]:
        match = self._LINE.match(text)
        if match is None:
            return None
        peer, time, request, status, size, referer, agent, forwarded = match.groups()
        method, path, query, protocol = RequestLine.split(unescape_log(request))
        client, peer_ip = self.client(peer, unescape_log(forwarded or ""))
        return AccessLogEntry(
            time=LogTime.parse(time),
            client_ip=client,
            method=method,
            path=path,
            query=query,
            status=RequestLine.number(status),
            size=RequestLine.number(size),
            referer=_dash(unescape_log(referer or "")),
            user_agent=_dash(unescape_log(agent or "")),
            raw_length=raw_length,
            protocol=protocol,
            peer_ip=peer_ip,
        )


def _dash(value: str) -> str:
    return "" if value == "-" else value


# ---------------------------------------------------------------------------
# JSON lines
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JsonFieldMap:
    """Which JSON keys hold which value. The first key that is present wins.

    A key may be a dotted path (``request.headers.User-Agent``); a list
    value is read as its first element (Caddy writes headers as lists).
    """

    time: Tuple[str, ...] = ("time", "timestamp", "@timestamp", "time_local", "time_iso8601", "ts")
    client_ip: Tuple[str, ...] = (
        "remote_addr", "client_ip", "clientip", "ip", "remote_ip", "request.remote_ip", "request.client_ip",
    )
    method: Tuple[str, ...] = ("method", "request_method", "request.method")
    path: Tuple[str, ...] = ("path", "uri", "request_uri", "url", "request.uri")
    query: Tuple[str, ...] = ("query", "query_string", "args")
    request: Tuple[str, ...] = ("request",)
    status: Tuple[str, ...] = ("status", "status_code", "response_status")
    size: Tuple[str, ...] = ("body_bytes_sent", "bytes_sent", "bytes", "size", "response_size")
    referer: Tuple[str, ...] = ("http_referer", "referer", "referrer", "request.headers.Referer")
    user_agent: Tuple[str, ...] = (
        "http_user_agent", "user_agent", "agent", "useragent", "request.headers.User-Agent",
    )
    forwarded_for: Tuple[str, ...] = (
        "http_x_forwarded_for", "x_forwarded_for", "forwarded_for", "request.headers.X-Forwarded-For",
    )

    FIELDS = ("time", "client_ip", "method", "path", "query", "request", "status", "size",
              "referer", "user_agent", "forwarded_for")

    @classmethod
    def from_settings(cls, raw: Any) -> "JsonFieldMap":
        """User mapping such as ``{"client_ip": "remote", "path": "req.path"}``; the rest stays default."""
        if not isinstance(raw, Mapping):
            return cls()
        values: Dict[str, Tuple[str, ...]] = {}
        for name in cls.FIELDS:
            given = raw.get(name)
            if isinstance(given, str) and given.strip():
                values[name] = (given.strip()[:100],)
            elif isinstance(given, (list, tuple)):
                keys = tuple(str(key).strip()[:100] for key in given if str(key).strip())
                if keys:
                    values[name] = keys[:10]
        return cls(**values)


class JsonLinesParser(LogParser):
    """One JSON object per line, e.g. nginx ``escape=json`` or Caddy."""

    NAME = "json"
    MAX_DEPTH = 6

    def __init__(
        self, fields: Optional[JsonFieldMap] = None, resolver: Optional[ClientAddressResolver] = None,
    ) -> None:
        super().__init__(resolver)
        self._fields = fields or JsonFieldMap()

    def _parse(self, text: str, raw_length: int) -> Optional[AccessLogEntry]:
        stripped = text.lstrip()
        if not stripped.startswith("{"):
            return None
        data = json.loads(stripped)
        if not isinstance(data, dict):
            return None
        f = self._fields
        peer = self._text(data, f.client_ip)
        if not peer:
            return None
        method, path, query, protocol = "", self._text(data, f.path), self._text(data, f.query), ""
        method = self._text(data, f.method)
        request = self._text(data, f.request)
        if request and (not path or not method):
            method_r, path_r, query_r, protocol = RequestLine.split(request)
            method, path, query = method or method_r, path or path_r, query or query_r
        if "?" in path and not query:
            path, _, query = path.partition("?")
        if not path:
            return None
        client, peer_ip = self.client(peer, self._text(data, f.forwarded_for))
        return AccessLogEntry(
            time=LogTime.parse(self._value(data, f.time)),
            client_ip=client,
            method=method[:20],
            path=path,
            query=query,
            status=RequestLine.number(self._value(data, f.status) or ""),
            size=RequestLine.number(self._value(data, f.size) or ""),
            referer=_dash(self._text(data, f.referer)),
            user_agent=_dash(self._text(data, f.user_agent)),
            raw_length=raw_length,
            protocol=protocol,
            peer_ip=peer_ip,
        )

    @classmethod
    def _value(cls, data: Mapping[str, Any], keys: Sequence[str]) -> Any:
        for key in keys:
            value = cls._lookup(data, key)
            if value is not None and value != "":
                return value
        return None

    @classmethod
    def _text(cls, data: Mapping[str, Any], keys: Sequence[str]) -> str:
        value = cls._value(data, keys)
        if value is None or isinstance(value, (dict, list)):
            return ""
        return str(value)[:MAX_LINE]

    @classmethod
    def _lookup(cls, data: Mapping[str, Any], key: str) -> Any:
        if key in data:
            return cls._first(data[key])
        current: Any = data
        for part in key.split(".")[: cls.MAX_DEPTH]:
            if not isinstance(current, Mapping) or part not in current:
                return None
            current = cls._first(current[part])
        return current

    @staticmethod
    def _first(value: Any) -> Any:
        if isinstance(value, list):
            return value[0] if value else None
        return value


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

class LogFormat(str, Enum):
    AUTO = "auto"
    COMBINED = "combined"
    JSON = "json"


@dataclass
class LogFormatDetector:
    """Picks the parser that reads most of the first lines of a log."""

    SAMPLE = 20
    resolver: ClientAddressResolver = field(default_factory=ClientAddressResolver)
    json_fields: JsonFieldMap = field(default_factory=JsonFieldMap)

    def build(self, log_format: LogFormat) -> LogParser:
        if log_format is LogFormat.JSON:
            return JsonLinesParser(self.json_fields, self.resolver)
        return NginxCombinedParser(self.resolver)

    def detect(self, lines: Sequence[str]) -> LogFormat:
        """The best format for *lines*; combined when nothing fits (all lines then count as malformed)."""
        sample = [line for line in lines if line.strip()][: self.SAMPLE]
        best, best_score = LogFormat.COMBINED, 0
        for log_format in (LogFormat.COMBINED, LogFormat.JSON):
            parser = self.build(log_format)
            score = sum(1 for line in sample if parser.parse(line) is not None)
            if score > best_score:
                best, best_score = log_format, score
        return best

    def parser_for(self, log_format: LogFormat, sample: Sequence[str] = ()) -> LogParser:
        chosen = self.detect(sample) if log_format is LogFormat.AUTO else log_format
        return self.build(chosen)


def parse_lines(parser: LogParser, lines: Sequence[str]) -> List[AccessLogEntry]:
    """Every line that could be read; the rest is counted in ``parser.stats``."""
    entries = []
    for line in lines:
        entry = parser.parse(line)
        if entry is not None:
            entries.append(entry)
    return entries
