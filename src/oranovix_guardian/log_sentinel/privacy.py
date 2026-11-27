"""
Personal data in access logs.

An IP address is personal data (DSGVO). By default an event keeps it
truncated (IPv4 /24, IPv6 /48) plus a keyed hash, so repeats from one
address can still be counted without storing the address. Query values
that look like credentials never reach the event store.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from typing import Optional, Protocol

from .entry import parse_ip

HIDDEN = "<hidden>"
MAX_REQUEST = 300


class KeyStore(Protocol):
    def get(self) -> str: ...
    def set(self, value: str) -> None: ...
    def is_available(self) -> bool: ...


class IpAnonymizer:
    """Truncates and hashes client addresses."""

    def __init__(self, key: bytes, keep_full: bool = False) -> None:
        if len(key) < 16:
            raise ValueError("The hash key is too short.")
        self._key = key
        self.keep_full = keep_full

    @staticmethod
    def truncate(address: str) -> str:
        """203.0.113.57 -> 203.0.113.0, 2001:db8:85a3:1::7 -> 2001:db8:85a3::"""
        ip = parse_ip(address)
        if ip is None:
            return "?"
        prefix = 24 if ip.version == 4 else 48
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).network_address)

    def display(self, address: str) -> str:
        """What is stored and shown: the full address only when the user chose it."""
        if self.keep_full:
            ip = parse_ip(address)
            return str(ip) if ip is not None else "?"
        return self.truncate(address)

    def hash(self, address: str) -> str:
        ip = parse_ip(address)
        text = str(ip) if ip is not None else address.strip()
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


class HashKeyProvider:
    """The key of the address hash, kept in the credential store when there is one."""

    ENTRY = "log_sentinel_ip_key"

    def __init__(self, store: Optional[KeyStore] = None, fallback: Optional["KeyFallback"] = None) -> None:
        self._store = store
        self._fallback = fallback

    def key(self) -> bytes:
        if self._store is not None and self._store.is_available():
            value = self._store.get()
            if not value:
                value = secrets.token_hex(32)
                try:
                    self._store.set(value)
                except Exception:
                    value = ""
            if value:
                return bytes.fromhex(value) if _is_hex(value) else value.encode("utf-8")
        if self._fallback is not None:
            return self._fallback.key()
        return secrets.token_bytes(32)          # counts repeats within this session only


class KeyFallback(Protocol):
    def key(self) -> bytes: ...


def _is_hex(value: str) -> bool:
    return len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)


class RequestRedactor:
    """Cuts a request line and hides query values that look like credentials."""

    SECRET_NAME = re.compile(
        r"(?:token|password|passwd|pwd|secret|key|session|sess|auth|jwt|signature|credential|otp)", re.IGNORECASE,
    )
    JWT = re.compile(r"\beyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]*", re.IGNORECASE)
    BEARER = re.compile(r"\b(bearer|basic) [a-z0-9._~+/=-]{8,}", re.IGNORECASE)

    @classmethod
    def target(cls, path: str, query: str) -> str:
        """``path?query`` with hidden secrets, at most ``MAX_REQUEST`` characters."""
        if query:
            parts = []
            for part in query.split("&"):
                name, eq, value = part.partition("=")
                if eq and value and cls.SECRET_NAME.search(name):
                    value = HIDDEN
                parts.append(f"{name}{eq}{value}")
            text = f"{path}?{'&'.join(parts)}"
        else:
            text = path
        return cls.text(text)

    @classmethod
    def text(cls, value: str) -> str:
        """Any free text from a request: tokens hidden, length capped."""
        value = cls.JWT.sub(HIDDEN, value)
        value = cls.BEARER.sub(lambda m: f"{m.group(1)} {HIDDEN}", value)
        value = re.sub(
            r"((?:token|password|passwd|pwd|secret|key|session|sess|auth|jwt|signature)[a-z0-9_]*=)[^&\s]+",
            lambda m: m.group(1) + HIDDEN, value, flags=re.IGNORECASE,
        )
        if len(value) > MAX_REQUEST:
            value = value[: MAX_REQUEST - 1] + "…"
        return value
