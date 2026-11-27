"""
HTTP access of the Threat Feed.

``HttpFetcher`` is the only class that opens a connection. It is handed
to the sources, so tests replace it with a fake and never touch the
network. A request carries the URL, a fixed User-Agent and the cache
validators of the last download, and nothing else.

Feed downloads run with ``public_only``: a host that resolves to any
address that is not globally routable (loopback, private, carrier NAT,
link-local, ...) is refused, also when a redirect points there.

Certificates are checked against the trust store of the operating
system (``truststore``), because Windows fetches many roots on demand
and Python's own copy of the store then misses them. Verification is
never switched off.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, List, Optional
from urllib.parse import urlsplit


class FetchError(RuntimeError):
    """The request was refused, failed, or the answer was not acceptable."""


class CertificateError(FetchError):
    """The certificate of the site could not be verified.

    The text starts with ``MARK``, so the page can explain it in the
    user's language after the error was stored as plain text.
    """

    MARK = "certificate not trusted"

    def __init__(self, detail: str) -> None:
        super().__init__(f"{self.MARK}: {detail}")

    @classmethod
    def is_text_of(cls, error: str) -> bool:
        return error.startswith(cls.MARK)

    @classmethod
    def detail_of(cls, error: str) -> str:
        return error[len(cls.MARK):].lstrip(": ")


class TlsTrust:
    """Builds the SSL context of every download. It always verifies."""

    @classmethod
    def context(cls) -> ssl.SSLContext:
        """The trust store of the operating system; without ``truststore``, certifi's bundle."""
        try:
            import truststore
        except ImportError:
            context = cls._bundled()
        else:
            context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    @staticmethod
    def _bundled() -> ssl.SSLContext:
        context = ssl.create_default_context()
        try:
            import certifi
            context.load_verify_locations(cafile=certifi.where())
        except (ImportError, OSError):
            pass        # the default context alone still verifies
        return context


@dataclass(frozen=True)
class FetchResponse:
    status: int
    body: bytes = b""
    etag: str = ""
    last_modified: str = ""
    elapsed_ms: int = 0

    @property
    def unchanged(self) -> bool:
        """The server answered 304: the copy we already have is current."""
        return self.status == 304

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class Fetcher(ABC):
    """Downloads one URL."""

    @abstractmethod
    def get(self, url: str, etag: str = "", last_modified: str = "") -> FetchResponse:
        """GET *url*. Any HTTP status is returned; ``FetchError`` means no usable answer."""

    def post(self, url: str, body: bytes, content_type: str) -> FetchResponse:
        """POST *body* to *url* (notifications). Not every fetcher can."""
        raise FetchError("This fetcher cannot send data.")


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only when the new address passes the same checks."""

    def __init__(self, check: Callable[[str], None]) -> None:
        self._check = check

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        self._check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


Opener = Callable[[urllib.request.Request, float], Any]
IpAddress = Any     # ipaddress.IPv4Address | ipaddress.IPv6Address


class PublicAddressGuard:
    """Refuses hosts that resolve to anything but public addresses."""

    def __call__(self, host: str, port: int) -> None:
        for address in self.resolve(host, port):
            if self.is_internal(address):
                raise FetchError(f"{host} points to an internal address ({address}).")

    @staticmethod
    def resolve(host: str, port: int) -> List[IpAddress]:
        try:
            # looked up at call time, so tests can replace it
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError) as exc:
            raise FetchError(f"{host} could not be resolved.") from exc
        addresses = []
        for info in infos:
            text = str(info[4][0]).split("%", 1)[0]
            try:
                addresses.append(ipaddress.ip_address(text))
            except ValueError as exc:
                raise FetchError(f"{host} resolved to an invalid address.") from exc
        if not addresses:
            raise FetchError(f"{host} could not be resolved.")
        return addresses

    @staticmethod
    def is_internal(address: IpAddress) -> bool:
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
        # "not global" also covers 100.64.0.0/10 (carrier NAT, Tailscale),
        # which is neither private nor reserved for the ipaddress module.
        return bool(
            not address.is_global
            or address.is_loopback or address.is_private or address.is_link_local
            or address.is_reserved or address.is_multicast or address.is_unspecified
        )


class HttpFetcher(Fetcher):
    """GET over https with a size cap, a timeout and conditional requests."""

    USER_AGENT = "OranovixGuardian"
    TIMEOUT_SECONDS = 10.0
    MAX_BYTES = 5 * 1024 * 1024

    def __init__(
        self,
        allow_http: bool = False,
        max_bytes: int = MAX_BYTES,
        truncate: bool = False,
        timeout: float = TIMEOUT_SECONDS,
        opener: Optional[Opener] = None,
        public_only: bool = False,
    ) -> None:
        """*allow_http* and *truncate* exist for uptime checks of the user's own sites.

        With *truncate* a long answer is cut at *max_bytes* instead of refused.
        With *public_only* every host, also of a redirect, must resolve to
        public addresses only.
        """
        self._schemes = frozenset({"https", "http"} if allow_http else {"https"})
        self._guard: Optional[PublicAddressGuard] = PublicAddressGuard() if public_only else None
        self._max_bytes = max_bytes
        self._truncate = truncate
        self._timeout = timeout
        self._open = opener or self._default_opener()

    def _default_opener(self) -> Opener:
        # One director, so a redirect is followed with the same context.
        director = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=TlsTrust.context()),
            _CheckedRedirects(self._check_url),
        )
        return lambda request, timeout: director.open(request, timeout=timeout)

    def get(self, url: str, etag: str = "", last_modified: str = "") -> FetchResponse:
        self._check_url(url)
        headers = {"User-Agent": self.USER_AGENT, "Accept": "*/*"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        request = urllib.request.Request(url, headers=headers, method="GET")
        return self._send(request)

    def post(self, url: str, body: bytes, content_type: str) -> FetchResponse:
        """POST over the same checks (scheme, public addresses, redirects, TLS, size).

        The body of an error answer is kept, so the caller can read why
        the request was refused.
        """
        self._check_url(url)
        headers = {"User-Agent": self.USER_AGENT, "Accept": "application/json", "Content-Type": content_type}
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        return self._send(request, error_body=True)

    def _send(self, request: urllib.request.Request, error_body: bool = False) -> FetchResponse:
        started = time.monotonic()
        try:
            with self._open(request, self._timeout) as response:
                body = self._read(response)
                status = int(getattr(response, "status", 200) or 200)
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            # 304 and error pages arrive as exceptions; the status is the answer.
            status, response_headers = exc.code, exc.headers
            body = self._error_body(exc) if error_body else b""
        except FetchError:
            raise
        except Exception as exc:
            if self._is_certificate_error(exc):
                raise CertificateError(self._reason(exc)) from exc
            raise FetchError(f"{type(exc).__name__}: {self._reason(exc)}") from exc

        return FetchResponse(
            status=status,
            body=body,
            etag=self._header(response_headers, "ETag"),
            last_modified=self._header(response_headers, "Last-Modified"),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    def _check_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError as exc:
            raise FetchError("The address is not valid.") from exc
        if parts.scheme.lower() not in self._schemes or not host:
            allowed = " or ".join(sorted(self._schemes))
            raise FetchError(f"Only {allowed} addresses are allowed.")
        if self._guard is not None:
            try:
                port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
            except ValueError as exc:
                raise FetchError("The address is not valid.") from exc
            self._guard(host, port)

    def _error_body(self, exc: urllib.error.HTTPError) -> bytes:
        try:
            return exc.read(min(self._max_bytes, 64 * 1024))
        except Exception:
            return b""

    def _read(self, response: Any) -> bytes:
        declared = self._header(response.headers, "Content-Length")
        if not self._truncate and declared.isdigit() and int(declared) > self._max_bytes:
            raise FetchError(f"The answer is larger than {self._max_bytes} bytes.")
        body = response.read(self._max_bytes + 1)
        if len(body) > self._max_bytes:
            if not self._truncate:
                raise FetchError(f"The answer is larger than {self._max_bytes} bytes.")
            body = body[: self._max_bytes]
        return body

    @staticmethod
    def _header(headers: Any, name: str) -> str:
        if headers is None:
            return ""
        return str(headers.get(name) or "").strip()[:300]

    @staticmethod
    def _is_certificate_error(exc: Exception) -> bool:
        """urllib wraps the SSL error in a URLError; look at both."""
        return isinstance(exc, ssl.SSLCertVerificationError) or isinstance(
            getattr(exc, "reason", None), ssl.SSLCertVerificationError
        )

    @staticmethod
    def _reason(exc: Exception) -> str:
        return str(getattr(exc, "reason", "") or exc)[:200]
