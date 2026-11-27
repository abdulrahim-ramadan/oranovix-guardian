"""
Email over SMTP, always with TLS.

Port 465 is implicit TLS. Any other port needs STARTTLS before the
login; a server that does not offer it is refused, and so is port 25
(plain SMTP between servers, usually blocked for clients anyway). The
certificate is checked with the same context as the Threat Feed
(``TlsTrust``: the system store, certifi as fallback, CERT_REQUIRED and
hostname check).

Addresses and the subject are checked before anything is built, so a
line break can never add a header ("Bcc: ..."). The password is read
from the credential store when the message is sent and never kept.
"""
from __future__ import annotations

import re
import smtplib
from dataclasses import dataclass, field, replace
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from typing import Any, Callable, Dict, Tuple

from oranovix_guardian.threat_intel.fetcher import TlsTrust

from .models import DeliveryResult, Notifier, OutboundMessage
from .redaction import safe_error_text

IMPLICIT_TLS_PORT = 465
STARTTLS_PORT = 587
PLAIN_PORT = 25
MAX_RECIPIENTS = 5
_SHAPE = re.compile(r"^[^@\s<>\"',;:()\[\]\\]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")


class EmailError(ValueError):
    """The settings or the message cannot be sent as they are."""


def validate_header(value: str, what: str = "subject") -> str:
    """A header value without line breaks; anything else is refused, not cleaned."""
    if "\r" in value or "\n" in value:
        raise EmailError(f"The {what} must not contain a line break.")
    return value


def validate_address(value: str) -> str:
    """A plain address like ``name@example.com``. Display names are not accepted."""
    validate_header(value, "address")
    address = value.strip()
    name, parsed = parseaddr(address)
    if not address or name or parsed != address or address.count("@") != 1 or not _SHAPE.match(address):
        raise EmailError(f"\"{address[:80]}\" is not an email address.")
    return address


@dataclass(frozen=True)
class EmailSettings:
    enabled: bool = False
    consented: bool = False
    host: str = ""
    port: int = STARTTLS_PORT
    username: str = ""
    from_addr: str = ""
    to_addrs: Tuple[str, ...] = field(default=())

    def validate(self) -> "EmailSettings":
        """The same settings, checked; raises ``EmailError`` with a clear text."""
        host = validate_header(self.host.strip(), "server")
        if not host or " " in host or "/" in host:
            raise EmailError("Enter the SMTP server, for example smtp.gmail.com.")
        if self.port == PLAIN_PORT:
            raise EmailError("Port 25 sends without TLS and is not allowed. Use 465 (TLS) or 587 (STARTTLS).")
        if not 0 < self.port < 65536:
            raise EmailError("The port must be 465 (TLS) or 587 (STARTTLS).")
        if not self.to_addrs:
            raise EmailError("Enter at least one recipient.")
        if len(self.to_addrs) > MAX_RECIPIENTS:
            raise EmailError(f"At most {MAX_RECIPIENTS} recipients.")
        validate_header(self.username, "user name")
        return replace(
            self, host=host, from_addr=validate_address(self.from_addr),
            to_addrs=tuple(validate_address(address) for address in self.to_addrs),
        )

    def to_json(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "consented": self.consented, "host": self.host, "port": self.port,
                "username": self.username, "from_addr": self.from_addr, "to_addrs": list(self.to_addrs)}

    @classmethod
    def from_json(cls, data: object) -> "EmailSettings":
        if not isinstance(data, dict):
            return cls()
        try:
            port = int(str(data.get("port", STARTTLS_PORT)))
        except ValueError:
            port = STARTTLS_PORT
        recipients = data.get("to_addrs")
        return cls(
            enabled=data.get("enabled") is True, consented=data.get("consented") is True,
            host=str(data.get("host") or "")[:255], port=port,
            username=str(data.get("username") or "")[:255], from_addr=str(data.get("from_addr") or "")[:255],
            to_addrs=tuple(str(a)[:255] for a in recipients[:MAX_RECIPIENTS]) if isinstance(recipients, list) else (),
        )


class EmailNotifier(Notifier):
    channel = "email"
    TIMEOUT_SECONDS = 20

    def __init__(self, settings: EmailSettings, password: Callable[[], str],
                 context: Callable[[], Any] = TlsTrust.context) -> None:
        self._settings = settings
        self._password = password
        self._context = context
        self.host = settings.host.strip()

    def build(self, message: OutboundMessage, settings: EmailSettings) -> EmailMessage:
        mail = EmailMessage()
        mail["Subject"] = validate_header(message.subject)
        mail["From"] = settings.from_addr
        mail["To"] = ", ".join(settings.to_addrs)
        mail["Date"] = formatdate(localtime=True)
        mail["Message-ID"] = make_msgid(domain=settings.from_addr.split("@", 1)[1])
        mail.set_content(message.text)
        mail.add_alternative(message.email_html, subtype="html")
        return mail

    def send(self, message: OutboundMessage) -> DeliveryResult:
        password = ""
        try:
            settings = self._settings.validate()
            mail = self.build(message, settings)
            password = self._password()
            if not password:
                return DeliveryResult(ok=False, error="No password is saved for the email account.", permanent=True)
            self._deliver(settings, mail, password)
        except EmailError as exc:
            return DeliveryResult(ok=False, error=str(exc), permanent=True)
        except smtplib.SMTPAuthenticationError as exc:
            return DeliveryResult(ok=False, permanent=True, error=safe_error_text(
                f"The server refused the login ({exc.smtp_code}). For Gmail, GMX or Outlook use an app password.",
                [password]))
        except Exception as exc:
            return DeliveryResult(ok=False, error=safe_error_text(exc, [password]))
        return DeliveryResult(ok=True)

    def _deliver(self, settings: EmailSettings, mail: EmailMessage, password: str) -> None:
        context = self._context()
        # Looked up at call time, so tests replace them with a recorder.
        if settings.port == IMPLICIT_TLS_PORT:
            with smtplib.SMTP_SSL(settings.host, settings.port, context=context, timeout=self.TIMEOUT_SECONDS) as server:
                self._login_and_send(server, settings, mail, password)
            return
        with smtplib.SMTP(settings.host, settings.port, timeout=self.TIMEOUT_SECONDS) as server:
            server.ehlo()
            if not server.has_extn("starttls"):
                raise EmailError(f"{settings.host} does not offer STARTTLS; nothing was sent. Use port 465.")
            try:
                server.starttls(context=context)
            except Exception as exc:
                # Retried later, like any network error; the server is never used without TLS.
                raise ConnectionError(f"STARTTLS failed, nothing was sent ({safe_error_text(exc, [password])})") from exc
            server.ehlo()
            self._login_and_send(server, settings, mail, password)

    @staticmethod
    def _login_and_send(server: Any, settings: EmailSettings, mail: EmailMessage, password: str) -> None:
        if settings.username:
            server.login(settings.username, password)
        server.send_message(mail)
