"""Email and Telegram delivery, all offline: a recording SMTP and a fake fetcher."""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from oranovix_guardian.notify.mail import EmailError, EmailNotifier, EmailSettings, validate_address, validate_header
from oranovix_guardian.notify.models import OutboundMessage
from oranovix_guardian.notify.redaction import safe_error_text
from oranovix_guardian.notify.telegram import TelegramError, TelegramNotifier, split_message, valid_token
from oranovix_guardian.threat_intel.fetcher import FetchError, FetchResponse

from feed_fakes import FakeFetcher
from notify_fakes import smtp_classes, smtp_password, telegram_token

UTC = timezone.utc


def message(text: str = "Hello\nWorld", html_part: str = "<p>Hello</p>", telegram: str = "<b>Hello</b>") -> OutboundMessage:
    return OutboundMessage(id="m1", kind="test", subject="Oranovix Guardian: test", text=text,
                           telegram_html=telegram, email_html=html_part, created_at=datetime(2026, 11, 22, tzinfo=UTC))


def settings(**changes: Any) -> EmailSettings:
    values: Dict[str, Any] = dict(enabled=True, consented=True, host="smtp.example.com", port=465, username="me@example.com",
                  from_addr="me@example.com", to_addrs=("you@example.com",))
    values.update(changes)
    return EmailSettings(**values)


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch):
    plain, implicit, log = smtp_classes()
    monkeypatch.setattr(smtplib, "SMTP", plain)
    monkeypatch.setattr(smtplib, "SMTP_SSL", implicit)
    return log


def notifier(config: EmailSettings) -> EmailNotifier:
    return EmailNotifier(config, password=smtp_password)


# ---------------------------------------------------------------------------
# Email: TLS
# ---------------------------------------------------------------------------

def test_port_465_uses_implicit_tls_with_the_feed_context(smtp) -> None:
    result = notifier(settings(port=465)).send(message())
    assert result.ok, result.error
    connection = smtp.connections[0]
    assert connection["class"] == "FakeSMTP_SSL" and connection["port"] == 465
    context = connection["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED and context.check_hostname
    assert smtp.logins == [("me@example.com", smtp_password(), True)]
    assert len(smtp.sent) == 1


def test_port_587_requires_starttls_before_login(smtp) -> None:
    result = notifier(settings(port=587)).send(message())
    assert result.ok, result.error
    connection = smtp.connections[0]
    assert connection["class"] == "FakeSMTP" and connection["tls"]
    context = connection["starttls_context"]
    assert context.verify_mode is ssl.CERT_REQUIRED and context.check_hostname
    assert smtp.logins[0][2] is True                       # logged in only after TLS


def test_port_25_is_refused_before_any_connection(smtp) -> None:
    result = notifier(settings(port=25)).send(message())
    assert not result.ok and result.permanent
    assert "25" in result.error and "TLS" in result.error
    assert smtp.connections == []


def test_a_server_without_starttls_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    plain, implicit, log = smtp_classes(extensions=("auth",))
    monkeypatch.setattr(smtplib, "SMTP", plain)
    monkeypatch.setattr(smtplib, "SMTP_SSL", implicit)
    result = notifier(settings(port=587)).send(message())
    assert not result.ok and "STARTTLS" in result.error
    assert log.logins == [] and log.sent == []


def test_a_starttls_failure_is_reported_and_nothing_is_sent_in_plain_text(monkeypatch: pytest.MonkeyPatch) -> None:
    plain, implicit, log = smtp_classes(fail_starttls=True)
    monkeypatch.setattr(smtplib, "SMTP", plain)
    monkeypatch.setattr(smtplib, "SMTP_SSL", implicit)
    result = notifier(settings(port=587)).send(message())
    assert not result.ok and "STARTTLS" in result.error
    assert log.logins == [] and log.sent == []


def test_the_password_never_appears_in_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    password = smtp_password()

    class Refusing:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise smtplib.SMTPAuthenticationError(535, f"bad credentials for {password}".encode())

    monkeypatch.setattr(smtplib, "SMTP_SSL", Refusing)
    result = notifier(settings()).send(message())
    assert not result.ok and password not in result.error


def test_the_message_has_text_and_html_parts(smtp) -> None:
    notifier(settings(to_addrs=("a@example.com", "b@example.com"))).send(message())
    sent = smtp.sent[0]
    assert sent["Subject"] == "Oranovix Guardian: test"
    assert sent["To"] == "a@example.com, b@example.com"
    kinds = [part.get_content_type() for part in sent.walk()]
    assert "text/plain" in kinds and "text/html" in kinds


# ---------------------------------------------------------------------------
# Email: header injection and address checks
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["you@example.com\r\nBcc: x@y", "you@example.com\nBcc: x@y", "x@y\rBcc: z@w"])
def test_addresses_with_line_breaks_are_refused(bad: str) -> None:
    with pytest.raises(EmailError):
        validate_address(bad)


@pytest.mark.parametrize("bad", ["Report\r\nBcc: x@y", "Report\nX: y", "Report\r"])
def test_a_subject_with_line_breaks_is_refused(bad: str) -> None:
    with pytest.raises(EmailError):
        validate_header(bad)


def test_an_injected_recipient_never_reaches_the_server(smtp) -> None:
    result = notifier(settings(to_addrs=("you@example.com\r\nBcc: x@y",))).send(message())
    assert not result.ok and result.permanent
    assert smtp.connections == []


def test_an_injected_subject_never_reaches_the_server(smtp) -> None:
    bad = OutboundMessage(id="m2", kind="test", subject="Hi\r\nBcc: x@y", text="t", telegram_html="t",
                          email_html="t", created_at=datetime(2026, 11, 22, tzinfo=UTC))
    result = notifier(settings()).send(bad)
    assert not result.ok and smtp.connections == []


@pytest.mark.parametrize("bad", ["", "no-at-sign", "a@b", "two@@example.com", "Name <a@example.com>",
                                 "a b@example.com", "a@exa mple.com"])
def test_address_shape_is_checked(bad: str) -> None:
    with pytest.raises(EmailError):
        validate_address(bad)


def test_at_most_five_recipients() -> None:
    with pytest.raises(EmailError):
        settings(to_addrs=tuple(f"u{n}@example.com" for n in range(6))).validate()
    settings(to_addrs=tuple(f"u{n}@example.com" for n in range(5))).validate()


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

SEND_URL = "https://api.telegram.org/bot" + telegram_token() + "/sendMessage"
UPDATES_URL = "https://api.telegram.org/bot" + telegram_token() + "/getUpdates"


class PostFetcher(FakeFetcher):
    pass


def ok_body(result: Any = True) -> bytes:
    return json.dumps({"ok": True, "result": result}).encode()


def telegram(fetcher: FakeFetcher, chat: str = "4242") -> TelegramNotifier:
    return TelegramNotifier(token=telegram_token, chat_id=chat, fetcher=fetcher)


def test_token_shape() -> None:
    assert valid_token(telegram_token())
    for bad in ("", "123:short", telegram_token() + "x", "abc:" + "x" * 35, telegram_token().replace(":", "")):
        assert not valid_token(bad)


def test_sending_posts_html_to_the_chat() -> None:
    fetcher = FakeFetcher({SEND_URL: ok_body({"message_id": 1})})
    result = telegram(fetcher).send(message(telegram="<b>Hi</b> &amp; you"))
    assert result.ok, result.error
    url, body, content_type = fetcher.posts[0]
    payload = json.loads(body)
    assert url == SEND_URL and content_type == "application/json"
    assert payload == {"chat_id": "4242", "text": "<b>Hi</b> &amp; you", "parse_mode": "HTML",
                       "disable_web_page_preview": True}


def test_a_long_message_is_sent_in_parts() -> None:
    fetcher = FakeFetcher({SEND_URL: ok_body()})
    long = "\n".join(f"line {n} " + "x" * 50 for n in range(300))
    assert telegram(fetcher).send(message(telegram=long)).ok
    parts = [json.loads(body)["text"] for _, body, _ in fetcher.posts]
    assert len(parts) > 1 and "\n".join(parts) == long


def test_split_keeps_lines_whole_and_under_the_limit() -> None:
    lines = [f"{n:04d} " + "y" * (n % 90) for n in range(400)]
    parts = split_message("\n".join(lines), limit=4096)
    assert all(len(part) <= 4096 for part in parts)
    assert [line for part in parts for line in part.split("\n")] == lines


def test_split_cuts_only_a_line_that_is_longer_than_the_limit() -> None:
    parts = split_message("short\n" + "z" * 5000 + "\nend", limit=4096)
    assert all(len(part) <= 4096 for part in parts)
    assert "".join(parts).replace("\n", "") == "short" + "z" * 5000 + "end"


def test_a_short_message_is_one_part() -> None:
    assert split_message("a\nb", limit=4096) == ["a\nb"]


def _error_with_url() -> Exception:
    return FetchError(f"URLError: cannot reach {SEND_URL}: timed out (bot{telegram_token()})")


def test_the_token_never_appears_in_the_result_or_log(caplog: pytest.LogCaptureFixture) -> None:
    fetcher = FakeFetcher({SEND_URL: _error_with_url()})
    with caplog.at_level(logging.DEBUG):
        result = telegram(fetcher).send(message())
    assert not result.ok
    token = telegram_token()
    assert token not in result.error and token.split(":")[1] not in result.error
    assert token not in caplog.text and token.split(":")[1] not in caplog.text
    assert "api.telegram.org" not in result.error or "bot<" in result.error


def test_a_telegram_error_answer_is_redacted() -> None:
    body = json.dumps({"ok": False, "error_code": 400,
                       "description": f"Bad Request: chat not found for {SEND_URL}"}).encode()
    fetcher = FakeFetcher({SEND_URL: FetchResponse(status=400, body=body)})
    result = telegram(fetcher).send(message())
    assert not result.ok and "chat not found" in result.error
    assert telegram_token() not in result.error


def test_unauthorized_is_permanent() -> None:
    body = json.dumps({"ok": False, "error_code": 401, "description": "Unauthorized"}).encode()
    result = telegram(FakeFetcher({SEND_URL: FetchResponse(status=401, body=body)})).send(message())
    assert not result.ok and result.permanent


def test_safe_error_text_removes_token_and_urls() -> None:
    token = telegram_token()
    text = safe_error_text(_error_with_url(), [token])
    assert token not in text and token.split(":")[1] not in text and "https://" not in text
    assert safe_error_text(f"bot{token}/sendMessage failed") == "bot<REDACTED>/sendMessage failed"


def test_find_my_chat_reads_updates_once_and_lists_names() -> None:
    updates = [
        {"update_id": 1, "message": {"chat": {"id": 4242, "type": "private", "first_name": "Rim"}, "text": "/start"}},
        {"update_id": 2, "message": {"chat": {"id": 4242, "type": "private", "first_name": "Rim"}, "text": "hi"}},
        {"update_id": 3, "message": {"chat": {"id": -1001, "type": "group", "title": "Ops"}, "text": "secret plan"}},
    ]
    fetcher = FakeFetcher({UPDATES_URL: ok_body(updates)})
    chats = telegram(fetcher, chat="").find_chats()
    assert chats == [("4242", "Rim"), ("-1001", "Ops")]
    assert fetcher.urls == [UPDATES_URL] and fetcher.posts == []
    assert all("secret plan" not in name and "/start" not in name for _, name in chats)


def test_find_my_chat_with_a_bad_token_raises_without_the_token() -> None:
    body = json.dumps({"ok": False, "error_code": 401, "description": "Unauthorized"}).encode()
    fetcher = FakeFetcher({UPDATES_URL: FetchResponse(status=401, body=body)})
    with pytest.raises(TelegramError) as raised:
        telegram(fetcher).find_chats()
    assert telegram_token() not in str(raised.value)


def test_an_invalid_token_is_not_sent_anywhere() -> None:
    fetcher = FakeFetcher({})
    result = TelegramNotifier(token=lambda: "nonsense", chat_id="1", fetcher=fetcher).send(message())
    assert not result.ok and result.permanent and fetcher.requests == [] and fetcher.posts == []


def test_the_default_fetcher_checks_public_addresses_and_tls() -> None:
    from oranovix_guardian.notify.telegram import TelegramNotifier as Notifier
    fetcher = Notifier.default_fetcher()
    assert getattr(fetcher, "_guard") is not None
    assert getattr(fetcher, "_schemes") == frozenset({"https"})
