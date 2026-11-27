"""
Telegram through the Bot API: ``sendMessage`` and, for the setup helper,
one ``getUpdates`` call.

Requests go through ``HttpFetcher`` with ``public_only``, checked
redirects and the system trust store. The token is part of every URL
(``/bot<token>/``), so every error text is passed through
``safe_error_text`` before it is returned, logged or stored.

Messages use ``parse_mode=HTML``. The renderer only emits ``<b>``,
``<i>``, ``<code>`` and ``<a>``, escapes every value, and never lets a
tag span two lines, so a long message can be split at line boundaries.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from oranovix_guardian.threat_intel.fetcher import FetchError, Fetcher, FetchResponse, HttpFetcher

from .models import DeliveryResult, Notifier, OutboundMessage
from .redaction import safe_error_text

API_HOST = "api.telegram.org"
MAX_MESSAGE = 4096
_TOKEN = re.compile(r"^\d{3,15}:[A-Za-z0-9_-]{35}$")


class TelegramError(RuntimeError):
    """A Bot API call failed. The text never contains the token."""


def valid_token(token: str) -> bool:
    """``<digits>:<35 characters>``, the shape @BotFather hands out."""
    return bool(_TOKEN.match(token or ""))


def split_message(text: str, limit: int = MAX_MESSAGE) -> List[str]:
    """Parts of at most *limit* characters, cut only between lines.

    Only a single line longer than *limit* is cut inside; it then fills
    parts of its own.
    """
    if len(text) <= limit:
        return [text]
    parts: List[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                parts.append(current)
                current = ""
            parts.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if current and len(candidate) > limit:
            parts.append(current)
            current = line
        else:
            current = candidate
    if current:
        parts.append(current)
    return parts


class TelegramNotifier(Notifier):
    channel = "telegram"
    host = API_HOST

    def __init__(self, token: Callable[[], str], chat_id: str, fetcher: Optional[Fetcher] = None) -> None:
        self._token = token
        self._chat_id = str(chat_id).strip()
        self._fetcher = fetcher or self.default_fetcher()

    @staticmethod
    def default_fetcher() -> HttpFetcher:
        return HttpFetcher(public_only=True, max_bytes=1024 * 1024, timeout=15)

    def send(self, message: OutboundMessage) -> DeliveryResult:
        token = self._token()
        if not valid_token(token):
            return DeliveryResult(ok=False, error="No valid bot token is saved.", permanent=True)
        if not self._chat_id:
            return DeliveryResult(ok=False, error="No chat is chosen. Use \"Find my chat\".", permanent=True)
        try:
            for part in split_message(message.telegram_html):
                self._call(token, "sendMessage", {
                    "chat_id": self._chat_id, "text": part, "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                })
        except _Refused as exc:
            return DeliveryResult(ok=False, error=str(exc), permanent=exc.permanent)
        except Exception as exc:
            return DeliveryResult(ok=False, error=safe_error_text(exc, [token]))
        return DeliveryResult(ok=True)

    def find_chats(self) -> List[Tuple[str, str]]:
        """Chats that wrote to the bot, as ``(id, name)``. Message texts are not kept."""
        token = self._token()
        if not valid_token(token):
            raise TelegramError("The bot token does not have the right shape (digits:35 characters).")
        url = self._url(token, "getUpdates")
        try:
            answer = self._fetcher.get(url)
            result = self._result(answer, token)
        except _Refused as exc:
            raise TelegramError(str(exc)) from None
        except FetchError as exc:
            raise TelegramError(safe_error_text(exc, [token])) from None
        chats: Dict[str, str] = {}
        for update in result if isinstance(result, list) else []:
            chat = self._chat_of(update)
            if chat is None:
                continue
            chat_id = str(chat.get("id", ""))
            if chat_id and chat_id not in chats:
                chats[chat_id] = self._chat_name(chat)
        return list(chats.items())

    # ------------------------------------------------------------------

    @staticmethod
    def _url(token: str, method: str) -> str:
        return f"https://{API_HOST}/bot{token}/{method}"

    def _call(self, token: str, method: str, payload: Dict[str, Any]) -> Any:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        answer = self._fetcher.post(self._url(token, method), body, "application/json")
        return self._result(answer, token)

    @staticmethod
    def _result(answer: FetchResponse, token: str) -> Any:
        try:
            data = json.loads(answer.body.decode("utf-8")) if answer.body else {}
        except (ValueError, UnicodeDecodeError):
            data = {}
        if answer.ok and isinstance(data, dict) and data.get("ok") is True:
            return data.get("result")
        description = str(data.get("description") or "") if isinstance(data, dict) else ""
        text = f"Telegram answered {answer.status}" + (f": {description}" if description else "")
        raise _Refused(safe_error_text(text, [token]), permanent=answer.status in (400, 401, 403, 404))

    @staticmethod
    def _chat_of(update: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(update, dict):
            return None
        for key in ("message", "edited_message", "channel_post", "my_chat_member"):
            entry = update.get(key)
            if isinstance(entry, dict) and isinstance(entry.get("chat"), dict):
                return entry["chat"]
        return None

    @staticmethod
    def _chat_name(chat: Dict[str, Any]) -> str:
        if chat.get("title"):
            name = str(chat["title"])
        else:
            name = " ".join(str(chat[k]) for k in ("first_name", "last_name") if chat.get(k))
            if not name and chat.get("username"):
                name = "@" + str(chat["username"])
        return name[:64] or str(chat.get("id", ""))


class _Refused(Exception):
    def __init__(self, text: str, permanent: bool) -> None:
        super().__init__(text)
        self.permanent = permanent
