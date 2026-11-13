"""
Web shell signatures: code that runs attacker input or hides a payload.

One class per rule. Content is read as latin-1, so byte positions and
line numbers stay right even in binary files with code inside.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from typing import ClassVar, List, Optional, Pattern, Sequence, Tuple


@dataclass(frozen=True)
class SignatureHit:
    rule: str
    description: str
    line: int


class WebShellRule(ABC):
    """One signature."""

    name: ClassVar[str]
    description: ClassVar[str]
    # Lower-case text of which at least one must occur; lets a rule skip a file cheaply.
    hints: ClassVar[Tuple[str, ...]] = ()

    def applies(self, lowered: str) -> bool:
        return not self.hints or any(hint in lowered for hint in self.hints)

    @property
    @abstractmethod
    def pattern(self) -> Pattern[str]:
        """Compiled regex of the signature."""

    def find(self, text: str) -> Optional[SignatureHit]:
        match = self.pattern.search(text)
        if match is None:
            return None
        return SignatureHit(self.name, self.description, text.count("\n", 0, match.start()) + 1)


class PhpEvalBase64Rule(WebShellRule):
    name = "php-eval-base64"
    hints = ("base64_decode",)
    description = "PHP eval() of base64-decoded data"
    _PATTERN = re.compile(r"\beval\s*\(\s*@?\s*base64_decode\s*\(", re.IGNORECASE)

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpCommandOnInputRule(WebShellRule):
    name = "php-command-on-input"
    hints = ("$_",)
    description = "PHP system/passthru/shell_exec/assert on request input"
    _PATTERN = re.compile(
        r"\b(?:system|passthru|shell_exec|assert)\s*\(\s*@?\s*\$_(?:GET|POST|REQUEST)\b",
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


_SUPERGLOBAL = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
_PHP_DECODERS = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)"


class PhpEvalOnInputRule(WebShellRule):
    name = "php-eval-on-input"
    hints = ("$_",)
    description = "PHP eval/assert/create_function/include on request input"
    # eval/create_function: input anywhere in the call; assert/include: input as the argument.
    _PATTERN = re.compile(
        r"(?<![\w$>:])(?:(?:eval|create_function)\s*\([^;\n]*?"
        r"|(?:assert|include_once|require_once|include|require)\s*\(?\s*@?\s*)" + _SUPERGLOBAL,
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpBacktickOnInputRule(WebShellRule):
    name = "php-backtick-on-input"
    hints = ("$_",)
    description = "PHP backtick command execution of request input"
    # Only where a value is expected, so `$_GET` quoted in docs does not hit.
    _PATTERN = re.compile(
        r"(?:=|\(|\becho|\bprint|<\?=|\breturn)\s*`[^`\n]*" + _SUPERGLOBAL + r"[^`\n]*`",
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpSuperglobalCallRule(WebShellRule):
    name = "php-superglobal-call"
    hints = ("$_",)
    description = "PHP calls a function named by request input"
    _PATTERN = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\n]*\]\s*\(", re.IGNORECASE)

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpEvalDecodeChainRule(WebShellRule):
    name = "php-eval-decode-chain"
    hints = ("eval",)
    description = "PHP eval() of a gzinflate/gzuncompress/str_rot13 decoding chain"
    # Plain eval(base64_decode( is php-eval-base64; this needs a compression or rot13 layer.
    _PATTERN = re.compile(
        r"\beval\s*\(\s*@?\s*(?:" + _PHP_DECODERS + r"\s*\(\s*@?\s*)*"
        r"(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(",
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpPregReplaceEvalRule(WebShellRule):
    name = "php-preg-replace-e"
    hints = ("preg_replace",)
    description = "PHP preg_replace() with the /e (evaluate) modifier"
    _PATTERN = re.compile(
        r"\bpreg_replace\s*\(\s*(['\"])([^\w\s\\])(?:(?!\1)[^\n])*?\2[a-zA-Z]*e[a-zA-Z]*\1",
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpConcatenatedCallRule(WebShellRule):
    name = "php-concatenated-call"
    hints = ("$_",)
    description = "PHP function name glued from string pieces, then called on request input"
    REACH = 2000
    _PATTERN = re.compile(
        r"\$(\w+)\s*=\s*(?:(['\"])[^'\"\n]*\2\s*\.\s*)+(['\"])[^'\"\n]*\3\s*;"
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN

    def find(self, text: str) -> Optional[SignatureHit]:
        # Two steps instead of one regex with a 2000-char lazy gap, which is slow on big files.
        for match in self._PATTERN.finditer(text):
            call = self._call_pattern(match.group(1))
            if call.search(text, match.end(), match.end() + self.REACH):
                return SignatureHit(self.name, self.description, text.count("\n", 0, match.start()) + 1)
        return None

    @staticmethod
    @lru_cache(maxsize=256)
    def _call_pattern(variable: str) -> Pattern[str]:
        return re.compile(r"\$" + re.escape(variable) + r"\s*\(\s*@?\s*" + _SUPERGLOBAL, re.IGNORECASE)


class PythonEvalOnRequestRule(WebShellRule):
    name = "python-eval-on-request"
    hints = ("request",)
    description = "Python eval/exec/compile/__import__ on request data"
    _PATTERN = re.compile(
        r"(?<![\w.])(?:eval|exec|compile|__import__)\s*\([^)\n]*?"
        r"\brequest\s*\.\s*(?:GET|POST|args|form|data|json|body|query_params)\b"
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PythonExecBase64Rule(WebShellRule):
    name = "python-exec-base64"
    hints = ("b64decode",)
    description = "Python exec() of base64-decoded data"
    _PATTERN = re.compile(
        r"\bexec\s*\(\s*(?:base64\s*\.\s*|__import__\s*\(\s*['\"]base64['\"]\s*\)\s*\.\s*)?"
        r"b64decode\s*\("
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PythonCommandOnRequestRule(WebShellRule):
    name = "python-command-on-request"
    hints = ("request",)
    description = "Python os.popen/os.system/subprocess on request data"
    _PATTERN = re.compile(
        r"\b(?:os\s*\.\s*(?:popen|system)|subprocess\s*\.\s*\w+)\s*\("
        r"[^)\n]*\brequest\s*\.\s*(?:GET|POST|args|form|values|data|json|query_params|body)\b"
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class JavaRuntimeExecRule(WebShellRule):
    name = "java-runtime-exec-parameter"
    hints = ("getparameter",)
    description = "Java Runtime.exec() on a request parameter"
    _PATTERN = re.compile(
        r"Runtime\s*(?:\.\s*getRuntime\s*\(\s*\))?\s*\.\s*exec\s*\(\s*request\s*\.\s*getParameter\s*\("
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class LongBase64LiteralRule(WebShellRule):
    name = "long-base64-literal"
    description = "String literal of more than 2000 base64 characters"
    _PATTERN = re.compile(r"([\"'])[A-Za-z0-9+/]{2001,}={0,2}\1")

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class WebShellDetector:
    """Runs every signature over a file's content."""

    MAX_BYTES = 5 * 1024 * 1024
    RULES: ClassVar[Sequence[WebShellRule]] = (
        PhpEvalBase64Rule(),
        PhpCommandOnInputRule(),
        PhpEvalOnInputRule(),
        PhpBacktickOnInputRule(),
        PhpSuperglobalCallRule(),
        PhpEvalDecodeChainRule(),
        PhpPregReplaceEvalRule(),
        PhpConcatenatedCallRule(),
        PythonExecBase64Rule(),
        PythonCommandOnRequestRule(),
        PythonEvalOnRequestRule(),
        JavaRuntimeExecRule(),
        LongBase64LiteralRule(),
    )

    @classmethod
    def scan_text(cls, text: str) -> List[SignatureHit]:
        lowered = text.lower()
        return [
            hit for rule in cls.RULES if rule.applies(lowered)
            for hit in [rule.find(text)] if hit is not None
        ]

    @classmethod
    def scan_file(cls, path: str) -> List[SignatureHit]:
        """Hits in the first ``MAX_BYTES`` of the file; none when it cannot be read."""
        try:
            with open(path, "rb") as handle:
                data = handle.read(cls.MAX_BYTES)
        except OSError:
            return []
        return cls.scan_text(data.decode("latin-1"))
