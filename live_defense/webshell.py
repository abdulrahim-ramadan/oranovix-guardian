"""
Web shell signatures: code that runs attacker input or hides a payload.

One class per rule. Content is read as latin-1, so byte positions and
line numbers stay right even in binary files with code inside.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, List, Optional, Pattern, Sequence


@dataclass(frozen=True)
class SignatureHit:
    rule: str
    description: str
    line: int


class WebShellRule(ABC):
    """One signature."""

    name: ClassVar[str]
    description: ClassVar[str]

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
    description = "PHP eval() of base64-decoded data"
    _PATTERN = re.compile(r"\beval\s*\(\s*@?\s*base64_decode\s*\(", re.IGNORECASE)

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PhpCommandOnInputRule(WebShellRule):
    name = "php-command-on-input"
    description = "PHP system/passthru/shell_exec/assert on request input"
    _PATTERN = re.compile(
        r"\b(?:system|passthru|shell_exec|assert)\s*\(\s*@?\s*\$_(?:GET|POST|REQUEST)\b",
        re.IGNORECASE,
    )

    @property
    def pattern(self) -> Pattern[str]:
        return self._PATTERN


class PythonExecBase64Rule(WebShellRule):
    name = "python-exec-base64"
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
        PythonExecBase64Rule(),
        PythonCommandOnRequestRule(),
        JavaRuntimeExecRule(),
        LongBase64LiteralRule(),
    )

    @classmethod
    def scan_text(cls, text: str) -> List[SignatureHit]:
        return [hit for rule in cls.RULES for hit in [rule.find(text)] if hit is not None]

    @classmethod
    def scan_file(cls, path: str) -> List[SignatureHit]:
        """Hits in the first ``MAX_BYTES`` of the file; none when it cannot be read."""
        try:
            with open(path, "rb") as handle:
                data = handle.read(cls.MAX_BYTES)
        except OSError:
            return []
        return cls.scan_text(data.decode("latin-1"))
