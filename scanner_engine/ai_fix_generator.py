"""
AI-powered and offline fix suggestion generator for Oranovix Guardian.

Provides two complementary fix generation strategies:

1. OfflineFixDatabase — instant rule-based suggestions from a curated
   dictionary of known vulnerability fixes, requiring zero network access.

2. AIFixGenerator — primary strategy using Gemini API; automatically falls
   back to OfflineFixDatabase when no API key is configured or the network
   is unavailable.  Results are cached in memory to avoid repeated API calls.

Version: 1.0.0
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional

from .base import Issue


# ---------------------------------------------------------------------------
# FixSuggestion data model
# ---------------------------------------------------------------------------

@dataclass
class FixSuggestion:
    """Structured fix suggestion for a single security issue."""
    original_code: str
    fixed_code: str
    explanation: str
    prevention: str
    confidence: float   # 0.0 (generic) → 1.0 (highly specific)
    source: str = "offline"  # "gemini" or "offline"


# ---------------------------------------------------------------------------
# Offline fix database
# ---------------------------------------------------------------------------

class OfflineFixDatabase:
    """Curated dictionary of fix templates for common vulnerability types.

    Each entry maps a keyword (matched case-insensitively against the
    issue's rule_id and title) to a (fixed_code, explanation, prevention)
    triple.  The first matching keyword wins.
    """

    # Ordered list of (keyword, fixed_code, explanation, prevention) tuples.
    # Keyword matching is case-insensitive against "{rule_id} {title}".
    _ENTRIES = [
        (
            "SQL",
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            "Parameterized queries separate SQL code from data, making injection impossible.",
            "Never build SQL strings by concatenation or f-strings with user input. "
            "Always use placeholders (?, %s) with a parameter tuple.",
        ),
        (
            "eval",
            "# Safe alternative to eval():\nresult = ast.literal_eval(user_input)",
            "ast.literal_eval() safely parses Python literals without executing code.",
            "Avoid eval() entirely in production. Use json.loads() for JSON data, "
            "ast.literal_eval() for Python literals, or define explicit parsers.",
        ),
        (
            "exec",
            "# Replace exec() with explicit functions or subprocess:\n"
            "result = subprocess.run(['command', '--arg'], capture_output=True, text=True)",
            "exec() with user input allows full code execution. subprocess.run() "
            "with a list argument avoids shell injection.",
            "Never pass user-controlled strings to exec(). Define functions instead "
            "of dynamically executing code strings.",
        ),
        (
            "password",
            "import os\npassword = os.environ.get('APP_PASSWORD')",
            "Environment variables keep secrets out of source code and version control.",
            "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) for "
            "production. At minimum, use environment variables and never commit "
            "secrets to git.",
        ),
        (
            "md5",
            "import hashlib\nhash_value = hashlib.sha256(data).hexdigest()",
            "SHA-256 is cryptographically secure; MD5 has known collision vulnerabilities.",
            "Use SHA-256 or SHA-3 for general hashing. For password storage use "
            "bcrypt, argon2-cffi, or hashlib.scrypt().",
        ),
        (
            "sha1",
            "import hashlib\nhash_value = hashlib.sha256(data).hexdigest()",
            "SHA-1 is deprecated for cryptographic use. SHA-256 is the current minimum.",
            "Replace all SHA-1 usage with SHA-256 or stronger. "
            "NIST deprecated SHA-1 for most uses in 2011.",
        ),
        (
            "pickle",
            "import json\ndata = json.loads(serialized_string)  # safe deserialization",
            "JSON deserialization cannot execute arbitrary code unlike pickle.",
            "Use JSON, msgpack, or protobuf for data exchange with untrusted sources. "
            "Only use pickle for data you generate and control yourself.",
        ),
        (
            "os.system",
            "import subprocess\nresult = subprocess.run(\n"
            "    ['command', '--arg', value],  # list avoids shell injection\n"
            "    capture_output=True, text=True, check=True\n)",
            "subprocess.run() with a list bypasses the shell, preventing injection.",
            "Always pass commands as lists to subprocess. Never use shell=True "
            "with user-controlled input.",
        ),
        (
            "AWS",
            "import os\naws_key = os.environ.get('AWS_ACCESS_KEY_ID')",
            "AWS credentials must never be hardcoded. Use environment variables or "
            "IAM roles.",
            "Use AWS IAM roles for EC2/Lambda workloads. Store credentials in "
            "~/.aws/credentials (never in source). Rotate any exposed key immediately.",
        ),
        (
            "GitHub",
            "import os\ngithub_token = os.environ.get('GITHUB_TOKEN')",
            "GitHub tokens with write access can modify repos and expose private code.",
            "Use GitHub Actions secrets for CI/CD. Revoke any exposed token immediately "
            "and audit recent activity.",
        ),
        (
            "JWT",
            "import os\n# Retrieve token at runtime from secure storage:\ntoken = os.environ.get('SERVICE_JWT_TOKEN')",
            "JWTs in source code are accessible to anyone with repository access "
            "and cannot be rotated without a code change.",
            "Store JWTs in environment variables or a secrets vault. "
            "Use short expiration times (< 1 hour) and implement refresh token rotation.",
        ),
        (
            "path",
            "import os\nbase = '/safe/directory'\n"
            "resolved = os.path.realpath(os.path.join(base, user_input))\n"
            "if not resolved.startswith(base + os.sep):\n"
            "    raise ValueError('Path traversal attempt detected')",
            "Resolving the real path and checking it remains within the base "
            "directory prevents directory traversal.",
            "Always validate that resolved paths stay inside the intended base "
            "directory before opening files.",
        ),
        (
            "marshal",
            "import json\ndata = json.loads(serialized_bytes.decode())",
            "JSON is safe for untrusted data; marshal can execute arbitrary code.",
            "Use JSON, msgpack, or protobuf instead of marshal for data interchange.",
        ),
        (
            "OpenAI",
            "import os\nopenai_key = os.environ.get('OPENAI_API_KEY')",
            "OpenAI keys can be used to make billable API calls if exposed.",
            "Store all API keys in environment variables or a secrets manager. "
            "Set usage limits on exposed keys and rotate immediately.",
        ),
        # Generic fallback — always last
        (
            "__DEFAULT__",
            "# Review this code and apply the principle of least privilege.\n"
            "# See OWASP guidelines for this vulnerability class.",
            "Apply security best practices specific to this vulnerability type.",
            "Follow OWASP Top 10 guidelines and conduct regular security code reviews.",
        ),
    ]

    @classmethod
    def get_fix(cls, issue: Issue) -> FixSuggestion:
        """Return the best available offline fix for the given issue.

        Searches entries in order, matching the keyword against
        ``"{issue.rule_id} {issue.title}"``.  Returns the generic fallback
        entry when no specific match is found.

        Args:
            issue: The security issue requiring a fix.

        Returns:
            A FixSuggestion with confidence 0.7 for specific matches or
            0.3 for the generic fallback.
        """
        search = f"{issue.rule_id} {issue.title}".upper()

        for keyword, fixed_code, explanation, *prevention_parts in cls._ENTRIES:
            prevention = prevention_parts[0] if prevention_parts else ""
            if keyword == "__DEFAULT__":
                return FixSuggestion(
                    original_code=issue.code_snippet,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    prevention=prevention,
                    confidence=0.3,
                    source="offline",
                )
            if keyword.upper() in search:
                return FixSuggestion(
                    original_code=issue.code_snippet,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    prevention=prevention,
                    confidence=0.7,
                    source="offline",
                )

        # Should never reach here because __DEFAULT__ is always last
        return FixSuggestion(
            original_code=issue.code_snippet,
            fixed_code="# Review and fix manually.",
            explanation="No specific fix template available for this issue.",
            prevention="Follow OWASP security guidelines.",
            confidence=0.2,
            source="offline",
        )


# ---------------------------------------------------------------------------
# AI Fix Generator
# ---------------------------------------------------------------------------

class AIFixGenerator:
    """Generates fix suggestions using Gemini API with offline fallback.

    If a Gemini API key is available (supplied at construction, stored in
    settings.json, or in GEMINI_API_KEY env var) and the network is reachable,
    the Gemini REST API is queried for a structured fix.  Any failure
    (network, quota, parse) silently triggers the OfflineFixDatabase fallback.

    Results are cached in memory keyed on (rule_id, file_path, line_number)
    to avoid repeated identical API calls within a session.
    """

    _GEMINI_URL = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-flash:generateContent"
    )

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key or self._load_api_key()
        self._cache: Dict[str, FixSuggestion] = {}

    # ------------------------------------------------------------------
    # API key resolution
    # ------------------------------------------------------------------

    @property
    def api_key(self) -> str:
        return self._api_key

    @api_key.setter
    def api_key(self, value: str) -> None:
        self._api_key = value

    @staticmethod
    def _load_api_key() -> str:
        """Try to read the Gemini API key from settings.json or env var."""
        env_key = os.getenv("GEMINI_API_KEY", "")
        if env_key:
            return env_key
        try:
            if getattr(sys, "frozen", False):
                settings_path = Path(sys.executable).parent / "settings.json"
            else:
                settings_path = Path(__file__).parent.parent / "settings.json"
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            return data.get("api_key", "")
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_fix(self, issue: Issue, code: str = "") -> FixSuggestion:
        """Generate a fix suggestion, trying Gemini first then offline fallback.

        Args:
            issue: The security issue to generate a fix for.
            code:  Full source code of the affected file (optional context).

        Returns:
            A FixSuggestion populated with fix details and a confidence score.
        """
        cache_key = f"{issue.rule_id}:{issue.file_path}:{issue.line_number}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        suggestion: FixSuggestion
        if self._api_key:
            try:
                suggestion = self._query_gemini(issue, code)
            except Exception:
                suggestion = OfflineFixDatabase.get_fix(issue)
        else:
            suggestion = OfflineFixDatabase.get_fix(issue)

        self._cache[cache_key] = suggestion
        return suggestion

    def generate_fix_async(
        self,
        issue: Issue,
        code: str,
        callback: Callable[[FixSuggestion], None],
    ) -> None:
        """Generate a fix in a daemon thread and deliver it via callback.

        Args:
            issue:    The security issue to fix.
            code:     Full source code of the affected file.
            callback: Called with the resulting FixSuggestion when done.
        """
        def _worker() -> None:
            suggestion = self.generate_fix(issue, code)
            callback(suggestion)

        threading.Thread(target=_worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Gemini REST API
    # ------------------------------------------------------------------

    def _query_gemini(self, issue: Issue, code: str) -> FixSuggestion:
        """POST to the Gemini REST API and parse the structured response.

        Args:
            issue: The security issue to fix.
            code:  Full source code for additional context.

        Returns:
            A FixSuggestion from the Gemini response.

        Raises:
            Exception: On any network, parse, or API error.
        """
        import urllib.request

        snippet = issue.code_snippet or (code[:400] if code else "N/A")

        prompt = (
            f"You are a security expert. This code has a {issue.severity.value} "
            f"vulnerability: {issue.title}\n\n"
            f"Vulnerable code (line {issue.line_number}):\n{snippet}\n\n"
            "Provide:\n"
            "1. Fixed code (just the corrected lines, no explanation in code)\n"
            "2. One sentence explanation of why the fix works\n"
            "3. One sentence prevention tip\n\n"
            "Return ONLY valid JSON, no markdown:\n"
            '{"fixed_code": "...", "explanation": "...", "prevention": "..."}'
        )

        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 512},
        }).encode("utf-8")

        url = f"{self._GEMINI_URL}?key={self._api_key}"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))

        raw_text = (
            response_data["candidates"][0]["content"]["parts"][0]["text"]
        )

        # The model sometimes wraps JSON in markdown code fences — strip them
        json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if not json_match:
            raise ValueError("No JSON object found in Gemini response")

        parsed = json.loads(json_match.group(0))

        return FixSuggestion(
            original_code=issue.code_snippet,
            fixed_code=parsed.get("fixed_code", ""),
            explanation=parsed.get("explanation", ""),
            prevention=parsed.get("prevention", ""),
            confidence=0.9,
            source="gemini",
        )
