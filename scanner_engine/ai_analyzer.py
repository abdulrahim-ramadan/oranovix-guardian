"""
Optional AI-powered analysis layer using the Google Gemini free-tier API.

This module implements the Strategy pattern for AI analysis of security scan
results.  The abstract base ``BaseAIAnalyzer`` defines the contract; concrete
implementations (``GeminiAnalyzer``) and a null-object placeholder
(``NoOpAnalyzer``) satisfy it.  Callers receive richer, contextual
recommendations for detected issues when a valid ``GEMINI_API_KEY`` is
available, and fall back silently to ``None`` when AI is unavailable or the
API call fails.

Key classes:
  - ``AIAnalysis``      — frozen dataclass holding the structured AI response.
  - ``BaseAIAnalyzer``  — ABC declaring the ``analyze`` / ``is_available`` contract.
  - ``GeminiAnalyzer``  — live implementation backed by ``google.generativeai``.
  - ``NoOpAnalyzer``    — null-object used when AI is disabled or not configured.

Version: 1.1.0
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from .base import Issue, ScanResult
from .gemini_config import DEFAULT_GEMINI_MODEL, GeminiConfig, GeminiModelNotFoundError


# ---------------------------------------------------------------------------
# Data model for AI analysis
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysis:
    """Structured result returned by an AI analysis pass.

    All fields are populated from the model's JSON response.  ``model_used``
    records which Gemini model variant produced the output so results can be
    reproduced or compared across model versions.

    Attributes:
        summary:             Short executive summary (2–3 sentences).
        overall_risk:        Qualitative risk rating: Low | Medium | High | Critical.
        top_recommendations: Ordered list of the most important remediation actions.
        detailed_insights:   Deeper observations about the scanned codebase.
        model_used:          Identifier of the generative model that produced this result.
    """

    summary: str
    overall_risk: str
    top_recommendations: List[str]
    detailed_insights: List[str]
    model_used: str = DEFAULT_GEMINI_MODEL


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseAIAnalyzer(ABC):
    """Abstract contract that every AI analyzer implementation must satisfy.

    Concrete subclasses must implement both ``analyze`` and ``is_available``
    so that calling code can query availability before attempting a (potentially
    expensive) API call, and can treat all analyzers polymorphically.
    """

    @abstractmethod
    def analyze(self, scan_result: ScanResult) -> Optional[AIAnalysis]:
        """Analyze a completed scan and return AI-generated insights.

        Args:
            scan_result: The ``ScanResult`` object produced by the scanner engine,
                         including all detected issues and aggregate statistics.

        Returns:
            An ``AIAnalysis`` instance on success, or ``None`` if the service is
            unavailable or the API call fails.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Report whether the underlying AI service is configured and reachable.

        Returns:
            ``True`` if an API key is present and the client was initialised
            successfully; ``False`` otherwise.
        """


# ---------------------------------------------------------------------------
# Gemini implementation
# ---------------------------------------------------------------------------

class GeminiAnalyzer(BaseAIAnalyzer):
    """AI analyzer backed by the Google Gemini generative model (free tier).

    On construction the analyzer attempts to configure the ``google.generativeai``
    client with the provided (or environment-sourced) API key.  All failures
    are handled silently so that the rest of the application continues to work
    without AI enrichment.

    Class attributes:
        MAX_ISSUES_IN_PROMPT: Hard cap on issues included in the prompt to
                              stay within free-tier token limits.
    """

    MAX_ISSUES_IN_PROMPT = 15  # keep tokens low for free tier

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None) -> None:
        """Initialise the Gemini analyzer and attempt to create the API client.

        Args:
            api_key: Explicit Gemini API key.  When omitted the key is read
                     from the ``GEMINI_API_KEY`` environment variable.  If
                     neither source provides a key, the analyzer degrades
                     gracefully to ``is_available() == False``.
        """
        # Prefer an explicitly-supplied key; fall back to the environment variable.
        self._api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self._model = model or GeminiConfig.model_name()
        self._last_error = ""
        self._client = None
        if self._api_key:
            self._init_client()

    def _init_client(self) -> None:
        """Configure the ``google.generativeai`` client and create the model handle.

        Swallows all exceptions (import errors, network errors, invalid keys) so
        that a missing or misconfigured ``google-generativeai`` package does not
        crash the application at startup.
        """
        try:
            from google.generativeai.client import configure  # type: ignore
            from google.generativeai.generative_models import GenerativeModel  # type: ignore
            configure(api_key=self._api_key)
            self._client = GenerativeModel(self._model)
        except Exception as exc:
            # Leave self._client as None; is_available() will return False.
            self._client = None
            self._last_error = f"Gemini client could not start ({type(exc).__name__}: {exc})."

    @property
    def model(self) -> str:
        return self._model

    @property
    def last_error(self) -> str:
        """Human-readable reason for the most recent failure, or an empty string."""
        return self._last_error

    @staticmethod
    def _is_model_not_found(exc: Exception) -> bool:
        return type(exc).__name__ == "NotFound" or "404" in str(exc)

    def is_available(self) -> bool:
        """Return True only when both an API key and a live client are present.

        Returns:
            ``True`` if the client was successfully initialised, ``False`` otherwise.
        """
        return bool(self._api_key and self._client)

    def analyze(self, scan_result: ScanResult) -> Optional[AIAnalysis]:
        """Send the scan summary to Gemini and return structured AI insights.

        Builds a security-engineer prompt from the scan statistics and the top
        issues, sends it to the Gemini API, and parses the JSON response into
        an ``AIAnalysis`` dataclass.

        Args:
            scan_result: The completed scan result to analyse.

        Returns:
            An ``AIAnalysis`` instance if the API call succeeds and the response
            can be parsed; ``None`` if the analyzer is unavailable or the request
            fails, in which case ``last_error`` explains why (e.g. a retired model).
        """
        if not self.is_available():
            return None
        try:
            prompt = self._build_prompt(scan_result)
            response = self._client.generate_content(prompt)  # type: ignore
            analysis = self._parse_response(response.text)
            analysis.model_used = self._model
            self._last_error = ""
            return analysis
        except Exception as exc:
            if self._is_model_not_found(exc):
                self._last_error = str(GeminiModelNotFoundError(self._model))
            else:
                self._last_error = f"Gemini request failed ({type(exc).__name__}: {exc})."
            return None

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(self, result: ScanResult) -> str:
        """Compose the prompt string sent to the Gemini model.

        Only the first ``MAX_ISSUES_IN_PROMPT`` issues are included to avoid
        exceeding the free-tier context window.  The model is instructed to
        respond with a strict JSON schema so that ``_parse_response`` can
        deserialise the output reliably.

        Args:
            result: The scan result whose statistics and issues populate the prompt.

        Returns:
            A formatted multi-line string ready to pass to ``generate_content``.
        """
        issues_text = ""
        # Enumerate issues with a 1-based index for readable prompt formatting.
        for i, issue in enumerate(result.issues[: self.MAX_ISSUES_IN_PROMPT], 1):
            issues_text += (
                f"{i}. [{issue.severity.value}] {issue.title}\n"
                f"   File: {issue.filename}:{issue.line_number}\n"
                f"   {issue.description}\n\n"
            )

        return f"""You are a senior application security engineer. Analyze the following security scan results and provide actionable insights.

SCAN SUMMARY:
- Target: {result.target_path}
- Files scanned: {result.files_scanned}
- Total issues: {result.total_issues}
- Critical: {result.critical_count}, High: {result.high_count}, Medium: {result.medium_count}, Low: {result.low_count}
- Risk Score: {result.risk_score}/100

TOP ISSUES:
{issues_text}

Provide a JSON response with this exact structure:
{{
  "summary": "2-3 sentence executive summary",
  "overall_risk": "Low|Medium|High|Critical",
  "top_recommendations": ["rec1", "rec2", "rec3", "rec4", "rec5"],
  "detailed_insights": ["insight1", "insight2", "insight3"]
}}"""

    @staticmethod
    def _parse_response(text: str) -> AIAnalysis:
        """Deserialise the Gemini text response into an ``AIAnalysis`` object.

        Uses a regex to locate the first ``{...}`` JSON block in the response
        (which may be surrounded by markdown fences or explanatory prose) and
        then parses it with ``json.loads``.  If parsing fails for any reason,
        a fallback ``AIAnalysis`` is returned with the raw text as the summary.

        Args:
            text: The raw string returned by ``GenerativeModel.generate_content``.

        Returns:
            A populated ``AIAnalysis`` instance.  The ``model_used`` field is
            left at its default value because the response text does not include
            the model identifier.
        """
        import json, re
        # Extract the first JSON object block from potentially mixed-format output.
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                return AIAnalysis(
                    summary=data.get("summary", ""),
                    overall_risk=data.get("overall_risk", "Unknown"),
                    top_recommendations=data.get("top_recommendations", []),
                    detailed_insights=data.get("detailed_insights", []),
                )
            except json.JSONDecodeError:
                # JSON block found but malformed; fall through to raw-text fallback.
                pass
        # Fallback: wrap the first 500 characters of raw output in an AIAnalysis.
        return AIAnalysis(
            summary=text[:500],
            overall_risk="Unknown",
            top_recommendations=[],
            detailed_insights=[],
        )


# ---------------------------------------------------------------------------
# Null object (no-op) for when AI is disabled
# ---------------------------------------------------------------------------

class NoOpAnalyzer(BaseAIAnalyzer):
    """Null-object implementation of ``BaseAIAnalyzer`` used when AI is disabled.

    Satisfies the ``BaseAIAnalyzer`` interface without making any network calls
    or requiring any external dependencies.  Callers receive ``None`` from
    ``analyze`` and ``False`` from ``is_available``, allowing the rest of the
    application to operate normally without AI enrichment.
    """

    def is_available(self) -> bool:
        """Always returns ``False`` — this analyzer performs no real work.

        Returns:
            ``False``.
        """
        return False

    def analyze(self, scan_result: ScanResult) -> Optional[AIAnalysis]:
        """No-op implementation; always returns ``None``.

        Args:
            scan_result: Ignored.

        Returns:
            ``None``.
        """
        return None
