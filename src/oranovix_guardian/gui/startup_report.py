"""
What the scanner console shows at start: real state, not fixed texts.

``StartupState.collect()`` reads the version, the rule count, the
vulnerability database, the AI setting and which monitors are switched
on. It reads local files only (settings, the rules, the OSV database and
the credential store) and is meant to run off the Tk thread.
``startup_lines()`` turns a state into translated console lines.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from oranovix_guardian.core.language_manager import LanguageManager

#: ``off``: no API key; ``offline``: a key, but online AI not allowed;
#: ``online``: a key and the user allowed online AI.
AI_STATES = ("off", "offline", "online")


@dataclass(frozen=True)
class StartupState:
    version: str
    rules: int
    osv_updated: Optional[datetime]
    osv_advisories: int
    ai: str
    live_defense: bool
    threat_feed: bool
    log_sentinel: bool
    language: str

    @staticmethod
    def ai_state() -> str:
        from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig
        if not GeminiConfig.api_key():
            return "off"
        return "online" if GeminiConfig.online_allowed() else "offline"

    @classmethod
    def collect(cls) -> "StartupState":
        """Read the current state. A part that cannot be read counts as off or missing."""
        from oranovix_guardian.core.version import APP_VERSION

        rules = 0
        try:
            from oranovix_guardian.scanner_engine.rule_engine import RuleEngine
            rules = sum(1 for rule in RuleEngine().rules if rule.enabled)
        except Exception:
            pass

        osv_updated: Optional[datetime] = None
        osv_advisories = 0
        try:
            from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
            database = OSVDatabase()
            osv_updated = database.updated_at()
            osv_advisories = database.advisory_count() if osv_updated else 0
        except Exception:
            pass

        try:
            ai = cls.ai_state()
        except Exception:
            ai = "off"

        return cls(
            version=APP_VERSION,
            rules=rules,
            osv_updated=osv_updated,
            osv_advisories=osv_advisories,
            ai=ai,
            live_defense=_section_flag("live_defense", "running"),
            threat_feed=_section_flag("threat_feed", "enabled"),
            log_sentinel=_section_flag("log_sentinel", "running"),
            language=LanguageManager().current_display_name,
        )


def _section_flag(section: str, key: str) -> bool:
    try:
        from oranovix_guardian.core.app_paths import AppPaths
        from oranovix_guardian.core.settings_file import SettingsFile
        return SettingsFile(str(AppPaths.settings_path())).section(section).get(key) is True
    except Exception:
        return False


def startup_lines(state: StartupState) -> List[Tuple[str, str]]:
    """``(text, level)`` pairs for the console, in the active language."""
    lm = LanguageManager()
    on, off = lm.t("boot_on"), lm.t("boot_off")
    lines: List[Tuple[str, str]] = [
        (lm.t("boot_version", version=state.version), "info"),
        (lm.t("boot_rules", count=state.rules), "ok" if state.rules else "error"),
    ]
    if state.osv_updated is not None:
        lines.append((lm.t("boot_osv_ready", count=state.osv_advisories,
                           date=state.osv_updated.strftime("%Y-%m-%d")), "ok"))
    else:
        lines.append((lm.t("boot_osv_missing"), "info"))
    ai = state.ai if state.ai in AI_STATES else "off"
    lines.append((lm.t(f"boot_ai_{ai}"), "ok" if ai == "online" else "info"))
    for key, running in (
        ("boot_live_defense", state.live_defense),
        ("boot_threat_feed", state.threat_feed),
        ("boot_log_sentinel", state.log_sentinel),
    ):
        lines.append((lm.t(key, state=on if running else off), "ok" if running else "info"))
    lines.append((lm.t("boot_language", language=state.language), "info"))
    lines.append((lm.t("boot_ready"), "done"))
    return lines
