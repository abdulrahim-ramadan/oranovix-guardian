"""AI privacy gaps, the AI fix callback thread, translations, Gemini SDK.

The secret in every redaction case is letters only, so the long
mixed-token rule cannot catch it by accident.
"""
from __future__ import annotations

import ast
import json
import sys
import threading
import types
from pathlib import Path
from typing import Any, Callable, List

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.core.redactor import Redactor

ROOT = Path(__file__).resolve().parents[2]
SECRET = "CorrectHorseBatteryStaple"


# ---------------------------------------------------------------------------
# Redactor: 27 cases
# ---------------------------------------------------------------------------

REDACTION_CASES = [
    # Shell scripts and PowerShell: the value after = is data.
    ("deploy.sh", f"export DB_PASSWORD={SECRET}\n"),
    ("start.bash", f"DB_PASSWORD={SECRET} ./run-server\n"),
    ("env.zsh", f"export API_TOKEN={SECRET}\n"),
    ("setup.ps1", f"$env:DB_PASSWORD={SECRET}\n"),
    ("setup.ps1", f"$Password = {SECRET}\n"),
    # Dockerfile: ENV and ARG, with = or a space.
    ("Dockerfile", f"FROM postgres:16\nENV POSTGRES_PASSWORD={SECRET}\n"),
    ("Dockerfile", f"ENV POSTGRES_PASSWORD {SECRET}\n"),
    ("api.dockerfile", f"ARG NPM_TOKEN={SECRET}\n"),
    # Credential files.
    (".pgpass", f"db.internal:5432:shop:admin:{SECRET}\n"),
    (".htpasswd", f"admin:$apr1$abcd$" + SECRET + "\n"),
    (".npmrc", f"//registry.npmjs.org/:_authToken={SECRET}\n"),
    (".netrc", f"machine example.com login admin password {SECRET}\n"),
    # XML / HTML elements named after a secret.
    ("web.config.xml", f"<config><password>{SECRET}</password></config>\n"),
    ("settings.xml", f"<db:Password type=\"plain\">{SECRET}</db:Password>\n"),
    ("page.html", f"<div><api-key>{SECRET}</api-key></div>\n"),
    # SQL.
    ("setup.sql", f"CREATE USER app IDENTIFIED BY {SECRET};\n"),
    ("setup.sql", f"ALTER USER app IDENTIFIED BY \"{SECRET}\";\n"),
    # Heredocs and Ruby literals.
    ("config.php", f"<?php\n$pw = <<<EOT\n{SECRET}\nEOT;\n"),
    ("config.php", f"<?php\n$pw = <<<'EOT'\n{SECRET}\nEOT;\n"),
    ("app.rb", f"password = %q({SECRET})\n"),
    ("app.rb", f"token = %Q{{{SECRET}}}\n"),
    # Comment without a space before it.
    ("views.py", f"x=1#{SECRET}\n"),
    # Unquoted value of a secret-like name in a file with no known type.
    ("Makefile", f"DB_PASSWORD := {SECRET}\n"),
    # Forms that were already covered stay covered.
    (".env", f"PASSWORD={SECRET}\n"),
    ("views.py", f'password = "{SECRET}"\n'),
    ("app.js", f"const apiKey = '{SECRET}';\n"),
    ("app.properties", f"db.password={SECRET}\n"),
]


@pytest.mark.parametrize("file_name, code", REDACTION_CASES, ids=[
    f"{i:02d}-{name}" for i, (name, _) in enumerate(REDACTION_CASES, 1)
])
def test_the_secret_never_leaves(file_name: str, code: str) -> None:
    assert SECRET not in Redactor.redact_code(code, file_name)


def test_there_are_27_cases() -> None:
    assert len(REDACTION_CASES) == 27


@pytest.mark.parametrize("file_name, code", [
    ("views.py", "password = get_password()\nlimit = max_items\n"),
    ("views.py", "password = settings.DB_PASSWORD\n"),
    ("views.py", "token: Optional[str] = None\n"),
    ("views.py", "if token == expected_token:\n    pass\n"),
    ("deploy.sh", "echo starting\nrsync -a src/ dst/\n"),
    ("page.html", "<p>Press any key</p>\n<key-hint>Esc</key-hint>\n"),
    ("views.py", "half = total // 2\n"),
])
def test_ordinary_code_keeps_its_shape(file_name: str, code: str) -> None:
    assert Redactor.redact_code(code, file_name) == code


def test_names_stay_readable() -> None:
    assert Redactor.redact_code(f"export DB_PASSWORD={SECRET}\n", "deploy.sh").startswith("export DB_PASSWORD=")
    assert Redactor.redact_code(f"<password>{SECRET}</password>", "a.xml").startswith("<password>")
    assert "IDENTIFIED BY" in Redactor.redact_code(f"CREATE USER app IDENTIFIED BY {SECRET};", "a.sql")


def test_prose_is_redacted_too() -> None:
    assert SECRET not in Redactor.redact(f"Found <password>{SECRET}</password> in web.xml")
    assert SECRET not in Redactor.redact(f"User created with IDENTIFIED BY {SECRET}")


# ---------------------------------------------------------------------------
# AI fix: the suggestion reaches the widgets on the Tk thread
# ---------------------------------------------------------------------------

class FakeWidget:
    def __init__(self) -> None:
        self.scheduled: List[Any] = []
        self.destroyed = False

    def after(self, delay: int, fn: Callable[..., Any], *args: Any) -> None:
        if self.destroyed:
            import tkinter
            raise tkinter.TclError("application has been destroyed")
        self.scheduled.append((fn, args))


def test_the_callback_is_handed_to_the_ui_thread() -> None:
    from oranovix_guardian.gui.ui_thread import on_ui_thread
    widget = FakeWidget()
    called: List[Any] = []
    callback = on_ui_thread(widget, called.append)

    worker = threading.Thread(target=callback, args=("suggestion",))
    worker.start()
    worker.join()

    assert called == []                                   # nothing ran in the worker
    fn, args = widget.scheduled[0]
    fn(*args)
    assert called == ["suggestion"]


def test_a_destroyed_window_is_not_an_error() -> None:
    from oranovix_guardian.gui.ui_thread import on_ui_thread
    widget = FakeWidget()
    widget.destroyed = True

    on_ui_thread(widget, lambda value: None)("late")      # must not raise


def test_results_page_builds_the_fix_panel_on_the_ui_thread() -> None:
    source = (ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "results_page.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "generate_fix_async"
    ]

    assert calls, "generate_fix_async is not called any more"
    for call in calls:
        callback = call.args[2] if len(call.args) > 2 else None
        assert isinstance(callback, ast.Call) and getattr(callback.func, "id", "") == "on_ui_thread", (
            "the AI fix callback must go through on_ui_thread"
        )


# ---------------------------------------------------------------------------
# Translations
# ---------------------------------------------------------------------------

def _translations(lang: str) -> dict:
    return json.loads((AppPaths.resource("translations") / f"{lang}.json").read_text(encoding="utf-8"))


def test_all_three_languages_have_the_same_keys() -> None:
    english = set(_translations("en"))

    for lang in ("de", "ar"):
        other = set(_translations(lang))
        assert sorted(english - other) == [], f"missing in {lang}"
        assert sorted(other - english) == [], f"only in {lang}"


@pytest.mark.parametrize("key", ["ai_fix", "cancel", "rules_manager", "save_rule", "rule_pattern"])
def test_former_english_only_keys_are_translated(key: str) -> None:
    assert _translations("de")[key] != _translations("en")[key]
    assert _translations("ar")[key] != _translations("en")[key]


def test_placeholders_match_across_languages() -> None:
    import re
    english = _translations("en")
    for lang in ("de", "ar"):
        other = _translations(lang)
        for key, text in english.items():
            assert set(re.findall(r"\{(\w+)\}", text)) == set(re.findall(r"\{(\w+)\}", other[key])), (lang, key)


# ---------------------------------------------------------------------------
# Gemini SDK: google-genai, not the archived google-generativeai
# ---------------------------------------------------------------------------

def test_no_code_imports_the_archived_sdk() -> None:
    offenders = []
    for path in ROOT.glob("**/*.py"):
        if any(part in ("venv", "build", "dist", "release", "corpus") for part in path.parts):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        if "google.generativeai" in path.read_text(encoding="utf-8", errors="ignore"):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_requirements_name_the_new_sdk() -> None:
    requirements = (ROOT / "src" / "requirements.txt").read_text(encoding="utf-8")

    assert "google-genai" in requirements
    assert "google-generativeai" not in requirements


class FakeGenAI:
    """Stands in for ``google.genai``; records what would be sent."""

    def __init__(self) -> None:
        self.api_keys: List[str] = []
        self.requests: List[dict] = []
        outer = self

        class Models:
            def generate_content(self, model: str, contents: str) -> Any:
                outer.requests.append({"model": model, "contents": contents})
                return types.SimpleNamespace(text='{"summary": "s", "overall_risk": "High"}')

        class Client:
            def __init__(self, api_key: str) -> None:
                outer.api_keys.append(api_key)
                self.models = Models()

        self.Client = Client


@pytest.fixture
def fake_genai(monkeypatch: pytest.MonkeyPatch) -> FakeGenAI:
    fake = FakeGenAI()
    google = types.ModuleType("google")
    genai = types.ModuleType("google.genai")
    genai.Client = fake.Client  # type: ignore[attr-defined]
    google.genai = genai  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    return fake


@pytest.fixture
def consent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[bool], object]:
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig
    path = tmp_path / "settings.json"
    monkeypatch.setattr(GeminiConfig, "settings_path", staticmethod(lambda: path))
    return GeminiConfig.set_online_consent


def _result() -> Any:
    from oranovix_guardian.scanner_engine.base import Issue, ScanResult, Severity
    from oranovix_guardian.scanner_engine.categories import IssueCategory
    result = ScanResult(target_path=r"C:\Users\someone\shop", scan_id="1")
    result.issues = [
        Issue("B608", "SQL built from strings", f'password = "{SECRET}"', Severity.HIGH,
              r"C:\Users\someone\shop\views.py", 3, category=IssueCategory.SQL_INJECTION),
        Issue("SEC001", "Hardcoded Secret", "x", Severity.CRITICAL,
              r"C:\Users\someone\shop\settings.py", 1, category=IssueCategory.SECRET),
    ]
    return result


def test_the_analyzer_uses_google_genai(fake_genai: FakeGenAI, consent: Callable[[bool], object]) -> None:
    from oranovix_guardian.scanner_engine.ai_analyzer import GeminiAnalyzer
    consent(True)

    analyzer = GeminiAnalyzer(api_key="key-123", model="gemini-flash-latest")
    analysis = analyzer.analyze(_result())

    assert analysis is not None
    assert fake_genai.api_keys == ["key-123"]
    (request,) = fake_genai.requests
    assert request["model"] == "gemini-flash-latest"
    assert SECRET not in request["contents"]                 # redaction unchanged
    assert "Hardcoded Secret" not in request["contents"]     # secret findings withheld
    assert "someone" not in request["contents"]


def test_the_analyzer_sends_nothing_without_consent(fake_genai: FakeGenAI, consent: Callable[[bool], object]) -> None:
    from oranovix_guardian.scanner_engine.ai_analyzer import GeminiAnalyzer
    consent(False)

    assert GeminiAnalyzer(api_key="key-123").analyze(_result()) is None
    assert fake_genai.requests == []


def test_a_404_from_the_new_sdk_names_the_model(fake_genai: FakeGenAI, consent: Callable[[bool], object]) -> None:
    from oranovix_guardian.scanner_engine.ai_analyzer import GeminiAnalyzer
    consent(True)

    class ClientError(Exception):
        code = 404

    analyzer = GeminiAnalyzer(api_key="key-123", model="gemini-old")

    def missing(model: str, contents: str) -> Any:
        raise ClientError("model not available")

    analyzer._client._client.models.generate_content = missing  # type: ignore[union-attr]
    assert analyzer.analyze(_result()) is None
    assert "gemini-old" in analyzer.last_error and "404" in analyzer.last_error
