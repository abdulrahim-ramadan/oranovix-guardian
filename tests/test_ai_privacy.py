"""Nothing secret leaves the machine: redaction, consent, and the request itself."""
from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator, List

import keyring
import pytest
from keyring.backends.fail import Keyring as FailKeyring

from core.redactor import REDACTED, Redactor
from scanner_engine import ai_fix_generator
from scanner_engine.ai_analyzer import GeminiAnalyzer
from scanner_engine.ai_fix_generator import AIFixGenerator, is_secret_finding
from scanner_engine.base import Issue, ScanResult, Severity
from scanner_engine.categories import IssueCategory
from scanner_engine.gemini_config import GEMINI_API_KEY_ENV, GeminiConfig
from scanner_engine.secrets_detector import SecretsDetector

# Fake values. Apart from the documented AWS example they are put together at
# runtime, so the file holds nothing that looks like a real provider key.
API_KEY = "test-gemini-key-" + "0" * 20
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
OPENAI_KEY = "s" + "k-" + "a1B2" * 12
GITHUB_TOKEN = "gh" + "p_" + "Z9y8" * 9
JWT_HEAD = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxIn0"
PEM_DASHES = "-" * 5
STRIPE_KEY = "sk" + "_live_" + "51Hx9QaZz8vT"
PLAIN_PASSWORD = "hunter2pass"
WEAK_PASSWORD = "Winter2026!"
HEX_TOKEN = "9f86d081884c7d65" + "9a2feaa0c55ad015"
BASIC_VALUE = base64.b64encode(f"admin:{PLAIN_PASSWORD}".encode()).decode()


def pem_line(edge: str, kind: str) -> str:
    return f"{PEM_DASHES}{edge} {kind} PRIVATE KEY{PEM_DASHES}"
CONNECTION = "postgresql://admin:Pa55word@host"
FULL_PATH = r"C:\Users\someone\projects\shop\billing\views.py"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class FakeResponse:
    """What ``urlopen`` returns: a context manager with ``read()``."""

    def __init__(self, text: str) -> None:
        self._body = json.dumps(
            {"candidates": [{"content": {"parts": [{"text": text}]}}]}
        ).encode("utf-8")

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class FakeHttp:
    """Stands in for ``urllib.request.urlopen`` and records every request."""

    def __init__(self) -> None:
        self.requests: List[urllib.request.Request] = []
        self.error: Exception | None = None

    def __call__(self, request: urllib.request.Request, timeout: float = 0) -> FakeResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return FakeResponse('{"fixed_code": "ok()", "explanation": "e", "prevention": "p"}')

    @property
    def sent_text(self) -> str:
        """The prompt of the single request that was sent."""
        assert len(self.requests) == 1
        data = self.requests[0].data
        assert isinstance(data, bytes)
        return json.loads(data.decode("utf-8"))["contents"][0]["parts"][0]["text"]


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> FakeHttp:
    fake = FakeHttp()
    monkeypatch.setattr(ai_fix_generator.urllib.request, "urlopen", fake)
    return fake


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An empty settings.json, no env key and no credential store."""
    path = tmp_path / "settings.json"
    monkeypatch.setattr(GeminiConfig, "settings_path", staticmethod(lambda: path))
    monkeypatch.delenv(GEMINI_API_KEY_ENV, raising=False)
    previous = keyring.get_keyring()
    keyring.set_keyring(FailKeyring())
    yield path
    keyring.set_keyring(previous)


@pytest.fixture
def consent_given() -> None:
    GeminiConfig.set_online_consent(True)


def make_issue(**overrides: Any) -> Issue:
    values = dict(
        rule_id="B608",
        title="SQL injection through string formatting",
        description="Query built from user input.",
        severity=Severity.HIGH,
        file_path=FULL_PATH,
        line_number=12,
        code_snippet='cursor.execute("SELECT * FROM t WHERE id = %s" % user_id)',
        recommendation="Use parameters.",
        category=IssueCategory.SQL_INJECTION,
    )
    values.update(overrides)
    return Issue(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "secret",
    [
        AWS_KEY,
        OPENAI_KEY,
        GITHUB_TOKEN,
        JWT_HEAD + ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ],
    ids=["aws", "openai", "github", "jwt"],
)
def test_token_formats_are_replaced(secret: str) -> None:
    redacted = Redactor.redact(f'client = connect("{secret}")')

    assert secret not in redacted
    assert redacted == f'client = connect("{REDACTED}")'


def test_jwt_signature_is_removed_too() -> None:
    redacted = Redactor.redact(f"h = '{JWT_HEAD}.SIGNATUREPART'")

    assert "SIGNATUREPART" not in redacted


def test_private_key_block_is_removed() -> None:
    text = (
        f"key = '''{pem_line('BEGIN', 'RSA')}\n"
        "MIIEowIBAAKCAQEAsecretbody\n"
        f"{pem_line('END', 'RSA')}'''\nprint(1)"
    )

    redacted = Redactor.redact(text)

    assert "MIIEowIBAAKCAQEAsecretbody" not in redacted
    assert "print(1)" in redacted


def test_connection_string_keeps_everything_but_the_password() -> None:
    redacted = Redactor.redact(f'engine = create_engine("{CONNECTION}/shop")')

    assert "Pa55word" not in redacted
    assert redacted == f'engine = create_engine("postgresql://admin:{REDACTED}@host/shop")'


@pytest.mark.parametrize(
    "line",
    [
        'password = "hunter2hunter2"',
        "DB_PASSWORD = 'hunter2hunter2'",
        'api_key: str = "hunter2hunter2"',
        'config = {"secret_key": "hunter2hunter2"}',
        "$cfg = ['token' => 'hunter2hunter2'];",
        'String apiKey = "hunter2hunter2";',
        'os.environ["CLIENT_SECRET"] = "hunter2hunter2"',
        'if token == "hunter2hunter2":',
        'connect(host="db", passwd="hunter2hunter2")',
        'auth_token = f"hunter2hunter2"',
    ],
)
def test_literal_assigned_to_a_secret_name_is_replaced(line: str) -> None:
    redacted = Redactor.redact(line)

    assert "hunter2hunter2" not in redacted
    assert REDACTED in redacted


@pytest.mark.parametrize(
    "line",
    [
        'name = "Alice"',
        'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        "password = get_password()",
        'password = ""',
        "return render(request, 'profile.html')",
    ],
)
def test_ordinary_code_is_left_alone(line: str) -> None:
    assert Redactor.redact(line) == line


def test_redaction_is_stable_when_applied_twice() -> None:
    once = Redactor.redact(f'password = "x1y2z3"; url = "{CONNECTION}"; k = "{AWS_KEY}"')

    assert Redactor.redact(once) == once


def test_every_detector_pattern_is_covered() -> None:
    """A pattern added to the scanner is redacted without touching the Redactor."""
    samples = {
        "SEC-AWS01": AWS_KEY,
        "SEC-OAI01": OPENAI_KEY,
        "SEC-GHP01": GITHUB_TOKEN,
        "SEC-PWD01": 'secret = "hunter2hunter2"',
        "SEC-CONN1": "mysql://root:hunter2hunter2@db",
        "SEC-PRVK1": f"{pem_line('BEGIN', 'EC')}\nhunter2hunter2\n{pem_line('END', 'EC')}",
        "SEC-JWT01": JWT_HEAD + ".hunter2hunter2",
    }
    assert {p.rule_id for p in SecretsDetector.patterns()} == set(samples)

    for rule_id, sample in samples.items():
        redacted = Redactor.redact(sample)
        assert REDACTED in redacted, rule_id
        for value in (AWS_KEY, "a1B2a1B2", "Z9y8Z9y8", "hunter2hunter2"):
            assert value not in redacted, rule_id


def test_file_name_drops_the_folder() -> None:
    assert Redactor.file_name(FULL_PATH) == "views.py"
    assert Redactor.file_name("/home/someone/app/views.py") == "views.py"
    assert Redactor.file_name("views.py") == "views.py"


# ---------------------------------------------------------------------------
# What the fix generator sends
# ---------------------------------------------------------------------------

def test_snippet_is_sent_without_the_secret_values(http: FakeHttp, consent_given: None) -> None:
    issue = make_issue(
        code_snippet=(
            f'aws = "{AWS_KEY}"; db = connect("{CONNECTION}"); '
            'cursor.execute("SELECT * FROM t WHERE id = %s" % user_id)'
        ),
    )

    suggestion = AIFixGenerator(api_key=API_KEY).generate_fix(issue)

    assert suggestion.source == "gemini"
    sent = http.sent_text
    assert AWS_KEY not in sent
    assert CONNECTION not in sent
    assert "Pa55word" not in sent
    assert 'aws = "<STR_1>"; db = connect("<STR_2>"); cursor.execute("<STR_3>" % user_id)' in sent


def test_nothing_in_the_whole_request_carries_the_secrets(
    http: FakeHttp, consent_given: None
) -> None:
    issue = make_issue(
        title=f"Injection near {AWS_KEY}",
        code_snippet=f'q = "{CONNECTION}" + user_id; password = "hunter2hunter2"',
    )

    AIFixGenerator(api_key=API_KEY).generate_fix(issue)

    request = http.requests[0]
    assert isinstance(request.data, bytes)
    everything = request.full_url + request.data.decode("utf-8")
    for value in (AWS_KEY, "Pa55word", "hunter2hunter2"):
        assert value not in everything


def test_only_the_file_name_is_sent(http: FakeHttp, consent_given: None) -> None:
    issue = make_issue(description=f"Found in {FULL_PATH}", title=f"SQL injection in {FULL_PATH}")

    AIFixGenerator(api_key=API_KEY).generate_fix(issue)

    sent = http.sent_text
    assert "views.py" in sent
    assert "someone" not in sent
    assert "billing" not in sent


def test_code_fallback_is_redacted_when_there_is_no_snippet(
    http: FakeHttp, consent_given: None
) -> None:
    issue = make_issue(code_snippet="")

    AIFixGenerator(api_key=API_KEY).generate_fix(issue, code=f'KEY = "{AWS_KEY}"\nrun(x)')

    assert AWS_KEY not in http.sent_text
    assert "run(x)" in http.sent_text


# ---------------------------------------------------------------------------
# Allowlist redaction of code
# ---------------------------------------------------------------------------

def test_unknown_secret_formats_never_reach_the_request_body(
    http: FakeHttp, consent_given: None
) -> None:
    snippet = "\n".join([
        f'r = requests.get(url, auth=("admin", "{PLAIN_PASSWORD}"),',
        f'                 headers={{"X-Api-Key": "{STRIPE_KEY}", "Authorization": "Basic {BASIC_VALUE}"}})',
        f"login(user, '{WEAK_PASSWORD}')",
        f"session_id = {HEX_TOKEN}",
        f"curl -H Authorization: Basic {BASIC_VALUE}",
    ])

    AIFixGenerator(api_key=API_KEY).generate_fix(make_issue(code_snippet=snippet))

    request = http.requests[0]
    assert isinstance(request.data, bytes)
    body = request.data.decode("utf-8")
    for value in (STRIPE_KEY, PLAIN_PASSWORD, WEAK_PASSWORD, HEX_TOKEN, BASIC_VALUE, "admin"):
        assert value not in body
    # The structure of the code still arrives.
    sent = http.sent_text
    assert "requests.get(" in sent
    assert "auth=(" in sent
    assert "headers={" in sent
    assert "login(user, " in sent


def test_string_contents_become_numbered_placeholders() -> None:
    redacted = Redactor.redact_code(
        f'r = requests.get(url, auth=("admin", "{PLAIN_PASSWORD}"), verify="{PLAIN_PASSWORD}")'
    )

    # Same value, same placeholder; quotes stay so the type is still visible.
    assert redacted == 'r = requests.get(url, auth=("<STR_1>", "<STR_2>"), verify="<STR_2>")'


@pytest.mark.parametrize(
    "code, expected",
    [
        ("a = 'single quoted'", "a = '<STR_1>'"),
        ('a = "double quoted"', 'a = "<STR_1>"'),
        ('a = """triple\nquoted"""', 'a = """<STR_1>"""'),
        ("a = '''triple\nquoted'''", "a = '''<STR_1>'''"),
        ('a = r"raw\\d+" + b"bytes" + rb"both"', 'a = r"<STR_1>" + b"<STR_2>" + rb"<STR_3>"'),
        ('a = "it\'s \\"escaped\\" inside"', 'a = "<STR_1>"'),
        ('a = f"SELECT * FROM t WHERE id = {user_id}"', 'a = f"<STR_1>{user_id}"'),
        ("a = f\"{d['secret key']}!\"", "a = f\"{d['<STR_1>']}!\""),
        ("const a = `Bearer ${token} for user`;", "const a = `<STR_1>${token}<STR_2>`;"),
        ('var a = $"Server={host};Password=hunter2"; ', 'var a = $"<STR_1>{host}<STR_2>"; '),
        ('var a = @"C:\\dir\\""quoted""";', 'var a = @"<STR_1>";'),
        ("$a = ['key' => 'value one', \"k\" => \"value two\"];", "$a = ['<STR_1>' => '<STR_2>', \"k\" => \"<STR_3>\"];"),
        ('String a = "text" + \'c\' + "more";', 'String a = "<STR_1>" + \'c\' + "<STR_2>";'),
    ],
    ids=[
        "single", "double", "triple-double", "triple-single", "prefixes", "escapes",
        "f-string", "f-string-nested", "js-template", "csharp-interpolated",
        "csharp-verbatim", "php", "java-char",
    ],
)
def test_string_literal_forms(code: str, expected: str) -> None:
    assert Redactor.redact_code(code) == expected


@pytest.mark.parametrize(
    "code",
    ['a = ""', "a = ''", 'a = """"""', "sep = ','", "nl = '\\n'", 'x = d[""] + "/"'],
)
def test_empty_strings_and_single_characters_are_kept(code: str) -> None:
    assert Redactor.redact_code(code) == code


def test_unterminated_string_is_redacted_to_the_end_of_the_line() -> None:
    redacted = Redactor.redact_code(f'x = connect("user", "{PLAIN_PASSWORD}\ny = 1')

    assert PLAIN_PASSWORD not in redacted
    assert redacted.endswith("\ny = 1")


def test_long_mixed_tokens_outside_strings_are_replaced() -> None:
    redacted = Redactor.redact_code(f"API_TOKEN={HEX_TOKEN}\nOTHER={HEX_TOKEN}\nKEY={STRIPE_KEY}")

    assert redacted == "API_TOKEN=<VALUE_1>\nOTHER=<VALUE_1>\nKEY=<VALUE_2>"


def test_ordinary_names_and_called_functions_survive() -> None:
    code = "obj = get_object_or_404(Model, pk=pk)\nvalue = urlsafe_base64_decode(uid)\ntotal = count + 1"

    assert Redactor.redact_code(code) == code


@pytest.mark.parametrize(
    "code, file_name, expected",
    [
        (f"x = 1  # password is {WEAK_PASSWORD}", "views.py", "x = 1  # <COMMENT>"),
        (f"int x = 1; // password is {WEAK_PASSWORD}", "App.java", "int x = 1; // <COMMENT>"),
        (f"/* pw {WEAK_PASSWORD} */ run();", "app.js", "/* <COMMENT> */ run();"),
        (f"# pw {WEAK_PASSWORD}\n// pw {WEAK_PASSWORD}", "", "# <COMMENT>\n// <COMMENT>"),
        ("half = total // 2  # floor", "views.py", "half = total // 2  # <COMMENT>"),
        ("#region Config\nvar x = 1;", "App.cs", "#region Config\nvar x = 1;"),
    ],
    ids=["python", "java", "block", "unknown-language", "python-floor-division", "csharp-directive"],
)
def test_comment_text_is_removed(code: str, file_name: str, expected: str) -> None:
    assert Redactor.redact_code(code, file_name) == expected


@pytest.mark.parametrize(
    "file_name, code, expected",
    [
        (".env", f"PASSWORD={WEAK_PASSWORD}\nDEBUG=true\nPORT=8080", "PASSWORD=<VALUE_1>\nDEBUG=true\nPORT=8080"),
        (".env.production", f"export DB_PASS={WEAK_PASSWORD}", "export DB_PASS=<VALUE_1>"),
        ("config.yaml", f"db:\n  pass: {WEAK_PASSWORD}\n  ssl: false", "db:\n  pass: <VALUE_1>\n  ssl: false"),
        ("app.ini", f"pw = {WEAK_PASSWORD} # prod", "pw = <VALUE_1>"),
        ("app.properties", f'pw="{WEAK_PASSWORD}"', 'pw="<STR_1>"'),
    ],
    ids=["env", "env-export", "yaml", "ini", "quoted"],
)
def test_unquoted_values_in_settings_files_are_replaced(
    file_name: str, code: str, expected: str
) -> None:
    assert Redactor.redact_code(code, file_name) == expected


def test_assignments_in_source_files_are_not_treated_as_settings() -> None:
    code = "password = get_password()\nlimit = max_items"

    assert Redactor.redact_code(code, "views.py") == code


def test_pattern_pass_still_runs_as_a_second_layer() -> None:
    # Outside any string, so only the pattern layer can catch the password.
    redacted = Redactor.redact_code(f"connect({CONNECTION}/shop)", "run.sh")

    assert "Pa55word" not in redacted
    assert REDACTED in redacted


def test_code_redaction_is_stable_when_applied_twice() -> None:
    code = (
        f'a = f"x {{y}} {PLAIN_PASSWORD}"  # note\n'
        f"TOKEN={HEX_TOKEN}\nb = connect('{CONNECTION}')"
    )
    once = Redactor.redact_code(code, "views.py")

    assert Redactor.redact_code(once, "views.py") == once


def test_fix_is_shown_as_returned_with_placeholders(
    http: FakeHttp, consent_given: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    returned = 'requests.get(url, auth=("<STR_1>", "<STR_2>"), timeout=10)'
    monkeypatch.setattr(
        ai_fix_generator.urllib.request, "urlopen",
        lambda request, timeout=0: FakeResponse(json.dumps({"fixed_code": returned})),
    )
    issue = make_issue(code_snippet=f'requests.get(url, auth=("admin", "{PLAIN_PASSWORD}"))')

    suggestion = AIFixGenerator(api_key=API_KEY).generate_fix(issue)

    assert suggestion.fixed_code == returned
    assert PLAIN_PASSWORD not in suggestion.fixed_code


# ---------------------------------------------------------------------------
# Secret findings stay offline
# ---------------------------------------------------------------------------

def test_secret_finding_makes_no_network_call(http: FakeHttp, consent_given: None) -> None:
    issue = make_issue(
        rule_id="SEC-AWS01",
        title="Hardcoded AWS Access Key ID",
        code_snippet=f'aws_key = "{AWS_KEY}"',
        category=IssueCategory.SECRET,
    )

    suggestion = AIFixGenerator(api_key=API_KEY).generate_fix(issue)

    assert http.requests == []
    assert suggestion.source == "offline"
    assert "never sent" in suggestion.notice


def test_issue_merged_with_a_secret_rule_makes_no_network_call(
    http: FakeHttp, consent_given: None
) -> None:
    issue = make_issue(category=IssueCategory.OTHER, also_detected_by=["B105"])

    assert is_secret_finding(issue)
    assert AIFixGenerator(api_key=API_KEY).generate_fix(issue).source == "offline"
    assert http.requests == []


def test_every_detector_finding_is_a_secret_finding(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text(f'aws = "{AWS_KEY}"\nurl = "{CONNECTION}"\n', encoding="utf-8")

    issues = SecretsDetector().scan(str(target)).issues

    assert len(issues) == 2
    assert all(is_secret_finding(issue) for issue in issues)


# ---------------------------------------------------------------------------
# The API key
# ---------------------------------------------------------------------------

def test_key_is_in_the_header_and_not_in_the_url(http: FakeHttp, consent_given: None) -> None:
    AIFixGenerator(api_key=API_KEY, model="gemini-test").generate_fix(make_issue())

    request = http.requests[0]
    assert request.get_header("X-goog-api-key") == API_KEY
    assert API_KEY not in request.full_url
    assert "key=" not in request.full_url
    assert "?" not in request.full_url
    assert request.full_url.endswith("/models/gemini-test:generateContent")
    assert isinstance(request.data, bytes)
    assert API_KEY not in request.data.decode("utf-8")


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.HTTPError(
            "https://generativelanguage.googleapis.com/v1beta/models/m:generateContent",
            403, f"Forbidden for key {API_KEY}", {}, io.BytesIO(b""),  # type: ignore[arg-type]
        ),
        urllib.error.HTTPError(
            "https://generativelanguage.googleapis.com/v1beta/models/m:generateContent",
            404, "Not Found", {}, io.BytesIO(b""),  # type: ignore[arg-type]
        ),
        urllib.error.URLError(f"cannot reach https://generativelanguage.googleapis.com/?key={API_KEY}"),
        ValueError(f"bad response from https://generativelanguage.googleapis.com with {API_KEY}"),
    ],
    ids=["http-403", "http-404", "url-error", "value-error"],
)
def test_failure_message_has_no_key_and_no_url(
    http: FakeHttp, consent_given: None, error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    http.error = error

    with caplog.at_level("DEBUG"):
        suggestion = AIFixGenerator(api_key=API_KEY).generate_fix(make_issue())

    assert suggestion.source == "offline"
    assert suggestion.notice
    for text in (suggestion.notice, caplog.text):
        assert API_KEY not in text
        assert "generativelanguage" not in text
        assert "http://" not in text and "https://" not in text


def test_safe_error_text_removes_key_and_url() -> None:
    error = RuntimeError(f"POST https://example.test/v1/models?key={API_KEY} failed for {API_KEY}")

    text = GeminiConfig.safe_error_text(error, API_KEY)

    assert API_KEY not in text
    assert "https://" not in text
    assert text.startswith("RuntimeError:")


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

def test_default_is_offline(http: FakeHttp) -> None:
    assert GeminiConfig.online_consent() is None
    assert GeminiConfig.online_allowed() is False

    suggestion = AIFixGenerator(api_key=API_KEY).generate_fix(make_issue())

    assert suggestion.source == "offline"
    assert http.requests == []


def test_offline_choice_is_saved_and_respected(http: FakeHttp, isolated_settings: Path) -> None:
    GeminiConfig.set_online_consent(False)

    assert json.loads(isolated_settings.read_text(encoding="utf-8")) == {
        "ai_online_consent": "offline"
    }
    assert GeminiConfig.online_consent() is False
    assert AIFixGenerator(api_key=API_KEY).generate_fix(make_issue()).source == "offline"
    assert http.requests == []


def test_allow_choice_is_saved_and_can_be_changed_back(
    http: FakeHttp, isolated_settings: Path
) -> None:
    isolated_settings.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")

    GeminiConfig.set_online_consent(True)
    assert json.loads(isolated_settings.read_text(encoding="utf-8")) == {
        "theme": "dark", "ai_online_consent": "allow",
    }
    assert AIFixGenerator(api_key=API_KEY).generate_fix(make_issue()).source == "gemini"
    assert len(http.requests) == 1

    GeminiConfig.set_online_consent(False)
    assert AIFixGenerator(api_key=API_KEY).generate_fix(make_issue()).source == "offline"
    assert len(http.requests) == 1


def test_consent_is_asked_only_for_a_request_that_would_go_online() -> None:
    with_key = AIFixGenerator(api_key=API_KEY)
    secret = make_issue(category=IssueCategory.SECRET)

    assert with_key.needs_consent(make_issue()) is True
    assert with_key.needs_consent(secret) is False          # stays offline anyway
    assert AIFixGenerator().needs_consent(make_issue()) is False   # no key

    GeminiConfig.set_online_consent(False)
    assert with_key.needs_consent(make_issue()) is False    # already answered


# ---------------------------------------------------------------------------
# AI analyzer (scan summary)
# ---------------------------------------------------------------------------

class FakeModel:
    def __init__(self) -> None:
        self.prompts: List[str] = []

    def generate_content(self, prompt: str) -> Any:
        self.prompts.append(prompt)

        class Response:
            text = '{"summary": "s", "overall_risk": "High"}'

        return Response()


def make_analyzer() -> tuple[GeminiAnalyzer, FakeModel]:
    analyzer = GeminiAnalyzer(api_key=API_KEY)
    model = FakeModel()
    analyzer._client = model  # type: ignore[assignment]
    return analyzer, model


def make_result() -> ScanResult:
    result = ScanResult(
        target_path=r"C:\Users\someone\projects\shop", scan_id="test", scanner_name="test"
    )
    result.issues = [
        make_issue(
            title=f"SQL injection ({AWS_KEY})",
            description=f'Query in {FULL_PATH} uses "{CONNECTION}" and password = "hunter2hunter2"',
        ),
        make_issue(
            rule_id="SEC-AWS01",
            title="Hardcoded AWS Access Key ID",
            description="Detected a hardcoded AWS Access Key ID (AKIAIO...MPLE) in source code.",
            category=IssueCategory.SECRET,
        ),
    ]
    return result


def test_analyzer_sends_nothing_without_consent() -> None:
    analyzer, model = make_analyzer()

    assert analyzer.analyze(make_result()) is None
    assert model.prompts == []
    assert "switched off" in analyzer.last_error


def test_analyzer_prompt_is_redacted_and_skips_secret_findings(consent_given: None) -> None:
    analyzer, model = make_analyzer()

    assert analyzer.analyze(make_result()) is not None

    (prompt,) = model.prompts
    for value in (AWS_KEY, "Pa55word", "hunter2hunter2", "AKIAIO", "someone", "billing"):
        assert value not in prompt
    assert "Hardcoded AWS Access Key ID" not in prompt
    assert "1 hardcoded-secret finding(s) are not listed" in prompt
    assert "File: views.py:12" in prompt
    assert "- Target: shop" in prompt


def test_analyzer_error_has_no_key_and_no_url(consent_given: None) -> None:
    analyzer, model = make_analyzer()

    def fail(prompt: str) -> Any:
        raise RuntimeError(f"POST https://generativelanguage.googleapis.com/x?key={API_KEY} refused")

    model.generate_content = fail  # type: ignore[method-assign]

    assert analyzer.analyze(make_result()) is None
    assert API_KEY not in analyzer.last_error
    assert "https://" not in analyzer.last_error
