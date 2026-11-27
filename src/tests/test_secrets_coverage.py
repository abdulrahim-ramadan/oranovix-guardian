"""Secret shapes the detector used to miss, and the placeholders it must keep ignoring.

Every key-like value is put together at runtime, so this file holds
nothing that Windows Defender or GitHub secret scanning would flag.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Dict, List, Set

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory, category_for_rule
from oranovix_guardian.scanner_engine.secrets_detector import SecretsDetector

DASHES = "-" * 5
ALNUM = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6"


def pem(kind: str) -> str:
    label = f"{kind} PRIVATE KEY" if kind else "PRIVATE KEY"
    return f"{DASHES}BEGIN {label}{DASHES}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n{DASHES}END {label}{DASHES}\n"


STRIPE_LIVE = "sk" + "_live_" + ALNUM[:24]
STRIPE_RESTRICTED = "rk" + "_live_" + ALNUM[2:26]
SLACK_BOT = "xo" + "xb-" + "1234567890-1234567890123-" + ALNUM[:24]
SLACK_USER = "xo" + "xp-" + "1234567890-1234567890123-" + ALNUM[3:27]
GOOGLE_API = "AI" + "za" + "Sy" + ALNUM[:33]
OPENAI_PROJECT = "sk" + "-proj-" + ALNUM[:40] + "_" + ALNUM[:20]
SENDGRID = "S" + "G." + ALNUM[:22] + "." + ALNUM[:43]
TELEGRAM = "123456789" + ":" + "AA" + ALNUM[:33]
GITHUB_FINE = "github" + "_pat_" + ALNUM[:22] + "_" + ALNUM[:40] + ALNUM[:19]
GITHUB_OTHER = {prefix: prefix + "_" + ALNUM[:36] for prefix in ("gh" + "o", "gh" + "u", "gh" + "s", "gh" + "r")}
STRONG = "Kq7" + "vR2xW9pL"          # a value that is not a placeholder


# (file name, content, rule id expected on the line holding ``marker``)
CASES: Dict[str, tuple] = {
    "pkcs8": ("deploy.py", f'KEY = """{pem("")}"""\n', "SEC-PRVK1", "BEGIN PRIVATE KEY"),
    "pkcs8_pem_file": ("server.pem", pem(""), "SEC-PRVK1", "BEGIN PRIVATE KEY"),
    "encrypted": ("deploy.py", f'KEY = """{pem("ENCRYPTED")}"""\n', "SEC-PRVK1", "BEGIN ENCRYPTED"),
    "openssh": ("id_ed25519", pem("OPENSSH"), "SEC-PRVK1", "BEGIN OPENSSH"),
    "service_account": (
        "service-account.json",
        json.dumps({"type": "service_account", "project_id": "demo",
                    "private_key": pem(""), "client_email": "svc@demo.iam.gserviceaccount.com"}),
        "SEC-GCP01", "private_key",
    ),
    "stripe_live": ("billing.py", f'stripe.api_key = "{STRIPE_LIVE}"\n', "SEC-STRP1", "stripe"),
    "stripe_restricted": ("billing.js", f"const key = '{STRIPE_RESTRICTED}';\n", "SEC-STRP1", "const key"),
    "slack_bot": ("notify.py", f'client = WebClient(token="{SLACK_BOT}")\n', "SEC-SLCK1", "WebClient"),
    "slack_user": ("notify.py", f'SLACK = "{SLACK_USER}"\n', "SEC-SLCK1", "SLACK"),
    "google_api": ("maps.js", f'const mapsKey = "{GOOGLE_API}";\n', "SEC-GAPI1", "mapsKey"),
    "openai_project": ("ai.py", f'client = OpenAI(api_key="{OPENAI_PROJECT}")\n', "SEC-OAI01", "OpenAI"),
    "sendgrid": ("mail.py", f'sg = SendGridAPIClient("{SENDGRID}")\n', "SEC-SGRD1", "SendGrid"),
    "telegram": ("bot.py", f'bot = Bot("{TELEGRAM}")\n', "SEC-TGBT1", "Bot("),
    "github_fine_grained": ("ci.py", f'TOKEN = "{GITHUB_FINE}"\n', "SEC-GHP01", "TOKEN"),
    **{
        f"github_{prefix}": ("ci.py", f'TOKEN = "{token}"\n', "SEC-GHP01", "TOKEN")
        for prefix, token in GITHUB_OTHER.items()
    },
    "url_postgres": ("settings.py", 'DB = "postgres://app:pass@db:5432/shop"\n', "SEC-CONN1", "DB ="),
    "url_redis_no_user": ("settings.py", 'CACHE = "redis://:pass@cache:6379/0"\n', "SEC-CONN1", "CACHE"),
    "url_amqp": ("settings.py", 'BROKER = "amqp://guest:Rabbit9pass@mq:5672//"\n', "SEC-CONN1", "BROKER"),
    "url_mongodb_srv": ("db.js", "const uri = 'mongodb+srv://app:Mongo9pass@cluster0.example.net/';\n",
                        "SEC-CONN1", "const uri"),
    "json_password": ("config.json", json.dumps({"db": {"user": "app", "password": STRONG}}, indent=2),
                      "SEC-CFG01", '"password"'),
    "yaml_password": ("docker-compose.yml", f"services:\n  db:\n    password: {STRONG}\n", "SEC-CFG01", "password:"),
    "env_db_password": (".env", f"DEBUG=1\nDB_PASSWORD={STRONG}\n", "SEC-CFG01", "DB_PASSWORD"),
    "env_secret_key": (".env", f"SECRET_KEY={STRONG}x\n", "SEC-CFG01", "SECRET_KEY"),
    "ini_token": ("app.ini", f"[api]\napi_key = {STRONG}\n", "SEC-CFG01", "api_key"),
    "toml_client_secret": ("pyproject.toml", f'[oauth]\nclient_secret = "{STRONG}"\n', "SEC-CFG01", "client_secret"),
    "properties_password": ("application.properties", f"spring.datasource.password={STRONG}\n",
                            "SEC-CFG01", "datasource.password"),
}


def scan(tmp_path: Path, name: str, content: str) -> List[Issue]:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return SecretsDetector().scan(str(tmp_path)).issues


def line_of(content: str, marker: str) -> int:
    for number, line in enumerate(content.splitlines(), start=1):
        if marker in line:
            return number
    raise AssertionError(f"marker {marker!r} not in content")


@pytest.mark.parametrize("case", sorted(CASES))
def test_every_new_shape_is_detected_with_the_right_rule(tmp_path: Path, case: str) -> None:
    name, content, rule_id, marker = CASES[case]

    issues = scan(tmp_path, name, content)

    line = line_of(content, marker)
    rules_on_line = {issue.rule_id for issue in issues if issue.line_number == line}
    assert rule_id in rules_on_line, (case, [(i.rule_id, i.line_number) for i in issues])
    for issue in issues:
        assert issue.category is IssueCategory.SECRET


@pytest.mark.parametrize("kind", ["RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED", ""])
def test_private_keys_of_every_kind_are_critical(tmp_path: Path, kind: str) -> None:
    issues = scan(tmp_path, "key.txt", pem(kind))

    keys = [issue for issue in issues if issue.rule_id == "SEC-PRVK1"]
    assert len(keys) == 1
    assert keys[0].severity is Severity.CRITICAL


def test_a_private_key_inside_a_json_string_is_found(tmp_path: Path) -> None:
    content = json.dumps({"private_key": pem("")})          # newlines become \n inside the string

    issues = scan(tmp_path, "creds.json", content)

    assert {"SEC-PRVK1", "SEC-GCP01"} <= {issue.rule_id for issue in issues}
    assert all(issue.severity is Severity.CRITICAL for issue in issues if issue.rule_id in {"SEC-PRVK1", "SEC-GCP01"})


NON_FINDINGS = {
    "env_changeme": (".env", "DB_PASSWORD=changeme\n"),
    "env_template": (".env", "SECRET_KEY=${SECRET_KEY}\n"),
    "env_empty": (".env", "DB_PASSWORD=\nAPI_TOKEN=\n"),
    "env_short": (".env", "DB_PASSWORD=abc123\n"),
    "env_example": (".env.example", "STRIPE_SECRET=sk_example_value_here\n"),
    "env_getenv": (".env", 'SECRET_KEY=getenv("SECRET_KEY")\n'),
    "yaml_angle": ("config.yml", "database:\n  password: <your-key>\n"),
    "yaml_env_call": ("config.yaml", "database:\n  password: env(DB_PASSWORD)\n"),
    "yaml_actions_secret": ("deploy.yml", "with:\n  token: ${{ secrets.DEPLOY_TOKEN }}\n"),
    "yaml_author": ("meta.yml", "author: Jane Doe-Smithson\nmax_tokens: 409600000\n"),
    "yaml_url_name": ("auth.yml", "token_url: https://login.example.org/oauth/token\n"),
    "ini_interpolation": ("app.ini", "[db]\npassword = %(db_pass)s\n"),
    "json_example": ("config.json", json.dumps({"password": "example-password"})),
    "json_empty": ("config.json", json.dumps({"password": "", "token": None})),
    "json_os_environ": ("config.json", json.dumps({"password": "os.environ['DB_PASSWORD']"})),
    "properties_template": ("application.properties", "spring.datasource.password=${DB_PASSWORD}\n"),
    "python_environ": ("settings.py", 'password = os.environ["DB_PASSWORD"]\n'),
    "python_env": ("settings.py", 'SECRET_KEY = env("SECRET_KEY")\n'),
    "python_getenv": ("settings.py", 'token = os.getenv("API_TOKEN")\n'),
    "url_template": ("settings.py", 'DB = "postgres://app:${DB_PASSWORD}@db/shop"\n'),
    "url_without_password": ("settings.py", 'DB = "postgres://db.internal:5432/shop"\n'),
    "python_unquoted_is_code": ("app.py", "password = load_password_from_vault(name)\n"),
    # A PEM header without key data is a constant or a comment in a crypto library.
    "pem_marker_constant": ("crypt.py", f'_PKCS8_MARKER = ("{DASHES}BEGIN PRIVATE KEY{DASHES}", "x")\n'),
    "pem_marker_comment": ("tls.py", f'# "{DASHES}BEGIN EC PRIVATE KEY{DASHES}...",\n'),
    "service_account_template": ("creds.json", json.dumps(
        {"private_key": f"{DASHES}BEGIN EC PRIVATE KEY{DASHES}\n<key bytes>\n{DASHES}END EC PRIVATE KEY{DASHES}\n"})),
    # "name=value" inside a JSON string is prose, not a key.
    "json_prose": ("api.json", json.dumps({"description": "filter on oAuthClientId=clientIdValue123, "
                                                         "or set access_token=ACCESS_TOKEN_VALUE first"})),
}


@pytest.mark.parametrize("case", sorted(NON_FINDINGS))
def test_placeholders_and_environment_lookups_give_nothing(tmp_path: Path, case: str) -> None:
    name, content = NON_FINDINGS[case]

    issues = scan(tmp_path, name, content)

    assert issues == [], [(i.rule_id, i.code_snippet) for i in issues]


def test_every_secret_rule_is_in_the_secret_category() -> None:
    for pattern in SecretsDetector.patterns():
        assert category_for_rule(pattern.rule_id) is IssueCategory.SECRET, pattern.rule_id


def _translations(lang: str) -> Dict[str, str]:
    return json.loads((AppPaths.resource("translations") / f"{lang}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("lang", ["en", "de", "ar"])
def test_every_secret_rule_has_a_title_in_every_language(lang: str) -> None:
    texts = _translations(lang)
    missing = [p.rule_id for p in SecretsDetector.patterns() if f"rule_title_{p.rule_id}" not in texts]
    assert missing == []


def test_every_secret_rule_has_id_severity_and_description() -> None:
    ids: Set[str] = set()
    for pattern in SecretsDetector.patterns():
        assert pattern.rule_id.startswith("SEC-") and pattern.rule_id not in ids
        ids.add(pattern.rule_id)
        assert isinstance(pattern.severity, Severity)
        assert pattern.secret_type


# ---------------------------------------------------------------------------
# Low noise on real code
# ---------------------------------------------------------------------------

NEW_RULES = {"SEC-GCP01", "SEC-STRP1", "SEC-SLCK1", "SEC-GAPI1", "SEC-SGRD1", "SEC-TGBT1", "SEC-CFG01"}


@pytest.mark.parametrize("package", ["requests", "urllib3", "customtkinter", "django"])
def test_installed_packages_give_no_new_secret_findings(package: str) -> None:
    spec = importlib.util.find_spec(package)
    if spec is None or not spec.submodule_search_locations:
        pytest.skip(f"{package} is not installed")
    folder = list(spec.submodule_search_locations)[0]

    issues = SecretsDetector().scan(folder).issues

    assert [(i.rule_id, i.file_path, i.line_number) for i in issues if i.rule_id in NEW_RULES] == []
