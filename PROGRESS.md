# Oranovix Guardian — Development Progress

## Dependency scan (branch `feature/dependency-scan`)

Goal: report known vulnerabilities (CVE / GHSA) in the packages a project depends on. Works offline after a one-time database download.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `OSVDatabase`: local SQLite copy of the OSV advisories (osv.dev) for PyPI and npm. `update()` downloads the two `all.zip` exports and rebuilds the file; it is the only code that uses the network. The new database is built beside the old one and swapped in when complete, so a failed download or a broken archive leaves the old one untouched. Stored per advisory: id, aliases (CVE), summary; per affected package: ecosystem, normalised name, severity, ranges with their events. GIT ranges and withdrawn advisories are not imported. Severity: CVSS v3 base score (computed from the vector), else the advisory's severity label, else MEDIUM. `status_warning()` reports a missing database or one older than 14 days. | `scanner_engine/deps/osv_db.py`, `scanner_engine/deps/severity.py` |
| 2 | Manifest parsers, one class each behind the ABC `ManifestParser`: `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735, Poetry tables), `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json` (lockfile versions 1 to 3). Every dependency carries its manifest line. `ManifestFinder` prefers lock files: `package.json` is skipped beside `package-lock.json`, `pyproject.toml` beside `poetry.lock`. Third-party folders (`node_modules`, `venv`...) are not searched. Entries installed from a URL, git or a local path are skipped. | `scanner_engine/deps/manifests.py` |
| 3 | Version matching with the OSV rule: events in version order, `introduced` switches "affected" on, `fixed` and `limit` switch it off from that version, `last_affected` after that version. PyPI versions use `packaging.version`; npm versions use the small `SemVer` class (pre-releases ordered as the semver spec says, build metadata ignored). A version that cannot be parsed is never reported. | `scanner_engine/deps/matcher.py`, `scanner_engine/deps/versions.py` |
| 4 | `DependencyScanner`. DEP001: one finding per package and vulnerability, on the manifest line, title like `Django 2.2.0: CVE-2019-14234 (SQL injection)`, fix text `Upgrade to X.Y.Z or later` with the lowest fixed version above the installed one. Records that share an id (the GHSA and the PYSEC entry of one CVE) are one finding that lists all ids. DEP002: an entry without an exact version gives one LOW finding "Unpinned dependency"; no version is guessed. Category `DEPENDENCY`. Package names are normalised (PEP 503 for PyPI). | `scanner_engine/deps/dependency_scanner.py`, `scanner_engine/categories.py` |
| 5 | Integration. `ScanOrchestrator` runs the stage only when a manifest exists; manifests count in `files_scanned`. `Issue.finding_key` keeps several vulnerabilities on one manifest line apart in `IssueMerger` and gives each its own alarm id, so a CRITICAL dependency goes through `AlarmCenter` like any other finding. A missing or old database and an unreadable manifest become engine warnings; the scan still completes. | `scanner_engine/orchestrator.py`, `scanner_engine/base.py`, `scanner_engine/issue_merger.py`, `core/alarm_center.py` |
| 6 | UI. Settings: "Update vulnerability database" button (runs in the background) and the database date; a warning when it is missing or older than 14 days. Results page: filter "Dependencies". PDF: section "Vulnerable dependencies" with package, version, ids and fix. Texts in AR/DE/EN. | `gui/pages/settings_page.py`, `gui/pages/results_page.py`, `reports/pdf_generator.py`, `translations/` |
| 7 | Config files (`.env`, `Dockerfile`, `.npmrc`, manifests, lock files, `.yaml`, `.json`...) are shown as language "Config" instead of "Unknown" in the toast and in the scan log. | `scanner_engine/base.py`, `core/alarm_center.py`, `gui/pages/scanner_page.py` |

Tests: 408 passing (226 before + 182 new). They use a tiny OSV fixture in `tests/fixtures/osv/`; no test reaches the network, and the dependency scan tests fail on any attempt to open a connection. Type check: `uvx pyright`, 0 errors.

Checked once by hand against the real OSV exports (not part of the test suite): download and import took about 54 seconds, 236,769 advisories, database file 63 MB; a scan of a small project took 0.2 seconds.

### Known limits

- Only PyPI and npm. `Pipfile` (without `.lock`), `yarn.lock`, `pnpm-lock.yaml` and `uv.lock` are not read.
- Only versions that are written in a manifest are checked. Packages that are installed but listed nowhere, and transitive packages without a lock file, are not seen.
- A package with many known vulnerabilities gives many findings (the real data lists 43 for Django 2.2.0), and the risk score then reaches 100 quickly.
- The suggested fix is the lowest fixed version above the installed one, which can be on a newer release line when the installed line got no fix.
- Advisories that list only single versions without a range, or only a GIT commit range, are not matched.
- CVSS v4 vectors are not scored; such advisories fall back to their severity label or MEDIUM.
- Advisory summaries are English only.
- The database file (`osv.db`) is written next to `settings.json`. The update replaces the whole file; there is no incremental update and no automatic update.

### Notes for the next build

- Do not rebuild the exe from this branch yet. The branch is not merged.
- New dependency in `src/requirements.txt`: `packaging`. `tomllib` and `sqlite3` are part of Python (3.11 or newer is needed for `tomllib`).
- No new PyInstaller options are expected: the new modules are plain imports. Not checked in a built exe.
- `osv.db` is not shipped. The user downloads it once from Settings.

---

## Type check, API key storage and AI privacy (branch `chore/types-and-api-key`)

Goal: a clean type check, a Gemini API key that is really saved without ever being written to a plain-text file, and no secret or unneeded code leaving the machine for the online AI.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Type check with pyright: `pyrightconfig.json` uses the project `venv` and skips `tests/corpus` (broken on purpose). 45 errors in application code fixed. `gui/dashboard.py` deleted: it imported names that do not exist and nothing used it. | `pyrightconfig.json`, 14 source files |
| 2 | `SecretStore` keeps the key in the OS credential store through `keyring` (Windows Credential Manager, service `OranovixGuardian`, entry `gemini_api_key`): `get()`, `set()`, `delete()`, `is_available()`, `mask()`. When no credential store works, `get()` returns nothing, `set()` and `delete()` raise `SecretStoreError`, and only the `GEMINI_API_KEY` environment variable is used. | `core/secret_store.py` |
| 3 | One key lookup for both AI engines: `GeminiConfig.api_key()` reads the environment variable first, then `SecretStore`. `settings.json` is no longer a key source. | `scanner_engine/gemini_config.py`, `scanner_engine/ai_analyzer.py`, `scanner_engine/ai_fix_generator.py` |
| 4 | One-time migration: an old `"api_key"` in `settings.json` is moved into `SecretStore` and deleted from the file (settings page start and every key lookup). A key already saved through the settings page is not overwritten. If the credential store is not usable, the entry stays in the file so the key is not lost, and the move is tried again next time. | `scanner_engine/gemini_config.py` |
| 5 | Settings page: Save and Remove buttons. Status shows "Key saved (••••1234)" with only the last 4 characters; the field is cleared after saving. A warning appears when the credential store is not available (Save is disabled) and a note when `GEMINI_API_KEY` is set and therefore wins. Texts in AR/DE/EN. | `gui/pages/settings_page.py`, `translations/` |
| 6 | Dead `_saved_api_key` / `_api_entry` code removed from the main window. | `gui/app.py` |

| 7 | `Redactor.redact(text)` replaces secret values with `<REDACTED>`: everything matched by the `SecretsDetector` patterns (AWS, OpenAI, GitHub, JWT with its signature, a private key block up to its END line, the password in a connection string) and any string literal assigned to or compared with a name that contains password / secret / token / api_key / secret_key and the other names of the AST secrets rule. The patterns and names are read from the scanner, not copied, so a new scanner pattern is redacted automatically. | `core/redactor.py`, `scanner_engine/secrets_detector.py`, `scanner_engine/ast_analyzer.py` |
| 8 | Every outbound AI text goes through the Redactor. The fix generator sends the title and the snippet, the analyzer sends titles and descriptions; both name the file without its folder, and the analyzer sends only the folder name of the scan target. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/ai_analyzer.py` |
| 9 | A finding in the secret category never goes online (also when a secret rule was merged into it). It always gets the `OfflineFixDatabase` fix, and the analyzer leaves it out of the prompt and sends only how many there were. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/ai_analyzer.py` |
| 10 | The API key is sent in the `x-goog-api-key` header; the URL has no query string. Failure messages contain only the HTTP status or the error type; analyzer errors pass through `GeminiConfig.safe_error_text`, which removes the key and any URL. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/gemini_config.py` |
| 11 | Consent. Nothing is sent unless `settings.json` holds `"ai_online_consent": "allow"`; the engines check this themselves, so the default is offline even without the UI. The first AI fix that would go online opens a dialog ("The vulnerable line will be sent to Google Gemini after secrets are removed. Allow?", Allow / Use offline only). Closing the dialog saves nothing and uses the offline fix. The choice can be changed with a switch in Settings. Texts in AR/DE/EN. | `gui/ai_consent_dialog.py`, `gui/pages/results_page.py`, `gui/pages/settings_page.py`, `translations/` |
| 12 | Allowlist redaction of code, because a pattern list cannot know every secret format. `Redactor.redact_code(snippet, file_name)`: (a) the content of every string literal becomes `<STR_1>`, `<STR_2>`... with the same value always getting the same placeholder; quotes and prefixes stay; only empty strings, single characters and single escapes are kept. Handles `'`, `"`, triple quotes, `r`/`b`/`f` prefixes, JS template strings, C# `$"..."` and `@"..."`, PHP/Java/C# quotes; in f-strings and template strings the `{...}` fields stay as code. An unterminated string is redacted to the end of the line. (b) Outside strings, every token of 16+ characters that mixes letters and digits becomes `<VALUE_1>`..., except a name that is being called (`get_object_or_404(`). (c) Comment text becomes `<COMMENT>`; the file extension decides whether `#` or `//` starts a comment. (d) The pattern pass from step 7 runs over the result as a second layer. Titles and descriptions use `redact` (patterns, then long tokens). The prompt tells the model to keep the placeholders; the returned fix is shown as it is and real values are never put back. | `core/redactor.py`, `scanner_engine/ai_fix_generator.py` |

Tests: 226 passing (117 + 25 in `tests/test_secret_store.py` + 84 in `tests/test_ai_privacy.py`). The key tests use an in-memory keyring backend and never touch the real Credential Manager; the privacy tests replace the HTTP call and inspect the request, so no test reaches the network. Type check: `uvx pyright`, 0 errors.

### Notes for the next build

- New dependency: `keyring` (`src/requirements.txt`).
- PyInstaller needs: `--hidden-import keyring.backends.Windows`.
- Not checked in a built exe yet. If the exe reports "secure storage is not available", also add `--copy-metadata keyring`.

### Known limits

- A new key is used by the next AI request; no restart is needed. An AI request that is already running keeps the old key.
- The settings page does not test the key against Google; a wrong key shows up at the first AI request.
- Code redaction is deliberately broad. The model no longer sees what a string says (for example the SQL text), only that there is a string and how it is combined with variables, so an online fix can be less specific than before.
- In a settings file (`.env*`, `.ini`, `.cfg`, `.conf`, `.properties`, `.yaml`, `.yml`, `.toml`) every unquoted value after `=` or `:` is replaced too, except booleans and numbers.
- Still sent as they are: variable and function names, numbers, and, in source files, values outside strings that are shorter than 16 characters or have no digit (for example a password typed unquoted in a shell script).
- Titles and descriptions are prose and only get the pattern and long-token passes, not the string replacement.
- With the offline choice or without consent, the AI fix button still works and shows the offline fix.

---

## Phase 1 — Django and DRF rules (branch `feature/django-rules`)

Goal: find the typical Django mistakes with few false alarms. Rules that depend on user input use a taint tracker instead of pattern matching. Python `ast` only, no new dependencies.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `TaintTracker`, one per function. Sources: `request.GET`, `POST`, `data`, `query_params`, `body`, `COOKIES`, `META`, `FILES`. Taint flows through assignment, subscript, `.get()`, concatenation, f-strings, `%` and `.format()`. Cleared by `int()`, `float()`, `uuid.UUID()`, `os.path.basename()`, `get_valid_filename()`, `escape()`, by a `url_has_allowed_host_and_scheme` check and by `name in ALLOWLIST`. Flow-sensitive: an expression is judged with the state at its own statement. | `scanner_engine/taint.py` |
| 2 | View rules, one class per rule (`DjangoRule.check(tree, tracker)`): DJ001 `@csrf_exempt` (HIGH), DJ002 SSRF (CRITICAL), DJ003 open redirect (HIGH), DJ004 path traversal (CRITICAL), DJ005 reflected XSS (HIGH), DJ006 raw SQL (CRITICAL), DJ007 JWT without signature check (CRITICAL), DJ008 DRF `AllowAny` on a write view (HIGH), DJ009 serializer `fields = "__all__"` (MEDIUM), DJ010 possible IDOR (HIGH, confidence LOW). | `scanner_engine/django_rules.py` |
| 3 | Settings rules, only for `settings.py` and files directly inside `settings/`: DS001 `ALLOWED_HOSTS` with `"*"` (HIGH), DS002 secure cookies off or missing (MEDIUM), DS003 `CsrfViewMiddleware` missing (HIGH), DS004 `SecurityMiddleware` missing (MEDIUM), DS005 `CORS_ALLOW_ALL_ORIGINS = True` (HIGH), DS006 SSL redirect / HSTS missing (LOW). "Missing" is only reported for a complete settings module, not for a file that star-imports a base module. | `scanner_engine/django_settings_rules.py` |
| 4 | Template rules for `.html`: DT001 `\|safe` (MEDIUM), DT002 `{% autoescape off %}` (HIGH). | `scanner_engine/django_template_rules.py` |
| 5 | Integration. View and settings rules run inside `PythonScanner`; templates run as their own `ScanOrchestrator` stage and count in `files_scanned`. Every rule has an `IssueCategory`, so a DJ finding merges with Bandit on the same line (DJ006 + B608). A merged issue keeps the highest confidence and the help text of any engine in the group. 18 `VulnerabilityDatabase` entries (what, why, how exploited, fix with code). `AlarmCenter`: sound and taskbar flash only for CRITICAL with confidence not LOW; LOW confidence gets a "needs review" badge on the results page and a toast, never a sound. Badge, hint, alarm title and rule titles are translated (AR/DE/EN). | `scanner_engine/python_scanner.py`, `scanner_engine/orchestrator.py`, `scanner_engine/issue_merger.py`, `scanner_engine/categories.py`, `scanner_engine/vulnerability_db.py`, `core/alarm_center.py`, `core/language_manager.py`, `gui/pages/results_page.py`, `translations/` |
| 6 | Corpus `tests/corpus/django_app/` (views, vulnerable and hardened settings, two templates). Every rule has at least one vulnerable case that must be reported and one safe case that must not. | `tests/test_django_rules.py` |

Tests: 117 passing (28 from Phase 0 + 89 new).

### Known limits

- Taint is tracked inside one function. It does not follow a value into a helper function, through `self.x`, or out of a nested function.
- A call to an unknown function does not carry taint (`requests.get(build_url(host))` is not reported). Methods called on tainted data and a short list of string and path helpers do.
- The Secure-cookie and HTTPS checks cannot see settings that live in another file unless that file is star-imported.
- Bandit still reports B608 for an f-string query whose only variable went through `int()`. It arrives with LOW confidence, so it shows the "needs review" badge and stays silent.
- Vulnerability help texts are English only; titles and the badge are translated.

### Notes for the next build

- Do not rebuild the exe from this branch yet. The branch is not merged.
- No new PyInstaller options are needed: the new modules are plain imports.

---

## Phase 0 — Engine Foundation (branch `fix/engine-foundation`)

Goal: make the scan engine trustworthy before adding features. Engine first, UI last.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Every language in a folder is scanned. `ScannerFactory.scanners_for_target` returns one scanner per language present; `ScanOrchestrator` runs language scanners + `SecretsDetector` + `RuleEngine` and returns one merged `ScanResult`. The scanner page only calls the orchestrator. | `scanner_engine/orchestrator.py`, `scanner_engine/factory.py`, `gui/pages/scanner_page.py` |
| 2 | Third-party folders are skipped by every engine through one shared `EXCLUDED_DIRS` (venv, .venv, env, node_modules, `__pycache__`, .git, dist, build, site-packages, migrations). | `scanner_engine/base.py` |
| 3 | Bandit runs as a library (`BanditRunner`) on the already filtered file list. If it cannot load or run, `ScanResult.engine_warnings` is filled and shown in the scan log, status bar and PDF. | `scanner_engine/bandit_runner.py`, `scanner_engine/python_scanner.py`, `reports/pdf_generator.py` |
| 4 | Duplicates are merged. Every rule has an `IssueCategory`; `IssueMerger` merges issues with the same (file, line, category), keeps the highest severity and stores the other rule ids in `Issue.also_detected_by`. Title "Hardcoded Hardcoded Password" fixed. | `scanner_engine/categories.py`, `scanner_engine/issue_merger.py` |
| 5 | False positives cut. SEC002 (regex `open()` path traversal) is disabled until it returns as a taint rule. RULE-002 ignores `127.0.0.1`, `0.0.0.0` and version strings (`Rule.exclude_line_pattern`). | `scanner_engine/python_scanner.py`, `scanner_engine/rule_engine.py`, `rules/default_rules.json` |
| 6 | Score no longer saturates: `weighted = 40*C + 20*H + 5*M + 1*L`, `score = round(100 * (1 - 0.5 ** (weighted / 40)))`. Labels unchanged; raw counts (`C:3 H:1 M:0 L:2`) are shown next to the score. | `scanner_engine/base.py` |
| 7 | Central alarm. `AlarmCenter.notify(findings)`: CRITICAL → critical sound + red toast + taskbar flash; HIGH → toast only. Stable finding id = sha1(category + relative path + line), stored in SQLite so a finding never alarms twice. Channels are injected so a background monitor can reuse it. Text in AR/DE/EN. | `core/alarm_center.py`, `gui/alarm_channels.py` |
| 8 | pytest suite (no GUI) with a vulnerable corpus in `tests/corpus/`. Run: `venv\Scripts\python -m pytest`. | `tests/`, `pytest.ini`, `src/requirements-dev.txt` |
| 9 | Repo cleanup: `release/` untracked and ignored; Gemini model read from `settings.json` (`gemini_model`, default `gemini-flash-latest`); a 404 gives a clear message. | `.gitignore`, `scanner_engine/gemini_config.py` |

### Follow-up fixes

| Fix | Change | Main files |
|-----|--------|-----------|
| 1 | Dotfiles are scanned again. `FileMatcher` matches by suffix **or** by name, so `.env`, `.env.local`, `.env.production` are found (`Path(".env").suffix` is empty). `SecretsDetector` also scans `Dockerfile`, docker-compose files, `.htpasswd`, `.npmrc`, `.pypirc`. `files_scanned` counts every file any engine looked at. | `scanner_engine/base.py`, `scanner_engine/secrets_detector.py`, `scanner_engine/orchestrator.py` |
| 2 | The alarm no longer goes silent forever. Sound + flash still fire once per finding, but every scan with open CRITICAL findings shows a persistent red banner on the results page ("N critical findings still open"). A full scan removes ids from `alarmed_findings` that are no longer present in that root, so a fixed-then-reintroduced finding alarms again. Finding ids are scoped to the scan root. | `core/alarm_center.py`, `gui/pages/results_page.py` |
| 3 | Readable titles. Bandit ids map to clear titles (`B307` → "Use of eval()", `B301` → "Unsafe pickle deserialization", ...). A merged issue led by Bandit takes the title of our own rule when one matched. | `scanner_engine/python_scanner.py`, `scanner_engine/issue_merger.py` |
| 4 | Local tool folders are ignored through `.git/info/exclude` (local only) instead of `.gitignore`. | `.gitignore` |

Tests: 28 passing (`venv\Scripts\python -m pytest`).

### Notes for the next build

- Do not rebuild the exe from this branch yet.
- Bandit now loads its checks as plugins, so PyInstaller needs:
  `--collect-all bandit --collect-all stevedore --copy-metadata bandit`.
  `bandit.exe` no longer has to be bundled.
- Score reference points: 1 low = 2, 1 high = 29, 1 critical = 50, 2 criticals = 75, 3 criticals = 88, 8 or more criticals round to 100.

### Open items

- ~~SEC002 path traversal returns as a taint-tracking rule.~~ Done as DJ004 in Phase 1.
- Background monitor that feeds `AlarmCenter.notify`.
- Dashboard history still shows the score without the raw counts.

---

## v1.1.0 — Advanced Features Release

### Feature 1: Secrets Detection ✅
**File:** `scanner_engine/secrets_detector.py`

- Abstract base class `SecretPattern(ABC)` with `pattern`, `secret_type`, `severity` abstract properties
- 7 concrete pattern classes: `AWSKeyPattern`, `OpenAIKeyPattern`, `GitHubTokenPattern`, `PasswordPattern`, `ConnectionStringPattern`, `PrivateKeyPattern`, `JWTPattern`
- `SecretsDetector(BaseScanner)` scans **every** text file type regardless of language (40+ extensions)
- Secrets values are masked in the UI (shows only first 6 + last 4 chars)
- Integrated into `scanner_page.py` as Phase 2 of the scan pipeline
- Results de-duplicated by `(rule_id, file_path, line_number)` before merging

---

### Feature 2: AST Parsing (Python) ✅
**File:** `scanner_engine/ast_analyzer.py`

- Abstract base class `ASTRule(ABC)` with `check(node: ast.AST)` abstract method
- 5 concrete rule classes:
  - `DangerousFunctionRule` — detects `eval()`, `exec()`, `compile()` calls
  - `SQLInjectionRule` — detects f-string/`.format()`/concatenation inside `cursor.execute()`
  - `HardcodedSecretsRule` — detects string literals assigned to sensitive variable names
  - `InsecureImportRule` — detects `import pickle`, `import marshal`, `import shelve`
  - `WeakCryptoRule` — detects `hashlib.md5()`, `hashlib.sha1()`
- `ASTAnalyzer.analyze(code, file_path)` classmethod — zero external dependencies
- Integrated into `PythonScanner._do_scan()` after Bandit + regex checks
- Full de-duplication against Bandit findings

---

### Feature 3: AI Fix Generator ✅
**File:** `scanner_engine/ai_fix_generator.py`

- `FixSuggestion` dataclass: `original_code`, `fixed_code`, `explanation`, `prevention`, `confidence`, `source`
- `OfflineFixDatabase` — 14 curated fix templates covering: SQL injection, eval/exec, passwords, MD5/SHA1, pickle, os.system, AWS/GitHub/OpenAI keys, JWT, path traversal, and more
- `AIFixGenerator` — Gemini REST API integration with automatic offline fallback
  - API key resolved from: constructor → `settings.json` → `GEMINI_API_KEY` env var
  - Memory cache avoids repeated API calls for the same issue
  - `generate_fix_async()` — non-blocking background thread delivery
- UI integration in `IssueAccordion._build_detail()`:
  - "🤖 AI Fix" button in every issue's detail panel
  - Shows loading indicator while generating
  - Displays source badge (Gemini AI / Offline), confidence %, fixed code, explanation, prevention
  - "📋 Copy Fix" button copies fixed code to clipboard
  - Syntax-highlighted fixed code block (Consolas font, green-on-dark)

---

### Feature 4: Rule Engine ✅
**File:** `scanner_engine/rule_engine.py`

- `RuleLanguage(str, Enum)` — `ALL`, `Python`, `JavaScript`, `PHP`, `Java`, `C#`
- `Rule` dataclass: `id`, `name`, `description`, `pattern`, `severity`, `language`, `enabled`, `fix_suggestion`, `is_builtin`
- `RuleEngine` class:
  - Loads from `rules/default_rules.json` (built-in) + `rules/custom_rules.json` (user)
  - `add_rule()`, `enable_rule()`, `disable_rule()`, `delete_rule()` — all persist automatically
  - `scan(code, language)` and `scan_file(file_path, language)` — return `Issue` objects
  - `test_rule(rule, sample_code)` — test without persisting
  - `export_rules(path)` / `import_rules(path)` — JSON import/export
- **10 built-in default rules:**
  1. TODO Security Comment
  2. Hardcoded IP Address
  3. Disabled SSL/TLS Verification
  4. Debug Mode Enabled (Python)
  5. Weak Random for Security (Python)
  6. Insecure HTTP URL
  7. console.log of Sensitive Data (JavaScript)
  8. Overly Permissive CORS
  9. Sensitive Data in URL Parameter
  10. PHP Short Open Tags
- UI: **Rules Manager** section in Settings page:
  - Scrollable list of all rules with ON/OFF toggle per rule
  - Severity badge (colored) and language tag per rule
  - Built-in rules marked as "built-in" (cannot delete, only toggle)
  - Custom rules have a delete (✕) button
  - "Add Rule" button opens a dialog with: ID, Name, Description, Pattern, Severity dropdown, Language dropdown, Fix Suggestion, and a live Test area
  - "Import Rules" / "Export Rules" buttons (JSON file)
  - Rule count indicator ("X/Y rules active")
- Integrated into `scanner_page.py` as Phase 3 of the scan pipeline

---

### Scanner Pipeline (Updated)

Each scan now runs 3 phases:

1. **Language Scanner** (Bandit + regex + AST for Python; regex for JS/PHP/Java/C#)
2. **Secrets Detector** (all file types, 7 secret patterns)
3. **Rule Engine** (user-defined + built-in regex rules)

All results are de-duplicated by `(rule_id, file_path, line_number)` before display.

---

### Files Changed

| File | Change |
|------|--------|
| `scanner_engine/secrets_detector.py` | **NEW** |
| `scanner_engine/ast_analyzer.py` | **NEW** |
| `scanner_engine/ai_fix_generator.py` | **NEW** |
| `scanner_engine/rule_engine.py` | **NEW** |
| `rules/default_rules.json` | **NEW** |
| `rules/custom_rules.json` | **NEW** |
| `scanner_engine/__init__.py` | Updated exports |
| `scanner_engine/python_scanner.py` | ASTAnalyzer integration in `_do_scan` |
| `gui/pages/scanner_page.py` | Phase 2+3 scan pipeline, new imports |
| `gui/pages/results_page.py` | AI Fix button in IssueAccordion |
| `gui/pages/settings_page.py` | Rules Manager section |
| `translations/en.json` | 20 new translation keys |
| `PROGRESS.md` | **NEW** |

---

### v1.0.0 — Initial Release

- Python scanner (Bandit + regex SEC001/SEC002)
- JavaScript/TypeScript scanner (15 rules)
- PHP scanner (12 rules)
- Java scanner (12 rules)
- C# scanner (13 rules)
- Vulnerability database (CWE/OWASP education)
- CustomTkinter GUI (Dark/Light theme, 10 languages)
- PDF report generation (ReportLab)
- Scan history (SQLite)
- AI analysis (Gemini API, optional)
- Sound alerts (Windows winsound)
