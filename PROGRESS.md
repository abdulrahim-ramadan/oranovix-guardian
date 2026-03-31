# Oranovix Guardian — Development Progress

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
