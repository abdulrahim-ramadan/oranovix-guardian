<p align="center">
  <img src="assets/icon.png" alt="Oranovix Guardian Logo" width="120"/>
</p>

<h1 align="center">Oranovix Guardian</h1>

<p align="center">
  <strong>Professional Code Security Scanner — 100% Offline, 100% Free</strong>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-blue?logo=windows"/>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python"/>
  <img alt="UI" src="https://img.shields.io/badge/UI-CustomTkinter-purple"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green"/>
  <img alt="Version" src="https://img.shields.io/badge/version-1.1.0-red"/>
</p>

---

## What is Oranovix Guardian?

Oranovix Guardian is a **professional desktop security scanner** that detects vulnerabilities in source code across five languages — entirely offline, with no telemetry, no account required, and no subscription. Drop a file or folder onto the scanner, click **Scan**, and get an instant risk report with actionable recommendations and optional AI-powered deep analysis.

---

## Features

| Feature | Details |
|---------|---------|
| 🔍 **Multi-language scanning** | Python (Bandit), JavaScript/TypeScript, PHP, Java, C# |
| 🚨 **Critical vulnerability detection** | SQL injection, eval/exec, command injection, hardcoded secrets, XSS, path traversal, weak crypto |
| 📊 **Risk scoring** | 0–100 composite score; CRITICAL / HIGH / MEDIUM / LOW breakdown |
| 📄 **PDF reports** | Professional ReportLab-generated reports with full issue table |
| 🤖 **AI analysis** | Optional Gemini integration for natural-language remediation advice |
| 🌍 **10 languages** | EN, DE, FR, ES, AR, ZH, JA, RU, PT, IT (with RTL support for Arabic) |
| 🎨 **Dark & Light theme** | Fully themeable CustomTkinter UI |
| 🔔 **Sound alerts** | Native Windows beep tones on scan complete/critical/error |
| 💾 **Scan history** | SQLite-backed history with trend chart and statistics |
| ⚡ **Fast startup** | Splash screen in < 0.2 s; heavy imports deferred to background thread |

---

## Screenshots

> Scanner Page · Dashboard · Settings

---

## Quick Start

### Download the pre-built executable (Windows)

1. Download **`Oranovix Guardian.exe`** from the [Releases](../../releases) page.
2. Double-click to run — no installation required.

### Run from source

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/oranovix-guardian.git
cd oranovix-guardian

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python main.py
```

---

## Build the Executable

```bash
venv\Scripts\pyinstaller --onefile --windowed ^
  --icon=assets/icon.ico ^
  --name="Oranovix Guardian" ^
  --add-data="assets;assets" ^
  --add-data="translations;translations" ^
  --hidden-import keyring.backends.Windows ^
  main.py
```

The output is placed in `dist\Oranovix Guardian.exe` (~24 MB).

---

## Supported Languages & Rules

| Language | Engine | Key Rules |
|----------|--------|-----------|
| **Python** | Bandit + regex | eval (B307), os.system (B605), SQL injection (B608), hardcoded secrets, path traversal, weak hash |
| **JavaScript / TypeScript** | Regex | eval, innerHTML XSS, document.write, hardcoded secrets, SQL concat, child_process injection, open redirect |
| **PHP** | Regex | eval, system/exec, SQL injection, file inclusion, XSS echo, MD5 passwords |
| **Java** | Regex | Runtime.exec, SQL string concat, ObjectInputStream deserialization, hardcoded credentials |
| **C#** | Regex | Process.Start, SQL string concat, BinaryFormatter, hardcoded passwords |

---

## Technologies

- **[Python 3.11+](https://python.org)** — core runtime
- **[CustomTkinter 5.x](https://github.com/TomSchimansky/CustomTkinter)** — modern themed UI
- **[Bandit](https://bandit.readthedocs.io/)** — Python AST-based security linter
- **[ReportLab](https://www.reportlab.com/)** — PDF generation
- **[Pillow](https://python-pillow.org/)** — image handling
- **[Google Gemini API](https://aistudio.google.com/)** — optional AI analysis (free tier)
- **SQLite** — local scan history (stdlib)

---

## Project Structure

```
oranovix-guardian/
├── main.py                    # Entry point
├── scanner_engine/            # Language scanners + AI analyzer
│   ├── base.py                # Abstract BaseScanner, Issue, ScanResult
│   ├── factory.py             # ScannerFactory (auto-detects language)
│   ├── python_scanner.py      # Bandit wrapper + regex extras
│   ├── js_scanner.py          # JS/TS regex scanner
│   ├── php_scanner.py         # PHP regex scanner
│   ├── java_scanner.py        # Java regex scanner
│   ├── csharp_scanner.py      # C# regex scanner
│   ├── ai_analyzer.py         # Gemini API integration
│   └── vulnerability_db.py    # CWE/OWASP education database
├── core/                      # Application services
│   ├── language_manager.py    # i18n (10 languages, RTL)
│   ├── scan_history.py        # SQLite scan history
│   └── sound_manager.py       # Windows sound alerts
├── gui/                       # CustomTkinter UI
│   ├── app.py                 # Root window + navigation
│   ├── pages/                 # Scanner, Results, Reports, Settings
│   └── ...                    # Sidebar, title bar, animations
├── reports/
│   └── pdf_generator.py       # ReportLab PDF export
├── translations/              # JSON translation files
└── assets/                    # Icons and images
```

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

<p align="center">Made with ❤️ — 100% free, 100% offline</p>
