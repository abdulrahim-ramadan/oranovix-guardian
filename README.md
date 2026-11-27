<p align="center">
  <img src="assets/icon_square.png" alt="Oranovix Guardian Logo" width="120"/>
</p>

<h1 align="center">Oranovix Guardian</h1>

<p align="center">
  <strong>Professional Code Security Scanner — Scans offline, optional online AI, 100% Free</strong>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-blue?logo=windows"/>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python"/>
  <img alt="UI" src="https://img.shields.io/badge/UI-CustomTkinter-purple"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green"/>
  <img alt="Version" src="https://img.shields.io/badge/version-1.2.0-red"/>
</p>

---

## What is Oranovix Guardian?

Oranovix Guardian is a **professional desktop security scanner** that detects vulnerabilities in source code across five languages. Scans run offline, with no telemetry, no account required, and no subscription. Drop a file or folder onto the scanner, click **Scan**, and get an instant risk report with actionable recommendations and optional AI-powered deep analysis. The AI analysis is the only part that sends code to an online service (Google Gemini), and only after you allow it. Before anything is sent, string contents, long tokens and recognised secrets are replaced by placeholders. Secret findings themselves are never sent. The redaction has limits: a secret that looks like a bare variable name, secrets built from char arrays or byte lists, and free text in README files and other documentation are not recognised as secrets and may be sent as they are.

---

## Features

| Feature | Details |
|---------|---------|
| 🔍 **Multi-language scanning** | Python (Bandit), JavaScript/TypeScript, PHP, Java, C# |
| 🚨 **Critical vulnerability detection** | SQL injection, eval/exec, command injection, hardcoded secrets, XSS, path traversal, weak crypto |
| 📦 **Dependency scan** | Known vulnerabilities (CVE / GHSA) in PyPI and npm packages from the OSV database; works offline after a one-time download in Settings |
| 📊 **Risk scoring** | 0–100 composite score; CRITICAL / HIGH / MEDIUM / LOW breakdown |
| 📄 **PDF reports** | Professional ReportLab-generated reports with full issue table |
| 🤖 **AI analysis** | Optional Gemini integration for natural-language remediation advice |
| 🌍 **Languages** | English, German and Arabic, with RTL support for Arabic |
| 🎨 **Dark & Light theme** | Fully themeable CustomTkinter UI |
| 🔔 **Sound alerts** | Native Windows beep tones on scan complete/critical/error |
| 💾 **Scan history** | SQLite-backed history with trend chart and statistics |
| ⚡ **Fast startup** | The scanner opens first; other pages are created on demand |
| ✉️ **Daily digest** | Optional morning report by email and/or Telegram, and instant CRITICAL alarms; off by default, nothing secret leaves the computer |

---

## Screenshots

> Scanner Page · Dashboard · Settings

---

## Quick Start

### Download the pre-built executable (Windows)

1. Download **`Oranovix_Guardian_Setup_v1.2.0.exe`** from the [Releases](../../releases) page.
2. Run it. The app is installed to `C:\Program Files\Oranovix Guardian`; a normal (non-admin) user can run it.

To update, run the new Setup over the old version. If the app is running, Setup (and the uninstaller) says "Oranovix Guardian is running, please close it" before anything is copied or removed. Your settings and data are kept: they are not in the program folder.

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
pip install -r src/requirements.txt

# 4. Run
python main.py
```

---

## Build the Executable

```powershell
powershell -ExecutionPolicy Bypass -File src\build_tools\build.ps1
```

The script runs PyInstaller with every flag the build needs (`--collect-all bandit --collect-all stevedore --copy-metadata bandit --hidden-import keyring.backends.Windows --hidden-import truststore --collect-data certifi`, plus the bundled assets, translations and default rules) and then Inno Setup 6. Results: the folder `dist\Oranovix Guardian\` (`Oranovix Guardian.exe` and `_internal\`) and `dist\Oranovix_Guardian_Setup_v1.2.0.exe`, which installs that whole folder. Use `-NoInstaller` to build only the folder, and `-OneFile` for a portable single `dist\Oranovix Guardian.exe` (no installer).

The installer uses the one-folder build on purpose. A one-file exe runs as two processes, a bootloader without a window and the app; Restart Manager cannot close the windowless one, so an update failed with "DeleteFile failed; code 5". It also unpacks itself to `%TEMP%` at every start, which antivirus products dislike. While it runs, the app holds the mutexes `OranovixGuardianRunning` and `Global\OranovixGuardianRunning`, which Setup checks (`AppMutex`). When Windows or Restart Manager asks the app to close (`WM_CLOSE`, `WM_QUERYENDSESSION`, `WM_ENDSESSION`), it takes the same path as the close button: monitors stopped, stores written, locks released.

### App icon

`assets/icon.png` is the untouched source logo. After changing it, regenerate the icon files and rebuild:

```powershell
python assets/icon_generator.py
```

This writes `assets/icon_square.png` (the logo tile on a transparent square, used by the UI and the large icon sizes), `assets/icon_shield.png` (the shield only, for the small sizes) and `assets/icon.ico` (16, 20, 24, 32, 48, 64, 128 and 256 px). Commit all three. After reinstalling, Windows may still show the old icon from its icon cache: run `ie4uinit.exe -show`, or sign out and in again.

---

## Where your data is

The installed app never writes into its own folder in Program Files. Everything it saves lives in one data folder per Windows user:

```
%LOCALAPPDATA%\Oranovix Guardian    settings.json            theme, sound, AI consent, monitors, feed sources
    scan_history.db          scan history and the memory of alarms already raised
    integrity.db             Live Defense baselines
    feed.db                  Threat Feed, projects, uptime history
    security_events.db       Log Sentinel events
    log_sentinel_state.db    how far each log has been read
    notify.db                notification outbox and delivery status
    osv.db                   vulnerability database for the dependency scan
    rules\custom_rules.json  your own rules
    reports\output\          PDF reports
```

If `%LOCALAPPDATA%` is not set, `%APPDATA%` is used, then your home folder. Running from source keeps the data in the project folder. The environment variable `ORANOVIX_DATA_DIR` sets another folder. Data an older version left next to the exe is copied over once on the first start; the old files are not deleted. Uninstalling keeps the data folder. API keys are not in this folder: they are kept in the Windows Credential Manager.

---

## Threat Feed and My Projects

The Threat Feed shows the CISA list of exploited vulnerabilities and security news (BleepingComputer, The Hacker News, BSI CERT-Bund) and marks the items that affect your own projects. It is **off by default**; a first-run dialog names the hosts before anything is downloaded. Only public feeds are downloaded. Nothing about your projects is sent: matching against your manifests happens on your computer with the local OSV database.

My Projects lists your projects with their last scan, the feed items that affect them and, when you add a site address, an uptime check every 5 minutes. Only add sites you own.

---

## Log Sentinel

Log Sentinel reads the access logs of your web server (nginx, Apache, Caddy; combined, common or JSON lines) on this computer and reports attacks: SQL injection, XSS, path traversal and file inclusion, command injection, SSRF, template injection, Log4j probes, probes for sensitive files and foreign admin panels, attack tools, brute force on logins, path scans and floods. When Live Defense has found a planted file in a public folder and the log shows it being served, Log Sentinel raises one critical alarm: a web shell is probably in use. Detection only: nothing is blocked.

Privacy (DSGVO): nothing from the logs leaves the computer. IP addresses are stored shortened (IPv4 /24, IPv6 /48) with a keyed hash unless you switch on "Keep full IP addresses"; credential values in URLs are hidden; events are deleted after 30 days by default. Use "Analyse a sample log" to see it work before pointing it at a real log.

---

## Notifications (daily report by email and Telegram)

Settings → Notifications. **Off by default.** When switched on, a short report of what happened goes out every morning at the time you choose (08:00 by default): Threat Feed items that affect your projects, websites that went down or came back, Log Sentinel attacks per severity and the top rules, open Live Defense changes, and the last scan. Optionally CRITICAL alarms are pushed at once (at most 5 per hour; the rest in one message at the end of the hour). If the PC was off at report time, the missed report goes out once at the next start. A report is never sent twice on the same day.

What is sent: counts, titles and CVE ids of feed items that affect a project, project names (or "Project A, B…" with *Hide project names*, then without the site host too), site hosts, rule names, relative paths of HIGH/CRITICAL file changes, and the last scan's date and counts. What is never sent: code or file contents, secret values or a secret finding's description, IP addresses (with *Include network* only the /24 or /48 network), request lines, user agents, keys or tokens, absolute paths.

- **Email**: SMTP server, port (465 = TLS, 587 = STARTTLS), user, password, sender and up to 5 recipients. TLS is always used and the certificate is checked; port 25 and servers without STARTTLS are refused. For Gmail, GMX or Outlook use an app password.
- **Telegram**: create a bot with @BotFather, send `/start` to it, paste the token and press *Find my chat*. Messages go to `api.telegram.org` only.

The SMTP password and the bot token are kept in the Windows Credential Manager, never in `settings.json`, and never appear in a status line, a log or the outbox. Each channel asks before it is switched on and names the host it will contact. A message that cannot be delivered waits in the outbox (`notify.db`) and is tried again after 1, 5, 15 and 60 minutes, then hourly, for up to 48 hours. *Preview* shows the message that would be sent now; *Send test* sends a short test.

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

```text
oranovix-guardian/
├── .github/                     # CI workflows
├── assets/                      # Icons, artwork and the sample access log
├── main.py                      # Source and desktop bundle entry point
└── src/
    ├── oranovix_guardian/
    │   ├── core/                # Application services and persistence
    │   ├── gui/                 # Tk views, navigation and scan activity
    │   ├── scanner_engine/      # Scan orchestration, rules and findings
    │   ├── live_defense/        # File integrity monitoring
    │   ├── log_sentinel/        # Access-log analysis and monitoring
    │   ├── threat_intel/        # Projects, uptime checks and threat feeds
    │   ├── reports/             # PDF generation
    │   ├── rules/               # Bundled default scan rules
    │   └── translations/        # English, German and Arabic
    ├── build_tools/             # Packaging and desktop workload checks
    ├── docs/                    # Development notes and examples
    └── tests/                   # Functional tests and fixtures
```

The scan workflow goes from `oranovix_guardian.gui` to `core.scan_job`
to `scanner_engine` within the application package. The job owns
background execution, progress and cancellation. The engine owns the
scan checkpoints, findings and coverage. The results page and PDF
generator use the same coverage summary.

From the repository root, run tests with `python -m pytest` after
installing `src/requirements-dev.txt`. `python -m pytest -m "not slow"`
leaves out the throughput tests, which take seconds each. Run the desktop workload check
with `python -m src.build_tools.check_desktop_workload` in a graphical
session. Source runs use the same runtime data paths as earlier
checkouts. Set `ORANOVIX_DATA_DIR` to keep generated settings, databases,
custom rules and reports in a separate folder.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

<p align="center">Made with ❤️ — 100% free, scans offline</p>
