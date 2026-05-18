# 🛡️ LogDefender

A real-time keylogger detection and response system built in Python. LogDefender monitors running processes, file hashes, keyboard hooks, network connections, clipboard access, and startup entries — then alerts, logs, and lets you act on threats directly from a modern GUI or CLI.

---

## Features

### Detection
| Module | What it does |
|--------|-------------|
| **Process Scanner** | Scans all running processes against a configurable keyword list and flags matches |
| **Keyboard Hook Detector** | Detects active low-level keyboard hooks (Win32 API on Windows, pynput fallback elsewhere) |
| **File Scanner** | Hashes files with SHA-256, checks against a local known-malicious list, and queries VirusTotal |
| **Remote Connection Detector** | Compares active network connections against a tracked suspicious-IP database |
| **Clipboard Monitor** | Detects processes reading the clipboard via Win32 clipboard owner API + keyword scan |
| **Startup Entry Scanner** | Inspects Windows registry Run/RunOnce keys and startup folders for persistence mechanisms |

### Response
- **Process Terminator** — kill a suspicious process by PID directly from the GUI
- **Quarantine Engine** — move suspicious files to a quarantine folder; restore or permanently delete them later
- **IP Blocker** — block suspicious IPs using Windows Firewall (`netsh`) or Linux `iptables`
- **Email Alerts** — automated alerts sent on every threat detection

### Monitoring & Logging
- **Real-time monitor** — background loop with configurable interval, toggle on/off from the GUI
- **SQLite database** — three tables: `logs`, `network_ip`, `threat_history`
- **Threat history** — structured per-event records with type, severity, and resolved status
- **CSV export** — export all logs and threat history to CSV from the GUI or dashboard

### Interfaces
- **GUI** — tabbed CustomTkinter app (Dashboard · Processes · File Scanner · Network · Quarantine · Startup · Settings)
- **CLI** — single-scan or continuous monitor mode with `--directory` and `--interval` flags
- **Web dashboard** — 4-page Streamlit app (Overview · Detection Logs · Network Logs · Threat History) with charts and live auto-refresh

---

## Project Structure

```
def-keylogger-shield/
│
├── main.py                  # Orchestration — all detection + alert functions
├── cli.py                   # CLI entry point
├── kd_app.py                # GUI launcher
├── monitor.py               # Standalone background monitor
│
├── core/
│   ├── process_detector.py       # Suspicious process scanning
│   ├── keyboard_hook_detector.py # Keyboard hook detection
│   ├── file_scanner.py           # File hash + VirusTotal scanning
│   ├── remote_connection_detector.py  # Network connection analysis
│   ├── clipboard_monitor.py      # Clipboard access detection
│   ├── startup_scanner.py        # Registry + startup folder scanner
│   └── quarantine.py             # Quarantine engine (move/restore/delete)
│
├── ui/
│   └── gui.py               # CustomTkinter tabbed GUI
│
├── web/
│   └── dashboard.py         # Streamlit web dashboard
│
├── utils/
│   ├── config_loader.py     # Centralised config + env var loading
│   ├── dblogs.py            # SQLite read/write + CSV export
│   ├── email_sender.py      # SMTP alert emails
│   ├── logger.py            # Logging configuration
│   ├── network_blocker.py   # Cross-platform IP blocking
│   ├── ip_scanner.py        # System/Docker/external IP collection
│   └── gethash.py           # SHA-256 file/directory hashing utility
│
├── data/
│   ├── known_hashes.yaml         # SHA-256 hashes of known malicious files
│   └── suspicious_keywords.yaml  # Process keyword list (fully configurable)
│
├── quarantine/              # Created automatically on first quarantine
├── config.yaml              # App configuration (use .env for secrets)
├── .env.example             # Template for secret environment variables
├── .gitignore
└── requirements.txt
```

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/your-username/def-keylogger-shield.git
cd def-keylogger-shield
pip install -r requirements.txt
```

### Configure secrets

Copy `.env.example` to `.env` and fill in your values. Environment variables take priority over `config.yaml`.

```bash
copy .env.example .env
```

```env
VIRUS_TOTAL_API_KEY=your_virustotal_api_key_here
EMAIL_SENDER=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password_here
EMAIL_RECEIVER=alert_recipient@example.com
```

> **Never commit `.env` or a `config.yaml` with real credentials.** Both are listed in `.gitignore`.

---

## Usage

### GUI (recommended)

```bash
python kd_app.py
```

Opens the tabbed desktop application. Use the **Dashboard** tab to run a full scan or start the real-time monitor. Each tab is focused on a specific detection or response task.

### CLI

```bash
# One-shot scan of the current directory
python cli.py

# Scan a specific directory
python cli.py --directory C:\Users\YourName\Downloads

# Continuous monitoring every 30 seconds
python cli.py --monitor --interval 30

# Verbose output
python cli.py --verbose
```

Exit code `0` = clean, `1` = threats found (useful for scripting/CI).

### Background monitor

```bash
python monitor.py --directory C:\Users --interval 60
```

### Web dashboard

```bash
streamlit run web/dashboard.py
```

Opens at `http://localhost:8501`. Four pages: Overview (metrics + charts), Detection Logs, Network Logs, Threat History.

---

## GUI Tabs

| Tab | What you can do |
|-----|----------------|
| **Dashboard** | Full scan, real-time monitor toggle, threat metric cards, CSV export, open web dashboard |
| **Processes** | Scan processes, check clipboard access, kill a selected suspicious process |
| **File Scanner** | Browse and scan a file or directory, quarantine suspicious results |
| **Network** | View all system IPs, add IPs to the watchlist, block suspicious IPs |
| **Quarantine** | View quarantined files, restore to original location, or permanently delete |
| **Startup** | Scan Windows registry and startup folders for persistence entries |
| **Settings** | Edit VirusTotal API key and email credentials, save to config.yaml |

---

## Configuration

`config.yaml` holds non-secret settings. Secrets should be set via environment variables or `.env`.

```yaml
virus_total_api_key: ""   # or set VIRUS_TOTAL_API_KEY env var

email:
  sender: ""      # or EMAIL_SENDER env var
  password: ""    # or EMAIL_PASSWORD env var (use a Gmail App Password)
  receiver: ""    # or EMAIL_RECEIVER env var
```

### Tuning detection

Edit `data/suspicious_keywords.yaml` to add or remove process keywords. Edit `data/known_hashes.yaml` to add SHA-256 hashes of known malicious files.

---

## Database Schema

LogDefender uses a local SQLite file (`logs.db`) with three tables.

**`logs`** — general detection events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| timestamp | TEXT | `YYYY-MM-DD HH:MM:SS` |
| level | TEXT | `INFO`, `WARN`, or `ERROR` |
| message | TEXT | Human-readable description |
| location | TEXT | File path, process name, or `N/A` |

**`network_ip`** — tracked suspicious IPs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| timestamp | TEXT | When the IP was logged |
| level | TEXT | Severity level |
| message | TEXT | Context message |
| source_ip | TEXT | The IP address |

**`threat_history`** — structured threat events
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Auto-increment primary key |
| timestamp | TEXT | When the threat was detected |
| threat_type | TEXT | `process`, `file`, `network`, `keyboard_hook`, `clipboard`, `startup` |
| severity | TEXT | `HIGH`, `MEDIUM`, or `LOW` |
| description | TEXT | Details of the threat |
| resolved | INTEGER | `0` = open, `1` = resolved |

---

## Tech Stack

| Library | Purpose |
|---------|---------|
| `psutil` | Process, network connection, and system info |
| `pynput` | Keyboard hook detection fallback |
| `hashlib` | SHA-256 file hashing |
| `requests` | VirusTotal API calls |
| `sqlite3` | Embedded database (stdlib) |
| `customtkinter` | Modern dark-themed GUI |
| `streamlit` | Web dashboard |
| `pandas` | Log data manipulation and display |
| `pyyaml` | Config and data file parsing |
| `python-dotenv` | `.env` secret loading |

---

## Security Notes

- Secrets (API keys, email passwords) should be stored in `.env`, not `config.yaml`
- All file hashing uses SHA-256 — MD5 is not used anywhere
- VirusTotal API calls are rate-limited to respect the free tier (4 req/min)
- IP blocking uses `netsh advfirewall` on Windows and `iptables` on Linux
- The quarantine folder stores files with a `.quar` extension and a `.manifest` sidecar — original paths are preserved for safe restoration

---

## Contributing

Fork the repo, create a feature branch, and open a pull request. Areas where contributions are especially welcome:

- Additional detection heuristics (e.g. DLL injection detection, memory scanning)
- macOS support for startup scanner and IP blocker
- Unit tests for core detection modules
- Threat intelligence feed integration

---

## License

This project is licensed under the [MIT License](LICENSE).
