# 🛡️ HookShield

A real-time system detection and response tool built in Python. HookShield monitors running processes, file hashes, keyboard hooks, network connections, clipboard access, and startup entries — then alerts, logs, and lets you act on threats directly from a modern Web Dashboard or CLI.

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
- **Web dashboard** — Custom Glassmorphic Flask app with charts, live auto-refresh, and CSV exports
- **GUI** — tabbed CustomTkinter app (Dashboard · Processes · File Scanner · Network · Quarantine · Startup)
- **CLI** — single-scan or continuous monitor mode with `--directory` and `--interval` flags

---

## Project Structure

```
HookShield/
│
├── main.py                  # Orchestration — all detection + alert functions
├── cli.py                   # CLI entry point
├── kd_app.py                # Desktop GUI launcher
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
├── web/
│   ├── app.py               # Flask web backend
│   └── static/              # HTML/CSS/JS frontend (Cyber-Glass Aesthetic)
│
├── ui/
│   └── gui.py               # CustomTkinter desktop GUI
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
├── config.yaml              # App configuration (use .config for secrets)
├── .config.example          # Template for secret environment variables
├── .gitignore
├── requirements.txt
└── .mise.toml               # Task runner configuration
```

---

## Installation

**Requirements:** Python 3.10+ and [Mise](https://mise.jdx.dev/)

```bash
git clone https://github.com/your-username/HookShield.git
cd HookShield

# Install dependencies using mise task
mise run install
```

### Configure secrets

Copy `.config.example` to `.config` and fill in your values. Environment variables take priority over `config.yaml`.

```bash
copy .config.example .config
```

```env
VIRUS_TOTAL_API_KEY=your_virustotal_api_key_here
EMAIL_SENDER=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password_here
EMAIL_RECEIVER=alert_recipient@example.com
OUTPUT_MODE=both
SYSLOG_HOST=127.0.0.1
SYSLOG_PORT=514
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
MALWARE_BAZAAR_API_KEY=your_malware_bazaar_api_key_here
```

> **Never commit `.config` or a `config.yaml` with real credentials.** Both are listed in `.gitignore`.

---

## Usage

### Web Dashboard (Recommended)

```bash
mise run ui
```

Opens at `http://localhost:5000`. Features a modern, cyber-glass aesthetic UI with live metrics, charts, and detection logs.
You can view your threat history, network logs, and configure settings directly from the browser. 
It also includes **CSV Export** buttons for the Detection Logs, Network Connections, and Threat History tables.

### CLI

```bash
# One-shot scan of the current directory
mise run run

# Scan a specific directory (via direct python invocation)
python cli.py --directory C:\Users\YourName\Downloads

# Continuous monitoring every 30 seconds
python cli.py --monitor --interval 30
```

### Desktop GUI (Legacy)

```bash
python kd_app.py
```

Opens the older tabbed desktop application via CustomTkinter.

---

## Web Dashboard Tabs

| Tab | What you can do |
|-----|----------------|
| **Overview** | View high-level metrics, threat charts, and recent security logs |
| **Detection Logs** | View all historical system scans and flags with full CSV export |
| **Network Logs** | View historical network connections and suspicious IP flags with CSV export |
| **Threat History** | View specifically marked threats and their resolution status with CSV export |
| **Settings** | Update API keys and export configuration securely to `.config` without leaving the browser |

---

## Configuration

`config.yaml` holds non-secret settings. Secrets should be set via environment variables or `.config`.

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

HookShield uses a local SQLite file (`logs.db`) with three tables.

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
| `flask` | Web dashboard backend API |
| `python-dotenv` | `.config` secret loading |
| `pynput` | Keyboard hook detection fallback |
| `hashlib` | SHA-256 file hashing |
| `requests` | VirusTotal API calls |
| `sqlite3` | Embedded database (stdlib) |
| `pyyaml` | Config and data file parsing |

---

## Security Notes

- Secrets (API keys, email passwords) should be stored in `.config`, not `config.yaml`
- All file hashing uses SHA-256 — MD5 is not used anywhere
- VirusTotal API calls are rate-limited to respect the free tier (4 req/min)
- IP blocking uses `netsh advfirewall` on Windows and `iptables` on Linux
- The quarantine folder stores files with a `.quar` extension and a `.manifest` sidecar — original paths are preserved for safe restoration

---

## License

This project is licensed under the [MIT License](LICENSE).
