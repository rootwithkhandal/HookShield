"""
Database logging utilities.
All tables use consistent column names throughout the codebase.
"""
import csv
import io
import sqlite3
import os
from datetime import datetime
from utils.config_loader import load_config
import logging
from logging.handlers import SysLogHandler
import json

_cfg = load_config()
OUTPUT_MODE = _cfg.get("output_mode", "sqlite").lower()
SYSLOG_HOST = _cfg.get("syslog_host", "127.0.0.1")
SYSLOG_PORT = int(_cfg.get("syslog_port", 514))

_syslog_logger = None
if OUTPUT_MODE in ["syslog", "both"]:
    _syslog_logger = logging.getLogger('HS_Syslog')
    _syslog_logger.setLevel(logging.INFO)
    try:
        handler = SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT))
        handler.setFormatter(logging.Formatter('%(message)s'))
        _syslog_logger.addHandler(handler)
    except Exception as e:
        print(f"Failed to init syslog: {e}")
        _syslog_logger = None

def _send_syslog(level, tag, data):
    if not _syslog_logger: return
    msg = f"[{tag}] {json.dumps(data)}"
    lvl = level.upper()
    if lvl in ["ERROR", "HIGH"]: _syslog_logger.error(msg)
    elif lvl in ["WARN", "MEDIUM"]: _syslog_logger.warning(msg)
    else: _syslog_logger.info(msg)

# Resolve DB path relative to project root so it works from any cwd
_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logs.db")


def _get_db_path() -> str:
    return os.path.abspath(_DB_PATH)


def create_db():
    """Create database tables if they don't already exist."""
    conn = sqlite3.connect(_get_db_path())
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            level     TEXT    NOT NULL,
            message   TEXT    NOT NULL,
            location  TEXT    NOT NULL
        )
    """)

    # Column is 'source_ip' — consistent across all modules
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_ip (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level     TEXT NOT NULL,
            message   TEXT NOT NULL,
            source_ip TEXT NOT NULL
        )
    """)

    # Threat history — one row per detected threat event
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            threat_type  TEXT NOT NULL,
            severity     TEXT NOT NULL,
            description  TEXT NOT NULL,
            resolved     INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def insert_log(level: str, log_message: str, location: str):
    """Insert a general log entry and optionally export to syslog."""
    if OUTPUT_MODE in ["sqlite", "both"]:
        conn = sqlite3.connect(_get_db_path())
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO logs (timestamp, level, message, location) VALUES (?, ?, ?, ?)",
            (timestamp, level, log_message, str(location)),
        )
        conn.commit()
        conn.close()

    _send_syslog(level, "HS_LOG", {"message": log_message, "location": str(location)})


def db_network_ip(level: str, message: str, source_ip: str):
    """Insert a network IP log entry and optionally export to syslog."""
    if OUTPUT_MODE in ["sqlite", "both"]:
        conn = sqlite3.connect(_get_db_path())
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO network_ip (timestamp, level, message, source_ip) VALUES (?, ?, ?, ?)",
            (timestamp, level, message, source_ip),
        )
        conn.commit()
        conn.close()

    _send_syslog(level, "HS_NET", {"message": message, "source_ip": source_ip})


def insert_threat(threat_type: str, severity: str, description: str):
    """Record a detected threat and optionally export to syslog."""
    if OUTPUT_MODE in ["sqlite", "both"]:
        conn = sqlite3.connect(_get_db_path())
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO threat_history (timestamp, threat_type, severity, description) VALUES (?, ?, ?, ?)",
            (timestamp, threat_type, severity, description),
        )
        conn.commit()
        conn.close()

    _send_syslog(severity, "HS_THREAT", {"threat_type": threat_type, "severity": severity, "description": description})


def mark_threat_resolved(threat_id: int):
    """Mark a threat_history row as resolved."""
    conn = sqlite3.connect(_get_db_path())
    conn.execute("UPDATE threat_history SET resolved = 1 WHERE id = ?", (threat_id,))
    conn.commit()
    conn.close()


def fetch_all_logs() -> list:
    return sqlite3.connect(_get_db_path()).execute("SELECT * FROM logs ORDER BY id DESC").fetchall()

def fetch_all_network_logs() -> list:
    return sqlite3.connect(_get_db_path()).execute("SELECT * FROM network_ip ORDER BY id DESC").fetchall()

def fetch_suspicious_ips() -> list:
    return [r[0] for r in sqlite3.connect(_get_db_path()).execute("SELECT DISTINCT source_ip FROM network_ip").fetchall()]

def fetch_threat_history(resolved: bool | None = None) -> list:
    q = "SELECT * FROM threat_history" + ("" if resolved is None else f" WHERE resolved = {1 if resolved else 0}") + " ORDER BY id DESC"
    return sqlite3.connect(_get_db_path()).execute(q).fetchall()


# Initialise tables on import
create_db()
