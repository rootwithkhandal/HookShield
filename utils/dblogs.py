"""
Database logging utilities.
All tables use consistent column names throughout the codebase.
"""
import csv
import io
import sqlite3
import os
from datetime import datetime

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
    """Insert a general log entry."""
    conn = sqlite3.connect(_get_db_path())
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO logs (timestamp, level, message, location) VALUES (?, ?, ?, ?)",
        (timestamp, level, log_message, str(location)),
    )
    conn.commit()
    conn.close()


def db_network_ip(level: str, message: str, source_ip: str):
    """Insert a network IP log entry."""
    conn = sqlite3.connect(_get_db_path())
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO network_ip (timestamp, level, message, source_ip) VALUES (?, ?, ?, ?)",
        (timestamp, level, message, source_ip),
    )
    conn.commit()
    conn.close()


def insert_threat(threat_type: str, severity: str, description: str):
    """Record a detected threat in the threat_history table."""
    conn = sqlite3.connect(_get_db_path())
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO threat_history (timestamp, threat_type, severity, description) VALUES (?, ?, ?, ?)",
        (timestamp, threat_type, severity, description),
    )
    conn.commit()
    conn.close()


def mark_threat_resolved(threat_id: int):
    """Mark a threat_history row as resolved."""
    conn = sqlite3.connect(_get_db_path())
    conn.execute("UPDATE threat_history SET resolved = 1 WHERE id = ?", (threat_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def fetch_all_logs() -> list:
    """Return all general log rows as a list of dicts."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_all_network_logs() -> list:
    """Return all network IP log rows as a list of dicts."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM network_ip ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_suspicious_ips() -> list:
    """Return all tracked suspicious IP addresses."""
    conn = sqlite3.connect(_get_db_path())
    rows = conn.execute("SELECT DISTINCT source_ip FROM network_ip").fetchall()
    conn.close()
    return [row[0] for row in rows]


def fetch_threat_history(resolved: bool | None = None) -> list:
    """
    Return threat history rows.
    Pass resolved=True/False to filter, or None for all rows.
    """
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    if resolved is None:
        rows = conn.execute(
            "SELECT * FROM threat_history ORDER BY id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM threat_history WHERE resolved = ? ORDER BY id DESC",
            (1 if resolved else 0,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_threat_stats() -> dict:
    """
    Return aggregate threat statistics.

    Keys: total, by_type {type: count}, by_severity {severity: count},
          unresolved, last_threat_at
    """
    conn = sqlite3.connect(_get_db_path())
    rows = conn.execute("SELECT * FROM threat_history").fetchall()
    conn.close()

    if not rows:
        return {
            "total": 0,
            "by_type": {},
            "by_severity": {},
            "unresolved": 0,
            "last_threat_at": None,
        }

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    unresolved = 0
    last_ts = None

    for row in rows:
        t = row[2]   # threat_type
        s = row[3]   # severity
        resolved = row[5]
        ts = row[1]  # timestamp

        by_type[t] = by_type.get(t, 0) + 1
        by_severity[s] = by_severity.get(s, 0) + 1
        if not resolved:
            unresolved += 1
        if last_ts is None or ts > last_ts:
            last_ts = ts

    return {
        "total": len(rows),
        "by_type": by_type,
        "by_severity": by_severity,
        "unresolved": unresolved,
        "last_threat_at": last_ts,
    }


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def export_logs_csv(include_network: bool = True) -> str:
    """
    Export all logs (and optionally network logs) to a CSV string.
    Returns the CSV content as a string.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # General logs
    writer.writerow(["=== Detection Logs ==="])
    writer.writerow(["id", "timestamp", "level", "message", "location"])
    for row in fetch_all_logs():
        writer.writerow([row["id"], row["timestamp"], row["level"], row["message"], row["location"]])

    if include_network:
        writer.writerow([])
        writer.writerow(["=== Network / IP Logs ==="])
        writer.writerow(["id", "timestamp", "level", "message", "source_ip"])
        for row in fetch_all_network_logs():
            writer.writerow([row["id"], row["timestamp"], row["level"], row["message"], row["source_ip"]])

    return output.getvalue()


def export_threats_csv() -> str:
    """Export threat history to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "threat_type", "severity", "description", "resolved"])
    for row in fetch_threat_history():
        writer.writerow([
            row["id"], row["timestamp"], row["threat_type"],
            row["severity"], row["description"], bool(row["resolved"]),
        ])
    return output.getvalue()


# Initialise tables on import
create_db()
