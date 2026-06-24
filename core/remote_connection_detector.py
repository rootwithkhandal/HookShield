"""
Remote connection detector.
Compares active network connections against the suspicious IP list in the DB.
"""
import logging

import psutil

from utils.dblogs import fetch_suspicious_ips
from core.threat_intel_feed import get_abuseipdb_ips

logger = logging.getLogger(__name__)


def detect_remote_connections() -> list[dict]:
    """
    Return a list of active connections whose remote IP is in the suspicious-IP database.

    Each result dict contains: local_addr, remote_addr, status, pid.
    """
    suspicious_ips = set(fetch_suspicious_ips())
    suspicious_ips.update(get_abuseipdb_ips())

    if not suspicious_ips:
        logger.info("No suspicious IPs in database — skipping connection check.")
        return []

    flagged = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.ip in suspicious_ips:
                flagged.append(
                    {
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        logger.error("Error scanning network connections: %s", e)

    if flagged:
        logger.warning("Suspicious remote connections detected: %s", flagged)
    else:
        logger.info("No suspicious remote connections found.")

    return flagged
