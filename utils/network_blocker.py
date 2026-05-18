"""
Network IP blocker.
Supports Windows (netsh advfirewall) and Linux (iptables/ufw).
"""
import sys
import logging
import subprocess
import platform

from utils.dblogs import fetch_suspicious_ips
from utils.email_sender import send_email

logger = logging.getLogger(__name__)

_OS = platform.system()  # "Windows", "Linux", "Darwin"


def _block_ip_windows(ip: str):
    """Block an IP on Windows using netsh advfirewall."""
    try:
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=LogDefender_Block_{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}",
            ],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=LogDefender_Block_{ip}_out",
                "dir=out", "action=block",
                f"remoteip={ip}",
            ],
            check=True, capture_output=True,
        )
        logger.info("Blocked IP (Windows firewall): %s", ip)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to block IP %s on Windows: %s", ip, e)
        return False


def _block_ip_linux(ip: str):
    """Block an IP on Linux using iptables."""
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            check=True, capture_output=True,
        )
        logger.info("Blocked IP (iptables): %s", ip)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to block IP %s on Linux: %s", ip, e)
        return False


def block_ip(ip: str) -> bool:
    """Block a single IP address using the platform-appropriate method."""
    if _OS == "Windows":
        return _block_ip_windows(ip)
    elif _OS == "Linux":
        return _block_ip_linux(ip)
    else:
        logger.warning("IP blocking not supported on %s", _OS)
        return False


def block_suspicious_ips(db_path: str = None) -> list:
    """
    Fetch all tracked suspicious IPs from the database and block them.
    Returns a list of IPs that were successfully blocked.
    """
    ips = fetch_suspicious_ips()

    if not ips:
        logger.info("No suspicious IPs found in database.")
        print("No suspicious IPs found.")
        return []

    blocked = []
    for ip in ips:
        if block_ip(ip):
            blocked.append(ip)
            print(f"Blocked: {ip}")

            subject = "🚨 SCRAMBLE — Suspicious IP Blocked"
            body = (
                f"🚨 Threat Alert: Suspicious Remote IP Blocked\n\n"
                f"Details:\n"
                f"---------\n"
                f"IP Address : {ip}\n"
                f"Action     : Incoming and outgoing traffic blocked.\n\n"
                f"This is an automated alert from LogDefender."
            )
            send_email(subject=subject, body=body)
        else:
            print(f"Failed to block: {ip}")

    return blocked
