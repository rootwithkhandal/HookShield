"""
Suspicious process detector.
Matches running processes against a keyword list loaded from YAML.
"""
import logging

import psutil

from utils.config_loader import load_suspicious_keywords
from core.threat_intel_feed import get_openphish_domains

logger = logging.getLogger(__name__)

# Fallback keyword list used when the YAML file cannot be loaded
_FALLBACK_KEYWORDS = [
    "keylogger", "pynput", "hook", "keyboard", "capture", "record",
    "keystroke", "listener", "intercept", "grabber", "inputhook", "keyhook",
    "spy", "screenshot", "cliplogger", "stealer", "remote", "rat", "inject",
    "dllinject", "persistence", "taskhide", "hidewindow", "rootkit", "backdoor",
    "malware", "trojan", "sniffer", "payload", "metasploit", "beacon", "c2",
    "bindshell", "reverse_shell", "mimikatz", "credsdump", "scrape",
    "exfiltrate", "obfuscate", "cryptor",
]


def detect_suspicious_processes() -> list[dict]:
    """
    Scan all running processes and return those matching suspicious keywords.

    Each result dict contains: pid, name, path, cmdline.
    """
    keywords = load_suspicious_keywords()
    if not keywords:
        logger.warning("suspicious_keywords.yaml empty or missing — using fallback list.")
        keywords = _FALLBACK_KEYWORDS[:]

    phish_urls = get_openphish_domains()
    if phish_urls:
        keywords.extend(phish_urls)

    detected = []

    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            path = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
            combined = f"{name} {cmdline}".lower()

            if any(kw in combined for kw in keywords):
                detected.append(
                    {
                        "pid": proc.info["pid"],
                        "name": name,
                        "path": path,
                        "cmdline": cmdline,
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if detected:
        logger.warning("Suspicious processes detected: %s", detected)
    else:
        logger.info("No suspicious processes found.")

    return detected
