"""
File scanner — checks files against known malicious hashes and VirusTotal.

VirusTotal free tier: 4 requests/minute.
This module enforces a configurable delay between API calls to stay within limits.
"""
import hashlib
import logging
import os
import time

import requests

from utils.config_loader import load_config
from core.threat_intel_feed import get_malware_bazaar_hashes

logger = logging.getLogger(__name__)

# Seconds to wait between VirusTotal API calls (free tier = 4 req/min → 15 s)
_VT_RATE_LIMIT_DELAY = 15

# YARA Setup
YARA_RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules", "keyloggers.yara"))
compiled_rules = None

try:
    import yara
    if os.path.exists(YARA_RULES_PATH):
        compiled_rules = yara.compile(filepath=YARA_RULES_PATH)
        logger.info("YARA rules loaded successfully.")
except ImportError:
    logger.warning("yara-python not installed. YARA behavioral scanning disabled.")
except Exception as e:
    logger.error("Failed to compile YARA rules: %s", e)

def check_yara(file_path: str) -> bool:
    """Scan file against compiled YARA rules."""
    if compiled_rules is None:
        return False
    try:
        matches = compiled_rules.match(file_path)
        if matches:
            logger.warning("YARA Rule Match on %s: %s", file_path, [m.rule for m in matches])
            return True
    except Exception:
        pass
    return False


def _sha256(file_path: str) -> str | None:
    """Return SHA-256 hex digest of a file, or None on read error."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, IOError) as e:
        logger.error("Cannot read file %s: %s", file_path, e)
        return None


def check_file_virus_total(file_hash: str, api_key: str) -> bool:
    """
    Query VirusTotal for a file hash.
    Returns True if any engine flagged the file as malicious.
    """
    if not api_key:
        logger.debug("VirusTotal API key not set — skipping VT check.")
        return False

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return False  # Hash not in VT database
        if response.status_code == 429:
            logger.warning("VirusTotal rate limit hit — waiting 60 s before retry.")
            time.sleep(60)
            response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        malicious_count = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0)
        )
        return malicious_count > 0
    except requests.RequestException as e:
        logger.error("VirusTotal request failed for hash %s: %s", file_hash, e)
        return False


def scan_files(
    directory: str,
    known_hashes: list | None = None,
    api_key: str | None = None,
    vt_delay: float = _VT_RATE_LIMIT_DELAY,
) -> list[str]:
    """
    Recursively scan a directory.
    Returns a list of suspicious file paths.
    """
    if known_hashes is None:
        known_hashes = get_malware_bazaar_hashes()
    if api_key is None:
        cfg = load_config()
        api_key = cfg.get("virus_total_api_key", "")

    suspicious: list[str] = []
    last_vt_call = 0.0

    for root, _dirs, files in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            file_hash = _sha256(path)
            if file_hash is None:
                continue

            # Local hash check (instant)
            if file_hash in known_hashes:
                logger.warning("Known malicious hash match: %s", path)
                suspicious.append(path)
                continue

            # YARA Check (instant, behavioral)
            if check_yara(path):
                suspicious.append(path)
                continue

            # VirusTotal check (rate-limited)
            if api_key:
                elapsed = time.time() - last_vt_call
                if elapsed < vt_delay:
                    time.sleep(vt_delay - elapsed)
                if check_file_virus_total(file_hash, api_key):
                    logger.warning("VirusTotal flagged: %s", path)
                    suspicious.append(path)
                last_vt_call = time.time()

    return suspicious


def scan_single_file(
    file_path: str,
    known_hashes: list | None = None,
    api_key: str | None = None,
) -> list[str]:
    """
    Scan a single file.
    Returns a list containing the file path if suspicious, else empty list.
    """
    if known_hashes is None:
        known_hashes = get_malware_bazaar_hashes()
    if api_key is None:
        cfg = load_config()
        api_key = cfg.get("virus_total_api_key", "")

    file_hash = _sha256(file_path)
    if file_hash is None:
        return []

    if file_hash in known_hashes:
        logger.warning("Known malicious hash match: %s", file_path)
        return [file_path]

    if check_yara(file_path):
        return [file_path]

    if api_key and check_file_virus_total(file_hash, api_key):
        logger.warning("VirusTotal flagged: %s", file_path)
        return [file_path]

    return []
