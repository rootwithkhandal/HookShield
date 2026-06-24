"""
Threat Intel Feed
Fetches and caches live Indicators of Compromise (IOCs) from external CTI APIs.
"""
import time
import requests
import logging
from typing import Set
from utils.config_loader import load_config

logger = logging.getLogger(__name__)

# TTL Cache mapping
_CACHE = {
    "malware_bazaar": {"expires": 0, "data": set()},
    "abuseipdb": {"expires": 0, "data": set()},
    "openphish": {"expires": 0, "data": set()},
}
_TTL_SECONDS = 3600  # 1 hour

def _get_api_keys():
    cfg = load_config()
    return cfg.get("abuseipdb_api_key", ""), cfg.get("malware_bazaar_api_key", "")

def get_malware_bazaar_hashes() -> Set[str]:
    """Fetch recent malware hashes from MalwareBazaar."""
    cache = _CACHE["malware_bazaar"]
    if time.time() < cache["expires"]:
        return cache["data"]

    _, mb_key = _get_api_keys()
    hashes = set()
    
    # MalwareBazaar API (Recent additions)
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_recent", "selector": "time"}
    headers = {"API-KEY": mb_key} if mb_key else {}
    
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=10)
        if resp.status_code == 200:
            json_data = resp.json()
            if json_data.get("query_status") == "ok":
                for item in json_data.get("data", []):
                    hashes.add(item.get("sha256_hash", "").lower())
        logger.info("Fetched %d hashes from MalwareBazaar.", len(hashes))
        cache["data"] = hashes
        cache["expires"] = time.time() + _TTL_SECONDS
    except Exception as e:
        logger.error("Failed to fetch MalwareBazaar feed: %s", e)
    
    return cache["data"]


def get_abuseipdb_ips() -> Set[str]:
    """Fetch malicious IP blacklist from AbuseIPDB."""
    cache = _CACHE["abuseipdb"]
    if time.time() < cache["expires"]:
        return cache["data"]

    abuse_key, _ = _get_api_keys()
    if not abuse_key:
        logger.warning("AbuseIPDB API key missing. Cannot fetch live IP blacklist.")
        return set()

    ips = set()
    # AbuseIPDB blacklist endpoint
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Accept": "application/json",
        "Key": abuse_key
    }
    params = {"confidenceMinimum": "90"}
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            json_data = resp.json()
            for item in json_data.get("data", []):
                ips.add(item.get("ipAddress"))
        logger.info("Fetched %d malicious IPs from AbuseIPDB.", len(ips))
        cache["data"] = ips
        cache["expires"] = time.time() + _TTL_SECONDS
    except Exception as e:
        logger.error("Failed to fetch AbuseIPDB blacklist: %s", e)
        
    return cache["data"]


def get_openphish_domains() -> Set[str]:
    """Fetch phishing domains/URLs from OpenPhish feed."""
    cache = _CACHE["openphish"]
    if time.time() < cache["expires"]:
        return cache["data"]

    domains = set()
    url = "https://openphish.com/feed.txt"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.strip():
                    domains.add(line.strip().lower())
        logger.info("Fetched %d phishing items from OpenPhish.", len(domains))
        cache["data"] = domains
        cache["expires"] = time.time() + _TTL_SECONDS
    except Exception as e:
        logger.error("Failed to fetch OpenPhish feed: %s", e)
        
    return cache["data"]
