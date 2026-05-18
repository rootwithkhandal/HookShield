"""
Centralized configuration loader.
Reads config.yaml and falls back to environment variables for secrets.
"""
import os
import yaml
from dotenv import load_dotenv

load_dotenv()  # Load .env if present


def load_config(filepath: str = None) -> dict:
    """Load config.yaml, merging in environment variable overrides for secrets."""
    if filepath is None:
        # Resolve relative to project root regardless of cwd
        filepath = os.path.join(os.path.dirname(__file__), "..", "config.yaml")

    filepath = os.path.abspath(filepath)

    config = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print(f"[config_loader] Error loading YAML: {e}")

    # Environment variable overrides (preferred over plaintext config)
    vt_key = os.getenv("VIRUS_TOTAL_API_KEY")
    if vt_key:
        config["virus_total_api_key"] = vt_key

    email_sender = os.getenv("EMAIL_SENDER")
    email_password = os.getenv("EMAIL_PASSWORD")
    email_receiver = os.getenv("EMAIL_RECEIVER")
    if email_sender or email_password or email_receiver:
        config.setdefault("email", {})
        if email_sender:
            config["email"]["sender"] = email_sender
        if email_password:
            config["email"]["password"] = email_password
        if email_receiver:
            config["email"]["receiver"] = email_receiver

    return config


def load_known_hashes(filepath: str = None) -> list:
    """Load known malicious file hashes from YAML."""
    if filepath is None:
        filepath = os.path.join(os.path.dirname(__file__), "..", "data", "known_hashes.yaml")

    filepath = os.path.abspath(filepath)

    if not os.path.exists(filepath):
        print(f"[config_loader] known_hashes file not found: {filepath}")
        return []

    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            return data.get("known_hashes", []) if data else []
    except yaml.YAMLError as e:
        print(f"[config_loader] Error loading known_hashes YAML: {e}")
        return []


def load_suspicious_keywords(filepath: str = None) -> list:
    """Load suspicious process keywords from YAML."""
    if filepath is None:
        filepath = os.path.join(os.path.dirname(__file__), "..", "data", "suspicious_keywords.yaml")

    filepath = os.path.abspath(filepath)

    if not os.path.exists(filepath):
        return []

    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            return data.get("keywords", []) if data else []
    except yaml.YAMLError as e:
        print(f"[config_loader] Error loading suspicious_keywords YAML: {e}")
        return []
