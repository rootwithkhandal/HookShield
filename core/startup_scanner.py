"""
Startup entry scanner.

Checks Windows registry run keys and common startup folders for entries
whose names or target paths match the suspicious-keyword list.
Falls back gracefully on non-Windows platforms.
"""
import logging
import os
import platform

from utils.config_loader import load_suspicious_keywords

logger = logging.getLogger(__name__)

_OS = platform.system()

# Registry run keys to inspect
_REGISTRY_RUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]

# Common startup folder paths (expanded at runtime)
_STARTUP_FOLDERS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]


def _keywords() -> list[str]:
    kw = load_suspicious_keywords()
    if not kw:
        kw = ["keylogger", "hook", "rat", "spy", "stealer", "backdoor", "trojan"]
    return [k.lower() for k in kw]


def _scan_registry() -> list[dict]:
    """Scan Windows registry run keys for suspicious entries."""
    results = []
    try:
        import winreg  # type: ignore  # Windows only
    except ImportError:
        return results

    keywords = _keywords()
    hives = [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]

    for hive in hives:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        for key_path in _REGISTRY_RUN_KEYS:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        combined = f"{name} {value}".lower()
                        if any(kw in combined for kw in keywords):
                            results.append(
                                {
                                    "source": "registry",
                                    "hive": hive_name,
                                    "key": key_path,
                                    "name": name,
                                    "value": value,
                                }
                            )
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue

    return results


def _scan_startup_folders() -> list[dict]:
    """Scan startup folders for suspicious shortcut/executable entries."""
    results = []
    keywords = _keywords()

    for folder in _STARTUP_FOLDERS:
        if not os.path.isdir(folder):
            continue
        for fname in os.listdir(folder):
            if any(kw in fname.lower() for kw in keywords):
                results.append(
                    {
                        "source": "startup_folder",
                        "folder": folder,
                        "filename": fname,
                        "full_path": os.path.join(folder, fname),
                    }
                )

    return results


def scan_startup_entries() -> list[dict]:
    """
    Scan all startup locations for suspicious entries.

    Returns a list of dicts describing each suspicious entry found.
    Works on Windows only; returns an empty list on other platforms.
    """
    if _OS != "Windows":
        logger.info("Startup scan is Windows-only — skipping on %s.", _OS)
        return []

    registry_hits = _scan_registry()
    folder_hits = _scan_startup_folders()
    all_hits = registry_hits + folder_hits

    if all_hits:
        logger.warning("Suspicious startup entries found: %d", len(all_hits))
    else:
        logger.info("No suspicious startup entries found.")

    return all_hits
