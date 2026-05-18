"""
Clipboard monitor.

Detects processes that are actively reading the clipboard — a common
data-exfiltration technique used by keyloggers and stealers.

On Windows this uses the OpenClipboard / GetClipboardOwner Win32 API
to identify which process currently owns the clipboard.
On other platforms it falls back to a psutil-based heuristic.
"""
import logging
import platform

import psutil

from utils.config_loader import load_suspicious_keywords

logger = logging.getLogger(__name__)

_OS = platform.system()


def _keywords() -> list[str]:
    kw = load_suspicious_keywords()
    if not kw:
        kw = ["keylogger", "hook", "rat", "spy", "stealer", "cliplogger", "grabber"]
    return [k.lower() for k in kw]


def _get_clipboard_owner_windows() -> dict | None:
    """
    Return info about the process that currently owns the clipboard on Windows.
    Returns None if the clipboard is not open or the owner cannot be determined.
    """
    try:
        import ctypes
        import ctypes.wintypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        if not user32.OpenClipboard(None):
            return None

        hwnd = user32.GetClipboardOwner()
        user32.CloseClipboard()

        if not hwnd:
            return None

        pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = pid.value

        if pid_val:
            try:
                proc = psutil.Process(pid_val)
                return {
                    "pid": pid_val,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cmdline": " ".join(proc.cmdline()),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {"pid": pid_val, "name": "unknown", "exe": "", "cmdline": ""}

    except Exception as e:
        logger.debug("Clipboard owner check failed: %s", e)

    return None


def detect_clipboard_access() -> list[dict]:
    """
    Return a list of suspicious processes that appear to be accessing the clipboard.

    On Windows: checks the current clipboard owner against the keyword list.
    On all platforms: scans running processes for clipboard-related keywords.
    """
    keywords = _keywords()
    suspicious: list[dict] = []

    # --- Windows: check actual clipboard owner ---
    if _OS == "Windows":
        owner = _get_clipboard_owner_windows()
        if owner:
            combined = f"{owner.get('name','')} {owner.get('cmdline','')}".lower()
            if any(kw in combined for kw in keywords):
                owner["detection_method"] = "clipboard_owner"
                suspicious.append(owner)
                logger.warning("Suspicious clipboard owner: %s (PID %s)", owner.get("name"), owner.get("pid"))

    # --- Cross-platform: keyword scan of all processes ---
    clipboard_libs = ["pyperclip", "clipboard", "win32clipboard", "xclip", "xsel", "wl-clipboard"]
    all_kw = keywords + clipboard_libs

    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
            combined = f"{name} {cmdline}".lower()

            if any(kw in combined for kw in all_kw):
                entry = {
                    "pid": proc.info["pid"],
                    "name": name,
                    "exe": proc.info["exe"] or "",
                    "cmdline": cmdline,
                    "detection_method": "process_keyword",
                }
                # Avoid duplicating the Windows clipboard-owner hit
                if not any(s["pid"] == entry["pid"] for s in suspicious):
                    suspicious.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if suspicious:
        logger.warning("Suspicious clipboard-related processes: %s", suspicious)
    else:
        logger.info("No suspicious clipboard activity detected.")

    return suspicious
