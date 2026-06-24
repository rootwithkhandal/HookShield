"""
LogDefender — main orchestration module.

Provides individual detection functions and a monitor_system() loop.
"""
import logging
import time
import asyncio

from utils.logger import configure_logger
from utils.config_loader import load_config, load_known_hashes
from utils.dblogs import insert_log, insert_threat
from utils.email_sender import send_email

from core.process_detector import detect_suspicious_processes
from core.file_scanner import scan_files
from core.keyboard_hook_detector import detect_keyboard_hooks
from core.remote_connection_detector import detect_remote_connections
from core.clipboard_monitor import detect_clipboard_access
from core.startup_scanner import scan_startup_entries
from core.memory_scanner import detect_dll_injection

logger = logging.getLogger(__name__)

# Load config once at module level
_cfg = load_config()
VIRUS_TOTAL_API_KEY: str = _cfg.get("virus_total_api_key", "")
KNOWN_HASHES: list = load_known_hashes()


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def detect_keyloggers() -> list[dict]:
    """Detect suspicious processes and keyboard hooks."""
    logger.info("--- Process scan started ---")
    processes = detect_suspicious_processes()

    if processes:
        insert_log("WARN", "Suspicious processes detected.", str(processes))
        insert_threat("process", "HIGH", f"Suspicious processes: {[p['name'] for p in processes]}")
        send_alert("Process", processes, "Terminate the process.")

    logger.info("--- Keyboard hook check ---")
    if detect_keyboard_hooks():
        insert_log("WARN", "Keyboard hook detected.", "N/A")
        insert_threat("keyboard_hook", "HIGH", "Active keyboard hook detected.")
        send_alert("Keyboard Hook", processes, "Terminate the process.")

    return processes


def scanning_files(directory_path: str) -> tuple[list[str], str]:
    """Scan a directory for suspicious files."""
    logger.info("--- File scan started: %s ---", directory_path)
    suspicious_files = scan_files(directory_path, KNOWN_HASHES, VIRUS_TOTAL_API_KEY)

    if suspicious_files:
        logger.warning("Suspicious files detected: %s", suspicious_files)
        insert_log("WARN", "Suspicious files detected.", str(suspicious_files))
        insert_threat("file", "HIGH", f"Suspicious files: {suspicious_files}")
        send_alert("File", suspicious_files, "Quarantine the file.")
    else:
        logger.info("No suspicious files found in %s", directory_path)

    return suspicious_files, "Scan Completed"


def detect_network(processes: list = None, files: list = None) -> list[dict]:
    """Detect suspicious remote connections."""
    logger.info("--- Network connection scan ---")
    connections = detect_remote_connections()

    if connections:
        insert_log("WARN", "Suspicious remote connections detected.", str(connections))
        insert_threat("network", "MEDIUM", f"Suspicious connections: {connections}")
        send_alert("Remote Connection", connections, "Block IP.")

    if not (processes or files or connections or detect_keyboard_hooks()):
        logger.info("No keylogger activity detected.")

    return connections


def detect_clipboard() -> list[dict]:
    """Detect suspicious clipboard access."""
    logger.info("--- Clipboard monitor check ---")
    hits = detect_clipboard_access()

    if hits:
        insert_log("WARN", "Suspicious clipboard access detected.", str(hits))
        insert_threat("clipboard", "MEDIUM", f"Clipboard access by: {[h['name'] for h in hits]}")
        send_alert("Clipboard Access", hits, "Investigate process.")

    return hits


def scan_startup() -> list[dict]:
    """Scan startup entries for suspicious items."""
    logger.info("--- Startup entry scan ---")
    entries = scan_startup_entries()

    if entries:
        insert_log("WARN", "Suspicious startup entries detected.", str(entries))
        insert_threat("startup", "HIGH", f"Suspicious startup entries: {entries}")
        send_alert("Startup Entry", entries, "Remove entry.")

    return entries


def detect_memory_injection() -> list[dict]:
    """Scan target processes for DLL injection/shellcode."""
    logger.info("--- Memory injection scan ---")
    hits = detect_dll_injection()

    if hits:
        insert_log("WARN", "Memory injection detected.", str(hits))
        insert_threat("memory", "HIGH", f"Injected into: {[h['name'] for h in hits]}")
        send_alert("Memory Injection", hits, "Investigate process immediately.")

    return hits


def kill_process(pid: int) -> bool:
    """
    Terminate a process by PID.
    Returns True on success, False on failure.
    """
    import psutil
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        proc.wait(timeout=5)
        logger.warning("Terminated process: %s (PID %d)", name, pid)
        insert_log("WARN", f"Process terminated: {name} (PID {pid})", "process_killer")
        insert_threat("process_kill", "HIGH", f"Process {name} (PID {pid}) was terminated.")
        return True
    except psutil.NoSuchProcess:
        logger.error("Process PID %d not found.", pid)
        return False
    except psutil.AccessDenied:
        logger.error("Access denied terminating PID %d.", pid)
        return False
    except psutil.TimeoutExpired:
        try:
            psutil.Process(pid).kill()
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Alert helpers
# ---------------------------------------------------------------------------

def send_alert(alert_type: str, details, action: str = ""):
    # ponytail: one unified alert function
    body = f"🚨 Threat Alert: Suspicious {alert_type} Detected\n\nDetails:\n---------\n{details}\n"
    if action: body += f"Action: {action}\n\n"
    send_email(f"🚨 SCRAMBLE — Suspicious {alert_type} Detected", body + "This is an automated alert from LogDefender.")


# ---------------------------------------------------------------------------
# Monitor loop
# ---------------------------------------------------------------------------

async def monitor_system(directory: str = ".", interval: int = 60):
    """
    Continuously run all detection checks concurrently.
    """
    logger.info("LogDefender monitor started. Scan interval: %d s", interval)
    while True:
        try:
            # ponytail: run blocking scanners concurrently in a thread pool
            results = await asyncio.wait_for(
                asyncio.gather(
                    asyncio.to_thread(detect_keyloggers),
                    asyncio.to_thread(scanning_files, directory),
                    asyncio.to_thread(detect_clipboard),
                    asyncio.to_thread(scan_startup),
                    asyncio.to_thread(detect_memory_injection)
                ),
                timeout=45.0
            )
            processes, (files, _), _, _, _ = results

            # network depends on processes and files
            await asyncio.wait_for(
                asyncio.to_thread(detect_network, processes, files),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            logger.error("A scan cycle timed out!")
        except Exception as e:
            logger.error("Unexpected error in monitor loop: %s", e)
            
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    configure_logger()
    logger.info("Starting LogDefender...")
    try:
        asyncio.run(monitor_system())
    except KeyboardInterrupt:
        logger.info("LogDefender shut down.")
