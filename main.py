"""
LogDefender — main orchestration module.

Provides individual detection functions and a monitor_system() loop.
"""
import logging
import time
import asyncio
import argparse
import threading

from utils.logger import configure_logger
from utils.config_loader import load_config, load_known_hashes
from utils.dblogs import insert_log, insert_threat
from utils.email_sender import send_email

from core.process_detector import detect_suspicious_processes
from core.file_scanner import scan_files
from core.keyboard_hook_detector import detect_keyboard_hooks
from core.remote_connection_detector import detect_remote_connections
from core.clipboard_monitor import detect_clipboard_access
from core.memory_scanner import detect_dll_injection
from core.etw_consumer import start_etw_listeners, get_next_etw_event
from core.scoring_engine import BehavioralScorer

logger = logging.getLogger(__name__)

# Load config once at module level
_cfg = load_config()
VIRUS_TOTAL_API_KEY: str = _cfg.get("virus_total_api_key", "")
KNOWN_HASHES: list = load_known_hashes()

scorer = BehavioralScorer(threshold=80, window_seconds=300)

def _trigger_aggregate_alert(pid: int, name: str):
    summary = scorer.get_summary(pid)
    if not summary: return
    details = f"Process {name} (PID: {pid}) breached behavioral threshold!\nScore: {summary.get('score', 0)}/100\nEvents: {summary.get('events', [])}"
    insert_threat("behavioral", "CRITICAL", details)
    send_alert("Behavioral Threshold Breached", details, "Auto-terminating process.")
    if pid > 0:
        kill_process(pid)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def detect_keyloggers() -> list[dict]:
    """Detect suspicious processes and keyboard hooks."""
    logger.info("--- Process scan started ---")
    processes = detect_suspicious_processes()

    if processes:
        insert_log("WARN", "Suspicious processes detected.", str(processes))
        for p in processes:
            if scorer.add_event(p['pid'], p['name'], "Suspicious Process", 30):
                _trigger_aggregate_alert(p['pid'], p['name'])

    logger.info("--- Keyboard hook check ---")
    if detect_keyboard_hooks():
        insert_log("WARN", "Keyboard hook detected.", "N/A")
        if scorer.add_event(0, "System", "Global Keyboard Hook", 50):
            _trigger_aggregate_alert(0, "System")

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
        for c in connections:
            pid = c.get('pid', 0)
            name = c.get('name', 'Unknown')
            if scorer.add_event(pid, name, "Network Connection", 40):
                _trigger_aggregate_alert(pid, name)

    if not (processes or files or connections or detect_keyboard_hooks()):
        logger.info("No keylogger activity detected.")

    return connections


def detect_clipboard() -> list[dict]:
    """Detect suspicious clipboard access."""
    logger.info("--- Clipboard monitor check ---")
    hits = detect_clipboard_access()

    if hits:
        insert_log("WARN", "Suspicious clipboard access detected.", str(hits))
        for h in hits:
            pid = h.get('pid', 0)
            name = h.get('name', 'Unknown')
            if scorer.add_event(pid, name, "Clipboard Access", 20):
                _trigger_aggregate_alert(pid, name)

    return hits


def route_etw_events_sync(event):
    """Fallback handler for ETW events if we parse them manually."""
    pass


def detect_memory_injection() -> list[dict]:
    """Scan target processes for DLL injection/shellcode."""
    logger.info("--- Memory injection scan ---")
    hits = detect_dll_injection()

    if hits:
        insert_log("WARN", "Memory injection detected.", str(hits))
        for h in hits:
            pid = h.get('pid', 0)
            name = h.get('name', 'Unknown')
            if scorer.add_event(pid, name, "Memory Injection", 80):
                _trigger_aggregate_alert(pid, name)

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

async def route_etw_events():
    """Consume events from the ETW queue and route them."""
    import re
    async for event in get_next_etw_event():
        try:
            event_str = str(event).lower()
            
            # Simple keyword-based event routing since `etw` dict structures vary
            if 'registry' in event_str and ('\\run' in event_str or 'runonce' in event_str):
                insert_log("WARN", "ETW: Suspicious Registry Run Key modified", event_str[:200])
                
                m = re.search(r"pid['\"]?\s*:\s*(\d+)", event_str)
                pid = int(m.group(1)) if m else 0
                
                if scorer.add_event(pid, f"ETW_PID_{pid}", "Registry Write (ETW)", 20):
                    _trigger_aggregate_alert(pid, f"ETW_PID_{pid}")
                
            elif 'process' in event_str and 'create' in event_str:
                insert_log("INFO", "ETW: Process Created", event_str[:150])
                
        except Exception as e:
            logger.error("ETW routing error: %s", e)

async def monitor_system(directory: str = ".", interval: int = 60):
    """
    Continuously run all detection checks concurrently.
    """
    logger.info("LogDefender monitor started. Scan interval: %d s", interval)
    
    etw_active = start_etw_listeners()
    if etw_active:
        logger.info("ETW Active: Swapping polling modules for event-driven router.")
        asyncio.create_task(route_etw_events())

    while True:
        try:
            tasks = [
                asyncio.to_thread(detect_clipboard),
                asyncio.to_thread(detect_memory_injection),
                asyncio.to_thread(scanning_files, directory)
            ]
            
            if not etw_active:
                tasks.append(asyncio.to_thread(detect_keyloggers))

            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=45.0)

            # Network scan logic (we pass empty lists if ETW is replacing polling)
            processes = results[3] if not etw_active else []
            files, _ = results[2]
            
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
    parser = argparse.ArgumentParser(description="HookShield Orchestrator")
    parser.add_argument("--red-team", action="store_true", help="Run Red Team Evasion Testing Mode")
    args = parser.parse_args()

    configure_logger()
    logger.info("Starting LogDefender...")
    
    if args.red_team:
        from core.red_team import run_red_team_simulation
        threading.Thread(target=run_red_team_simulation, daemon=True).start()

    try:
        asyncio.run(monitor_system())
    except KeyboardInterrupt:
        logger.info("LogDefender shut down.")
