"""
Red Team Evasion Simulator
Spawns a controlled dummy process that performs keylogger-like activities
to verify HookShield's behavioral scoring and auto-kill capabilities.
"""
import sys
import subprocess
import time
import logging

logger = logging.getLogger(__name__)

def red_team_payload():
    """This function is executed by the spawned dummy process."""
    import winreg
    import ctypes
    
    print("[Red Team] Suspicious process started (named keylogger_test).")
    
    # 1. Fake Clipboard Read (20 points)
    print("[Red Team] Triggering clipboard access...")
    try:
        user32 = ctypes.windll.user32
        if user32.OpenClipboard(None):
            # Taking ownership of the clipboard briefly
            user32.EmptyClipboard()
            user32.CloseClipboard()
    except Exception as e:
        print("[Red Team] Clipboard access failed:", e)

    # 2. Fake Registry Write x2 (20 + 20 = 40 points via ETW)
    print("[Red Team] Triggering registry RUN key modification...")
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        winreg.SetValueEx(key, "HookShield_Test1", 0, winreg.REG_SZ, "dummy.exe")
        time.sleep(0.5)
        winreg.SetValueEx(key, "HookShield_Test2", 0, winreg.REG_SZ, "dummy2.exe")
        winreg.CloseKey(key)
    except Exception as e:
        print("[Red Team] Registry write failed:", e)

    # 3. Suspicious command line keyword "keylogger_test" (30 points)
    # Total points expected: 20 + 40 + 30 = 90 points (Auto-Kill is 80)
    
    print("[Red Team] Sleeping to allow monitor to detect us. If auto-kill works, we will be terminated...")
    for _ in range(60):
        time.sleep(1)
        
    print("[Red Team] Cleanup - test failed to terminate us.")
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteValue(key, "HookShield_Test1")
        winreg.DeleteValue(key, "HookShield_Test2")
        winreg.CloseKey(key)
    except Exception:
        pass


def run_red_team_simulation():
    """Spawns the payload as a separate process."""
    time.sleep(2) # Give the monitor time to start up
    logger.info("=========================================")
    logger.info("🚨 RED TEAM EVASION SIMULATION STARTED 🚨")
    logger.info("=========================================")
    
    # Spawn a child process with a suspicious command line keyword
    # We append # keylogger_test so it appears in the cmdline args
    cmd = [sys.executable, "-c", "from core.red_team import red_team_payload; red_team_payload() # keylogger_test"]
    
    try:
        proc = subprocess.Popen(cmd)
        logger.info("Red team payload spawned (PID: %d). Watch the detection engine catch it!", proc.pid)
    except Exception as e:
        logger.error("Failed to spawn red team payload: %s", e)

if __name__ == "__main__":
    # If run directly, act as the payload
    red_team_payload()
